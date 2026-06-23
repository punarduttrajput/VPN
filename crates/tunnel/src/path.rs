//! Per-peer NAT-traversal path state machine (PRD Phase 4).
//!
//! For each mesh peer we want to prefer a **direct** path (lowest latency, no
//! third party) but fall back to a **relay** when no direct path can be punched
//! through the NATs. A peer therefore moves through a small lifecycle:
//!
//! ```text
//!   Idle ──begin──▶ Connecting ──direct──▶ Direct
//!                    │     ▲  │               │
//!              relay │     │  └────direct─────┘ (upgrade)
//!                    ▼     │                    │
//!                  Relay ──┘◀──────stale────────┘ (downgrade)
//! ```
//!
//! * **Idle** — known peer, nothing attempted yet.
//! * **Connecting** — probing: handshakes are being fanned across the peer's
//!   candidates ([`mesh::probe_targets`](crate::mesh)), no path confirmed yet.
//! * **Relay** — the relay fallback is confirmed and carrying traffic; we keep
//!   probing in the background, hoping to *upgrade* to direct.
//! * **Direct** — a direct path is confirmed and carrying traffic.
//!
//! Confirmation is driven by *authenticated inbound packets*: a datagram that
//! decrypts for a peer proves the path it arrived on works (the same property
//! mesh crypto-demux + endpoint roaming already rely on). If a confirmed path
//! then goes silent past a timeout we **downgrade** — to the relay if one is
//! live, otherwise back to probing — which is what makes a dead direct path
//! (peer roamed, NAT mapping expired) recover instead of black-holing.
//!
//! This module is pure logic with an injectable clock ([`Instant`] passed in),
//! so the transitions are unit-tested without sleeping. The data-plane wiring
//! lives in [`mesh`](crate::mesh).

use std::time::{Duration, Instant};

/// The underlay a peer's traffic should currently ride — the machine's
/// externally-visible decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// No path confirmed yet; nothing can be sent reliably.
    None,
    /// The relay fallback.
    Relay,
    /// A confirmed direct path.
    Direct,
}

/// A peer's connectivity state in the `idle → connecting → relay → direct`
/// lifecycle (see the [module docs](self)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// Nothing attempted yet.
    Idle,
    /// Probing for a path; none confirmed.
    Connecting,
    /// Relay confirmed and in use; still probing for a direct upgrade.
    Relay,
    /// Direct path confirmed and in use.
    Direct,
}

/// An observable change in a peer's path, returned by the machine's inputs so
/// the caller can log/report it (and react, e.g. resume probing on a downgrade).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// Began probing for a path (left [`PathState::Idle`]).
    Probing,
    /// A direct path was confirmed — upgraded to [`Path::Direct`].
    UpgradedToDirect,
    /// The relay fallback came up while no direct path was available.
    UsingRelay,
    /// A confirmed direct path went stale; fell back to the live relay.
    DowngradedToRelay,
    /// A confirmed direct path went stale with no relay; resumed probing.
    DowngradedToConnecting,
    /// The relay path went stale; resumed probing.
    RelayLost,
}

impl Transition {
    /// Whether this transition means the caller should (re)start direct probing
    /// — i.e. fan handshakes back out across the peer's candidates.
    pub fn should_resume_probing(self) -> bool {
        matches!(
            self,
            Transition::Probing
                | Transition::DowngradedToRelay
                | Transition::DowngradedToConnecting
                | Transition::RelayLost
        )
    }
}

/// How long without an authenticated inbound packet before a confirmed path is
/// treated as stale. Chosen well above WireGuard's keepalive (~25 s would keep a
/// healthy tunnel fresh) but below its rekey window, so a genuinely dead path is
/// noticed promptly without flapping a live one.
pub const DEFAULT_DIRECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Staleness window for the relay path (longer: the relay is the safety net, so
/// we tolerate more silence before declaring it lost).
pub const DEFAULT_RELAY_TIMEOUT: Duration = Duration::from_secs(40);

/// The per-peer path state machine. Cheap to construct (one per peer); rebuilt
/// whenever the peer set is replaced.
#[derive(Debug, Clone)]
pub struct PathMachine {
    state: PathState,
    /// Last authenticated inbound packet over the direct path.
    last_direct: Option<Instant>,
    /// Last authenticated inbound packet over the relay path.
    last_relay: Option<Instant>,
    direct_timeout: Duration,
    relay_timeout: Duration,
}

impl Default for PathMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl PathMachine {
    /// A fresh machine in [`PathState::Idle`] with the default staleness windows.
    pub fn new() -> Self {
        Self {
            state: PathState::Idle,
            last_direct: None,
            last_relay: None,
            direct_timeout: DEFAULT_DIRECT_TIMEOUT,
            relay_timeout: DEFAULT_RELAY_TIMEOUT,
        }
    }

    /// A machine with custom staleness windows (used by tests and tuning).
    pub fn with_timeouts(direct_timeout: Duration, relay_timeout: Duration) -> Self {
        Self {
            direct_timeout,
            relay_timeout,
            ..Self::new()
        }
    }

    /// The current lifecycle state.
    pub fn state(&self) -> PathState {
        self.state
    }

    /// The underlay traffic should currently ride.
    pub fn path(&self) -> Path {
        match self.state {
            PathState::Direct => Path::Direct,
            PathState::Relay => Path::Relay,
            PathState::Idle | PathState::Connecting => Path::None,
        }
    }

    /// Whether the caller should keep fanning handshakes across the peer's
    /// candidates: true unless a direct path is already confirmed. (We keep
    /// probing even while on the relay, to find a direct upgrade.)
    pub fn wants_direct_probe(&self) -> bool {
        self.state != PathState::Direct
    }

    /// Note that probing has begun (handshakes are going out). Moves
    /// [`Idle`](PathState::Idle) → [`Connecting`](PathState::Connecting).
    pub fn begin_probing(&mut self) -> Option<Transition> {
        if self.state == PathState::Idle {
            self.state = PathState::Connecting;
            Some(Transition::Probing)
        } else {
            None
        }
    }

    /// Record an authenticated inbound packet over the **direct** path at `now`.
    /// Confirms (or upgrades to) [`Direct`](PathState::Direct).
    pub fn on_direct_packet(&mut self, now: Instant) -> Option<Transition> {
        self.last_direct = Some(now);
        if self.state != PathState::Direct {
            self.state = PathState::Direct;
            Some(Transition::UpgradedToDirect)
        } else {
            None
        }
    }

    /// Record an authenticated inbound packet over the **relay** path at `now`.
    /// Brings up the relay fallback if we have no direct path; if we are already
    /// [`Direct`](PathState::Direct) it only refreshes the relay's liveness (the
    /// relay stays a hot standby, traffic keeps using direct).
    pub fn on_relay_packet(&mut self, now: Instant) -> Option<Transition> {
        self.last_relay = Some(now);
        match self.state {
            PathState::Idle | PathState::Connecting => {
                self.state = PathState::Relay;
                Some(Transition::UsingRelay)
            }
            PathState::Relay | PathState::Direct => None,
        }
    }

    /// Advance time to `now`, downgrading a confirmed path that has gone stale.
    ///
    /// * A stale **direct** path falls back to the relay if one is live,
    ///   otherwise resumes probing.
    /// * A stale **relay** path resumes probing.
    pub fn tick(&mut self, now: Instant) -> Option<Transition> {
        match self.state {
            PathState::Direct if self.is_stale(self.last_direct, now, self.direct_timeout) => {
                if self.relay_is_live(now) {
                    self.state = PathState::Relay;
                    Some(Transition::DowngradedToRelay)
                } else {
                    self.state = PathState::Connecting;
                    Some(Transition::DowngradedToConnecting)
                }
            }
            PathState::Relay if self.is_stale(self.last_relay, now, self.relay_timeout) => {
                self.state = PathState::Connecting;
                Some(Transition::RelayLost)
            }
            _ => None,
        }
    }

    /// Whether `ts` is missing or older than `timeout` as of `now`.
    fn is_stale(&self, ts: Option<Instant>, now: Instant, timeout: Duration) -> bool {
        ts.is_none_or(|t| now.saturating_duration_since(t) >= timeout)
    }

    /// Whether the relay has been heard from within its staleness window.
    fn relay_is_live(&self, now: Instant) -> bool {
        self.last_relay
            .is_some_and(|t| now.saturating_duration_since(t) < self.relay_timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn starts_idle_with_no_path() {
        let m = PathMachine::new();
        assert_eq!(m.state(), PathState::Idle);
        assert_eq!(m.path(), Path::None);
        assert!(m.wants_direct_probe());
    }

    #[test]
    fn idle_to_connecting_on_begin_probing() {
        let mut m = PathMachine::new();
        assert_eq!(m.begin_probing(), Some(Transition::Probing));
        assert_eq!(m.state(), PathState::Connecting);
        // Idempotent: a second begin from a non-idle state is a no-op.
        assert_eq!(m.begin_probing(), None);
    }

    #[test]
    fn direct_packet_confirms_direct_then_is_idempotent() {
        let base = Instant::now();
        let mut m = PathMachine::new();
        m.begin_probing();
        assert_eq!(m.on_direct_packet(base), Some(Transition::UpgradedToDirect));
        assert_eq!(m.state(), PathState::Direct);
        assert_eq!(m.path(), Path::Direct);
        assert!(
            !m.wants_direct_probe(),
            "no need to probe once direct is up"
        );
        // A further direct packet just refreshes liveness, no transition.
        assert_eq!(m.on_direct_packet(at(base, 1)), None);
    }

    #[test]
    fn relay_brings_up_fallback_then_direct_upgrades() {
        let base = Instant::now();
        let mut m = PathMachine::new();
        m.begin_probing();
        assert_eq!(m.on_relay_packet(base), Some(Transition::UsingRelay));
        assert_eq!(m.state(), PathState::Relay);
        assert_eq!(m.path(), Path::Relay);
        assert!(m.wants_direct_probe(), "keep probing for a direct upgrade");
        // Direct comes up later -> upgrade.
        assert_eq!(
            m.on_direct_packet(at(base, 2)),
            Some(Transition::UpgradedToDirect)
        );
        assert_eq!(m.path(), Path::Direct);
        // Relay packets while direct stay direct (relay is a hot standby).
        assert_eq!(m.on_relay_packet(at(base, 3)), None);
        assert_eq!(m.state(), PathState::Direct);
    }

    #[test]
    fn stale_direct_downgrades_to_relay_when_relay_is_live() {
        let base = Instant::now();
        let mut m = PathMachine::with_timeouts(Duration::from_secs(20), Duration::from_secs(40));
        m.begin_probing();
        m.on_relay_packet(base); // relay heard at t=0
        m.on_direct_packet(base); // direct up at t=0 (overrides to Direct)
        assert_eq!(m.state(), PathState::Direct);
        // No direct traffic for 21s, but the relay was refreshed at t=5 (live).
        m.on_relay_packet(at(base, 5));
        let t = m.tick(at(base, 21));
        assert_eq!(t, Some(Transition::DowngradedToRelay));
        assert_eq!(m.path(), Path::Relay);
        assert!(t.unwrap().should_resume_probing());
    }

    #[test]
    fn stale_direct_downgrades_to_connecting_without_relay() {
        let base = Instant::now();
        let mut m = PathMachine::with_timeouts(Duration::from_secs(20), Duration::from_secs(40));
        m.begin_probing();
        m.on_direct_packet(base);
        // No relay ever, no direct traffic for 25s -> resume probing.
        let t = m.tick(at(base, 25));
        assert_eq!(t, Some(Transition::DowngradedToConnecting));
        assert_eq!(m.state(), PathState::Connecting);
        assert_eq!(m.path(), Path::None);
        assert!(t.unwrap().should_resume_probing());
    }

    #[test]
    fn relay_downgrade_when_relay_also_went_stale() {
        let base = Instant::now();
        let mut m = PathMachine::with_timeouts(Duration::from_secs(20), Duration::from_secs(40));
        m.begin_probing();
        m.on_direct_packet(base);
        // Relay last heard at t=5; direct stale at t=21. Relay (window 40s) is
        // still live at 21, so we downgrade to relay first.
        m.on_relay_packet(at(base, 5));
        assert_eq!(m.tick(at(base, 21)), Some(Transition::DowngradedToRelay));
        // Now the relay itself goes silent past its 40s window (t=5 + 40 = 45).
        assert_eq!(m.tick(at(base, 46)), Some(Transition::RelayLost));
        assert_eq!(m.state(), PathState::Connecting);
    }

    #[test]
    fn fresh_direct_path_is_not_downgraded() {
        let base = Instant::now();
        let mut m = PathMachine::with_timeouts(Duration::from_secs(20), Duration::from_secs(40));
        m.begin_probing();
        m.on_direct_packet(base);
        // Steady traffic keeps it fresh; ticks just short of the window do nothing.
        assert_eq!(m.tick(at(base, 10)), None);
        m.on_direct_packet(at(base, 10));
        assert_eq!(m.tick(at(base, 19)), None);
        assert_eq!(m.state(), PathState::Direct);
    }
}
