//! High-level VPN client facade (PRD Phase 5, FR1 / M1).
//!
//! [`FerrumClient`] is the single shared entry point every native shell (iOS,
//! Android, desktop) drives — the box labelled "connection state machine" in the
//! Phase 5 architecture. It owns the connection lifecycle, talks to the
//! coordinator through [`ControlClient`](crate::ControlClient), surfaces the peer
//! set, and emits state-change events over a subscription channel.
//!
//! The types here are deliberately FFI-friendly (plain enums and records of
//! strings/vecs, no generics across the boundary) so a thin `uniffi` annotation
//! layer can wrap them into Swift/Kotlin bindings later. The data-plane bring-up
//! (TUN device + `run_mesh`) is supplied by each platform shell, which owns the
//! OS VPN integration; this facade owns everything platform-independent: control
//! sync, the state machine, and the peer view.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::broadcast;

use crate::{ControlClient, Error, PeerSpec};

/// Capacity of the event broadcast buffer (events are small and consumers are
/// expected to keep up; a lagging consumer simply misses intermediate events).
const EVENT_CAPACITY: usize = 64;

/// Granularity of the cancellable reconnect backoff sleep: the loop wakes this
/// often to check whether [`FerrumClient::disconnect`] cancelled it, so a
/// disconnect during a long backoff is honoured promptly rather than after the
/// full wait.
const BACKOFF_POLL_STEP: Duration = Duration::from_millis(50);

/// The connection lifecycle as shown to the UI (FR1/FR5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ConnectionState {
    /// No tunnel; idle.
    #[default]
    Disconnected,
    /// Registering with the coordinator and building the peer set.
    Connecting,
    /// Tunnel is up and the peer set is loaded.
    Connected,
    /// Lost the tunnel and re-establishing (network change, peer restart).
    Reconnecting,
    /// The last connect attempt failed; see the accompanying event reason.
    Failed,
}

/// How this client currently reaches a peer (Phase 4 mesh state, surfaced in the
/// connection-detail UI per FR5). Until live path probing lands this is
/// best-effort: a coordinator-provided endpoint is reported as `Direct`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum PeerPath {
    /// A direct peer-to-peer path.
    Direct,
    /// Traffic is relayed (e.g. through a MASQUE proxy).
    Relay,
    /// Path not yet determined.
    Unknown,
}

/// One peer as presented to the UI.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PeerStatus {
    /// Peer's base64 public key (its identity).
    pub public_key: String,
    /// Peer's reachable endpoint `ip:port`.
    pub endpoint: String,
    /// CIDRs routed to this peer.
    pub allowed_ips: Vec<String>,
    /// Direct vs relayed path (FR5).
    pub path: PeerPath,
}

impl PeerStatus {
    fn from_spec(spec: PeerSpec) -> Self {
        // Without live probing, treat a coordinator-listed endpoint as direct.
        let path = if spec.endpoint.is_empty() {
            PeerPath::Unknown
        } else {
            PeerPath::Direct
        };
        Self {
            public_key: spec.public_key,
            endpoint: spec.endpoint,
            allowed_ips: spec.allowed_ips,
            path,
        }
    }
}

/// An event emitted to subscribers when the client's observable state changes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ClientEvent {
    /// The connection state transitioned.
    StateChanged(ConnectionState),
    /// The peer set changed; carries the new peer count. (`u32`, not `usize`, so
    /// the type crosses the FFI boundary.)
    PeersUpdated(u32),
    /// A non-fatal or fatal error occurred; carries a human-readable reason.
    Error(String),
    /// The kill-switch's "block all traffic" signal flipped (FR5). `true` means
    /// the kill-switch is engaged *and* the tunnel is not up, so the platform
    /// shell should block non-tunnel traffic to prevent leaks; `false` means it
    /// may allow traffic again. Only emitted when the signal actually changes.
    TrafficBlocked(bool),
}

/// Policy governing automatic reconnect (FR5 reliability).
///
/// Backoff starts at `initial_backoff_ms` and doubles after each failed attempt,
/// capped at `max_backoff_ms`. `max_retries` bounds the number of *retries* after
/// the initial attempt (so the loop makes up to `max_retries + 1` attempts);
/// `0` means retry indefinitely until success or [`FerrumClient::disconnect`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ReconnectPolicy {
    /// Maximum retries after the first attempt; `0` = retry forever.
    pub max_retries: u32,
    /// Backoff before the first retry, in milliseconds.
    pub initial_backoff_ms: u64,
    /// Upper bound the doubling backoff is clamped to, in milliseconds.
    pub max_backoff_ms: u64,
}

impl Default for ReconnectPolicy {
    /// Retry forever, 1 s initial backoff doubling up to 30 s — a sensible
    /// always-on default for a long-lived client.
    fn default() -> Self {
        Self {
            max_retries: 0,
            initial_backoff_ms: 1_000,
            max_backoff_ms: 30_000,
        }
    }
}

/// Identity + registration details a client presents to the coordinator.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ClientIdentity {
    /// This device's base64 public key.
    pub public_key: String,
    /// Human-friendly device name.
    pub name: String,
    /// This device's reachable endpoint advertised to peers (`ip:port`).
    pub endpoint: String,
    /// Policy tags (ignored by the coordinator when OIDC auth derives them).
    pub tags: Vec<String>,
}

#[derive(Default)]
struct Inner {
    state: ConnectionState,
    address: Option<String>,
    peers: Vec<PeerStatus>,
    /// Whether the kill-switch is armed (the user's policy choice).
    kill_switch: bool,
    /// Last broadcast value of the derived "block traffic" signal, so
    /// [`FerrumClient::refresh_traffic_block`] only emits on a real change.
    traffic_blocked: bool,
    /// Optional OIDC bearer token applied to every coordinator RPC this client
    /// makes (via [`FerrumClient::set_token`]). `None` when the coordinator runs
    /// without auth.
    token: Option<String>,
}

/// The shared client core: connection state machine + control-plane sync.
///
/// Cheap to clone (`Arc`-backed); clones share the same state and event stream.
#[derive(Clone)]
pub struct FerrumClient {
    inner: Arc<Mutex<Inner>>,
    events: broadcast::Sender<ClientEvent>,
    /// Monotonic token bumped by [`disconnect`](FerrumClient::disconnect); a
    /// running reconnect loop captures it at entry and bails when it changes, so
    /// a disconnect (or a fresh connect) cancels an in-flight retry loop.
    generation: Arc<AtomicU64>,
}

impl Default for FerrumClient {
    fn default() -> Self {
        Self::new()
    }
}

impl FerrumClient {
    /// Create a fresh, disconnected client.
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            events,
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Subscribe to state-change events. The returned receiver yields every
    /// [`ClientEvent`] emitted after this call (the UI typically calls `status`
    /// once for the current value, then drives off this stream).
    pub fn subscribe(&self) -> broadcast::Receiver<ClientEvent> {
        self.events.subscribe()
    }

    /// Attach (or clear) an OIDC bearer token applied to every coordinator RPC
    /// this client makes — registration, network-map fetch/watch, candidate
    /// publish, and relay lookup. Required when the coordinator runs with OIDC
    /// auth; pass `None` (the default) otherwise. Set it before `connect`/
    /// `run_mesh_session`; it is read each time a control channel is opened, so it
    /// also applies to every reconnect.
    pub fn set_token(&self, token: Option<String>) {
        self.inner.lock().expect("client mutex poisoned").token = token;
    }

    /// The currently configured bearer token, if any (crate-internal: the
    /// data-plane runner reads it to authenticate its own control channels).
    pub(crate) fn token(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("client mutex poisoned")
            .token
            .clone()
    }

    /// The current connection state.
    pub fn status(&self) -> ConnectionState {
        self.inner.lock().expect("client mutex poisoned").state
    }

    /// The assigned tunnel address, once connected (e.g. `10.8.0.2/32`).
    pub fn address(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("client mutex poisoned")
            .address
            .clone()
    }

    /// The current peer list (FR1 `peer_list`).
    pub fn peers(&self) -> Vec<PeerStatus> {
        self.inner
            .lock()
            .expect("client mutex poisoned")
            .peers
            .clone()
    }

    /// Connect: register with the coordinator at `coordinator` and load the peer
    /// set. Drives the state machine Disconnected/Failed → Connecting → Connected
    /// (or → Failed), emitting an event on each transition.
    ///
    /// The OS data-plane bring-up (TUN + `run_mesh`) is the platform shell's job;
    /// this establishes the control-plane session and the peer view it needs.
    pub async fn connect(
        &self,
        coordinator: impl Into<String>,
        identity: &ClientIdentity,
    ) -> Result<(), Error> {
        self.set_state(ConnectionState::Connecting);

        let result = self.do_connect(coordinator.into(), identity).await;
        match result {
            Ok(()) => {
                self.set_state(ConnectionState::Connected);
                Ok(())
            }
            Err(e) => {
                self.emit(ClientEvent::Error(e.to_string()));
                self.set_state(ConnectionState::Failed);
                Err(e)
            }
        }
    }

    /// Connect with automatic reconnect (FR5): like [`connect`](FerrumClient::connect),
    /// but on failure it transitions to `Reconnecting` and retries with
    /// exponential backoff per `policy` instead of giving up at the first error.
    ///
    /// Returns `Ok(())` once connected, or `Err` only after the policy's retries
    /// are exhausted (leaving the client `Failed`). A call to
    /// [`disconnect`](FerrumClient::disconnect) — or another connect — cancels an
    /// in-flight loop, in which case this returns `Ok(())` without forcing a
    /// state (the cancelling call owns the resulting state).
    ///
    /// Like `connect`, this establishes the *control-plane* session; the platform
    /// shell still owns the OS data-plane bring-up. A shell that wants the data
    /// plane to come back after a drop reruns its mesh session when this resolves.
    pub async fn connect_with_retry(
        &self,
        coordinator: impl Into<String>,
        identity: &ClientIdentity,
        policy: &ReconnectPolicy,
    ) -> Result<(), Error> {
        let coordinator = coordinator.into();
        // Snapshot the generation; a concurrent disconnect/connect bumps it and
        // we abandon this loop so we don't fight the newer caller for the state.
        let generation = self.generation.load(Ordering::SeqCst);
        let mut attempt: u32 = 0;
        let mut backoff = policy.initial_backoff_ms.max(1);

        self.set_state(ConnectionState::Connecting);
        loop {
            match self.do_connect(coordinator.clone(), identity).await {
                Ok(()) => {
                    if self.is_cancelled(generation) {
                        return Ok(());
                    }
                    self.set_state(ConnectionState::Connected);
                    return Ok(());
                }
                Err(e) => {
                    if self.is_cancelled(generation) {
                        return Ok(());
                    }
                    self.emit(ClientEvent::Error(e.to_string()));
                    attempt += 1;
                    if policy.max_retries != 0 && attempt > policy.max_retries {
                        self.set_state(ConnectionState::Failed);
                        return Err(e);
                    }
                    self.set_state(ConnectionState::Reconnecting);
                    // Cancellable backoff: a disconnect during the wait stops us.
                    if !self.sleep_unless_cancelled(backoff, generation).await {
                        return Ok(());
                    }
                    backoff = backoff.saturating_mul(2).min(policy.max_backoff_ms.max(1));
                }
            }
        }
    }

    /// Whether a newer `disconnect`/connect has superseded the loop that captured
    /// `generation`.
    fn is_cancelled(&self, generation: u64) -> bool {
        self.generation.load(Ordering::SeqCst) != generation
    }

    /// Sleep `ms` milliseconds, waking every [`BACKOFF_POLL_STEP`] to check for
    /// cancellation. Returns `true` if the full delay elapsed, `false` if a
    /// `disconnect`/connect cancelled the owning loop partway through.
    async fn sleep_unless_cancelled(&self, ms: u64, generation: u64) -> bool {
        let total = Duration::from_millis(ms);
        let mut elapsed = Duration::ZERO;
        while elapsed < total {
            if self.is_cancelled(generation) {
                return false;
            }
            let chunk = BACKOFF_POLL_STEP.min(total - elapsed);
            tokio::time::sleep(chunk).await;
            elapsed += chunk;
        }
        !self.is_cancelled(generation)
    }

    async fn do_connect(
        &self,
        coordinator: String,
        identity: &ClientIdentity,
    ) -> Result<(), Error> {
        let mut control = ControlClient::connect(coordinator).await?;
        if let Some(token) = self.token() {
            control = control.with_token(token);
        }
        let plan = control
            .plan(
                &identity.public_key,
                &identity.name,
                &identity.endpoint,
                &identity.tags,
            )
            .await?;

        let peers: Vec<PeerStatus> = plan.peers.into_iter().map(PeerStatus::from_spec).collect();
        let count = peers.len();
        {
            let mut inner = self.inner.lock().expect("client mutex poisoned");
            inner.address = Some(plan.address);
            inner.peers = peers;
        }
        self.emit(ClientEvent::PeersUpdated(count as u32));
        Ok(())
    }

    /// Rotate this device's static key with the coordinator (PRD Phase 3, FR3).
    ///
    /// Opens a control channel (carrying the configured bearer token, if any) and
    /// asks the coordinator to move the device's registration from
    /// `old_public_key` to `new_public_key` — preserving the assigned tunnel IP,
    /// name, endpoint, tags, and candidates — returning the unchanged CIDR.
    ///
    /// This rotates the *control-plane* identity only. For a graceful
    /// re-handshake the caller generates a fresh WireGuard keypair, rotates here,
    /// then rebuilds the OS data plane with the new private key (e.g. by re-running
    /// its supervised mesh session). Peers learn the new key over their watch
    /// stream and re-handshake to it. A shell can drive this on any interval it
    /// chooses to get periodic rotation.
    pub async fn rotate_key(
        &self,
        coordinator: impl Into<String>,
        old_public_key: &str,
        new_public_key: &str,
    ) -> Result<String, Error> {
        let mut control = ControlClient::connect(coordinator.into()).await?;
        if let Some(token) = self.token() {
            control = control.with_token(token);
        }
        control.rotate_key(old_public_key, new_public_key).await
    }

    /// Disconnect: tear down the session view and return to `Disconnected`.
    ///
    /// Also cancels any in-flight [`connect_with_retry`](FerrumClient::connect_with_retry)
    /// loop (so an always-on client stops retrying when the user disconnects).
    pub fn disconnect(&self) {
        // Bump first so a reconnect loop sees the cancellation before we set the
        // state, and can't clobber `Disconnected` with a late transition.
        self.generation.fetch_add(1, Ordering::SeqCst);
        {
            let mut inner = self.inner.lock().expect("client mutex poisoned");
            inner.peers.clear();
            inner.address = None;
        }
        self.emit(ClientEvent::PeersUpdated(0));
        self.set_state(ConnectionState::Disconnected);
    }

    /// Arm or disarm the kill-switch (FR5). When armed, the client signals that
    /// non-tunnel traffic should be blocked whenever the tunnel is not up; the
    /// platform shell enforces it (firewall rules) and observes the intent via
    /// [`traffic_blocked`](FerrumClient::traffic_blocked) and the
    /// [`ClientEvent::TrafficBlocked`] event. Idempotent.
    pub fn set_kill_switch(&self, enabled: bool) {
        self.inner
            .lock()
            .expect("client mutex poisoned")
            .kill_switch = enabled;
        self.refresh_traffic_block();
    }

    /// Whether the kill-switch is armed (the policy choice, independent of the
    /// current connection state).
    pub fn kill_switch_enabled(&self) -> bool {
        self.inner
            .lock()
            .expect("client mutex poisoned")
            .kill_switch
    }

    /// The derived "block non-tunnel traffic now" signal: `true` iff the
    /// kill-switch is armed and the tunnel is not currently `Connected`. The
    /// platform shell reads this to decide whether to apply leak-blocking rules.
    pub fn traffic_blocked(&self) -> bool {
        let inner = self.inner.lock().expect("client mutex poisoned");
        Self::block_signal(&inner)
    }

    /// Compute the kill-switch block signal from current state.
    fn block_signal(inner: &Inner) -> bool {
        inner.kill_switch && inner.state != ConnectionState::Connected
    }

    /// Recompute the block signal and broadcast [`ClientEvent::TrafficBlocked`]
    /// only if it changed since the last broadcast. Called after any change to
    /// the kill-switch arming or the connection state.
    fn refresh_traffic_block(&self) {
        let changed = {
            let mut inner = self.inner.lock().expect("client mutex poisoned");
            let now = Self::block_signal(&inner);
            if now == inner.traffic_blocked {
                None
            } else {
                inner.traffic_blocked = now;
                Some(now)
            }
        };
        if let Some(blocked) = changed {
            self.emit(ClientEvent::TrafficBlocked(blocked));
        }
    }

    /// Replace the peer set (e.g. from a live `WatchNetworkMap` push) and notify
    /// subscribers. Used by the platform shell's watch loop to keep the UI fresh.
    pub fn apply_peers(&self, specs: Vec<PeerSpec>) {
        let peers: Vec<PeerStatus> = specs.into_iter().map(PeerStatus::from_spec).collect();
        let count = peers.len();
        self.inner.lock().expect("client mutex poisoned").peers = peers;
        self.emit(ClientEvent::PeersUpdated(count as u32));
    }

    /// Set the connection state and broadcast the transition (idempotent: a
    /// no-op state set emits nothing).
    fn set_state(&self, next: ConnectionState) {
        {
            let mut inner = self.inner.lock().expect("client mutex poisoned");
            if inner.state == next {
                return;
            }
            inner.state = next;
        }
        self.emit(ClientEvent::StateChanged(next));
        // The kill-switch block signal depends on the state, so re-evaluate it
        // (and emit `TrafficBlocked` if it flipped) after every transition.
        self.refresh_traffic_block();
    }

    fn emit(&self, event: ClientEvent) {
        // Ignore the "no subscribers" error — events are best-effort.
        let _ = self.events.send(event);
    }

    /// Move the facade into `Reconnecting` (crate-internal): used by the data-plane
    /// supervisor between a dropped session and its next attempt, so the UI shows
    /// a reconnect in progress rather than a bare `Disconnected`/`Failed`.
    ///
    /// Gated to `data-plane` (the supervisor is its only caller) so non-data-plane
    /// builds don't flag it as dead code under `-D warnings`.
    #[cfg(feature = "data-plane")]
    pub(crate) fn mark_reconnecting(&self) {
        self.set_state(ConnectionState::Reconnecting);
    }

    /// Broadcast an `Error` event (crate-internal): lets the supervisor surface a
    /// data-plane build failure (TUN/transport) that happens before
    /// [`connect`](FerrumClient::connect) would otherwise emit one.
    ///
    /// Gated to `data-plane` (the supervisor is its only caller) so non-data-plane
    /// builds don't flag it as dead code under `-D warnings`.
    #[cfg(feature = "data-plane")]
    pub(crate) fn emit_error(&self, reason: String) {
        self.emit(ClientEvent::Error(reason));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_control_proto::coordinator::coordinator_server::CoordinatorServer;
    use ferrum_coordinator::{CoordinatorService, Registry};
    use std::net::Ipv4Addr;
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    async fn start_coordinator() -> String {
        let registry = StdArc::new(StdMutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let svc = CoordinatorService::new(registry);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            Server::builder()
                .add_service(CoordinatorServer::new(svc))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        format!("http://{addr}")
    }

    fn identity(pk: &str, name: &str, endpoint: &str) -> ClientIdentity {
        ClientIdentity {
            public_key: pk.into(),
            name: name.into(),
            endpoint: endpoint.into(),
            tags: vec![],
        }
    }

    #[test]
    fn new_client_starts_disconnected() {
        let c = FerrumClient::new();
        assert_eq!(c.status(), ConnectionState::Disconnected);
        assert!(c.peers().is_empty());
        assert!(c.address().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_drives_state_and_loads_peers() {
        let url = start_coordinator().await;
        let a = FerrumClient::new();
        let b = FerrumClient::new();

        // A connects first: assigned .2, no peers yet.
        a.connect(url.clone(), &identity("AAA", "laptop", "1.1.1.1:51820"))
            .await
            .unwrap();
        assert_eq!(a.status(), ConnectionState::Connected);
        assert_eq!(a.address().as_deref(), Some("10.8.0.2/32"));
        assert!(a.peers().is_empty());

        // B connects: assigned .3, sees A as a peer.
        b.connect(url, &identity("BBB", "gateway", "2.2.2.2:51820"))
            .await
            .unwrap();
        assert_eq!(b.status(), ConnectionState::Connected);
        let peers = b.peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].public_key, "AAA");
        assert_eq!(peers[0].endpoint, "1.1.1.1:51820");
        assert_eq!(peers[0].path, PeerPath::Direct);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subscribers_observe_state_transitions() {
        let url = start_coordinator().await;
        let c = FerrumClient::new();
        let mut events = c.subscribe();

        c.connect(url, &identity("AAA", "laptop", "1.1.1.1:51820"))
            .await
            .unwrap();

        // Expect: Connecting, PeersUpdated(0), Connected (in order).
        assert_eq!(
            events.recv().await.unwrap(),
            ClientEvent::StateChanged(ConnectionState::Connecting)
        );
        assert_eq!(events.recv().await.unwrap(), ClientEvent::PeersUpdated(0));
        assert_eq!(
            events.recv().await.unwrap(),
            ClientEvent::StateChanged(ConnectionState::Connected)
        );

        c.disconnect();
        assert_eq!(events.recv().await.unwrap(), ClientEvent::PeersUpdated(0));
        assert_eq!(
            events.recv().await.unwrap(),
            ClientEvent::StateChanged(ConnectionState::Disconnected)
        );
        assert_eq!(c.status(), ConnectionState::Disconnected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_failure_transitions_to_failed() {
        let c = FerrumClient::new();
        // Nothing listening on this port -> connect fails.
        let err = c
            .connect(
                "http://127.0.0.1:1",
                &identity("AAA", "laptop", "1.1.1.1:51820"),
            )
            .await;
        assert!(err.is_err());
        assert_eq!(c.status(), ConnectionState::Failed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn set_token_is_applied_and_does_not_break_a_no_auth_coordinator() {
        let url = start_coordinator().await; // no OIDC
        let c = FerrumClient::new();
        assert_eq!(c.token(), None);

        // A token set on the client is carried on every control RPC; a coordinator
        // without auth simply ignores it, so connect still succeeds.
        c.set_token(Some("a.b.c".to_string()));
        assert_eq!(c.token().as_deref(), Some("a.b.c"));
        c.connect(url, &identity("AAA", "laptop", "1.1.1.1:51820"))
            .await
            .unwrap();
        assert_eq!(c.status(), ConnectionState::Connected);

        // Clearing it is honoured.
        c.set_token(None);
        assert_eq!(c.token(), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rotate_key_through_the_facade_keeps_the_address() {
        let url = start_coordinator().await;
        let a = FerrumClient::new();
        let b = FerrumClient::new();

        a.connect(url.clone(), &identity("OLD", "laptop", "1.1.1.1:51820"))
            .await
            .unwrap();
        let addr = a.address().unwrap();

        // Rotate A's control-plane key; the assigned CIDR is unchanged.
        let after = a.rotate_key(url.clone(), "OLD", "NEW").await.unwrap();
        assert_eq!(after, addr);

        // A peer connecting now sees A under its NEW key.
        b.connect(url, &identity("BBB", "gateway", "2.2.2.2:51820"))
            .await
            .unwrap();
        let peers = b.peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].public_key, "NEW");
    }

    fn fast_policy(max_retries: u32) -> ReconnectPolicy {
        ReconnectPolicy {
            max_retries,
            initial_backoff_ms: 10,
            max_backoff_ms: 10,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_with_retry_reconnects_then_fails_after_exhaustion() {
        let c = FerrumClient::new();
        let mut events = c.subscribe();

        // Nothing listening -> every attempt fails. With 2 retries the loop makes
        // 3 attempts, passing through Reconnecting, before giving up as Failed.
        let err = c
            .connect_with_retry(
                "http://127.0.0.1:1",
                &identity("AAA", "laptop", "1.1.1.1:51820"),
                &fast_policy(2),
            )
            .await;
        assert!(err.is_err());
        assert_eq!(c.status(), ConnectionState::Failed);

        // The transition stream shows at least one Reconnecting before Failed.
        let mut saw_reconnecting = false;
        let mut saw_failed = false;
        while let Ok(ev) = events.try_recv() {
            match ev {
                ClientEvent::StateChanged(ConnectionState::Reconnecting) => saw_reconnecting = true,
                ClientEvent::StateChanged(ConnectionState::Failed) => saw_failed = true,
                _ => {}
            }
        }
        assert!(saw_reconnecting, "expected a Reconnecting transition");
        assert!(saw_failed, "expected a Failed transition");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_with_retry_succeeds_when_coordinator_is_up() {
        let url = start_coordinator().await;
        let c = FerrumClient::new();
        c.connect_with_retry(
            url,
            &identity("AAA", "laptop", "1.1.1.1:51820"),
            &fast_policy(3),
        )
        .await
        .unwrap();
        assert_eq!(c.status(), ConnectionState::Connected);
        assert_eq!(c.address().as_deref(), Some("10.8.0.2/32"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disconnect_cancels_an_in_flight_reconnect_loop() {
        let c = FerrumClient::new();
        // Long backoff + infinite retries: the loop would never end on its own.
        let policy = ReconnectPolicy {
            max_retries: 0,
            initial_backoff_ms: 60_000,
            max_backoff_ms: 60_000,
        };
        let runner = c.clone();
        let handle = tokio::spawn(async move {
            runner
                .connect_with_retry(
                    "http://127.0.0.1:1",
                    &identity("AAA", "laptop", "1.1.1.1:51820"),
                    &policy,
                )
                .await
        });

        // Let it fail once and enter Reconnecting, then cancel via disconnect.
        wait_for(Duration::from_secs(5), || {
            c.status() == ConnectionState::Reconnecting
        })
        .await;
        c.disconnect();

        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("reconnect loop did not stop after disconnect")
            .expect("task panicked");
        assert!(result.is_ok(), "cancelled loop should return Ok");
        assert_eq!(c.status(), ConnectionState::Disconnected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kill_switch_blocks_until_connected_then_releases() {
        let url = start_coordinator().await;
        let c = FerrumClient::new();
        let mut events = c.subscribe();

        // Arm the kill-switch while disconnected: traffic must be blocked now.
        c.set_kill_switch(true);
        assert!(c.kill_switch_enabled());
        assert!(c.traffic_blocked(), "armed + not connected => blocked");
        assert_eq!(
            events.recv().await.unwrap(),
            ClientEvent::TrafficBlocked(true)
        );

        // Connecting brings the tunnel up, which releases the block.
        c.connect(url, &identity("AAA", "laptop", "1.1.1.1:51820"))
            .await
            .unwrap();
        assert!(!c.traffic_blocked(), "connected => not blocked");

        // The release is observable as a TrafficBlocked(false) event.
        let mut saw_release = false;
        while let Ok(ev) = events.try_recv() {
            if ev == ClientEvent::TrafficBlocked(false) {
                saw_release = true;
            }
        }
        assert!(saw_release, "expected TrafficBlocked(false) on connect");

        // Disconnecting re-blocks while the kill-switch stays armed.
        c.disconnect();
        assert!(c.traffic_blocked(), "armed + disconnected => blocked again");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kill_switch_change_only_emits_on_real_change() {
        let c = FerrumClient::new();
        let mut events = c.subscribe();

        // Disarmed while disconnected: block signal stays false, so arming-then-
        // disarming nets no change and emits nothing.
        c.set_kill_switch(false);
        c.set_kill_switch(true); // false -> true (one event)
        c.set_kill_switch(true); // idempotent, no event
        c.set_kill_switch(false); // true -> false (one event)

        assert_eq!(
            events.recv().await.unwrap(),
            ClientEvent::TrafficBlocked(true)
        );
        assert_eq!(
            events.recv().await.unwrap(),
            ClientEvent::TrafficBlocked(false)
        );
        assert!(
            events.try_recv().is_err(),
            "no extra TrafficBlocked events expected"
        );
    }

    /// Poll `cond` until it holds or `timeout` elapses.
    async fn wait_for(timeout: Duration, mut cond: impl FnMut() -> bool) {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("condition not met within {timeout:?}");
    }
}
