//! ICE-style candidate prioritization (RFC 8445) for ordering NAT-traversal
//! connectivity checks (PRD Phase 4 hardening).
//!
//! Phase 4 already *gathers* candidates ([`ferrum_transport::stun`]), *signals*
//! them through the coordinator, and *probes* them ([`mesh::probe_targets`](crate::mesh)).
//! What was missing is **order**: the original prober fanned handshakes across a
//! peer's candidates in arrival order, so a slow WAN path could be tried before a
//! fast LAN one. ICE solves this with a deterministic priority — try the path
//! most likely to be both reachable and low-latency first.
//!
//! This module implements the two priority formulas from RFC 8445 as pure
//! functions and exposes [`prioritized_targets`], which the mesh prober uses to
//! order a peer's probe targets:
//!
//! * **Candidate priority** (RFC 8445 §5.1.2.1):
//!   `priority = 2^24·type_pref + 2^8·local_pref + (256 − component_id)`.
//!   The dominant term is the candidate *type*: a **host** candidate (a directly
//!   reachable LAN address) outranks a **server-reflexive** one (a NAT mapping),
//!   which outranks a **relayed** one (traffic through a third party). So peers on
//!   a shared LAN find each other directly before falling back to the public path.
//! * **Candidate-pair priority** (RFC 8445 §6.1.2.3):
//!   `pair = 2^32·min(G,D) + 2·max(G,D) + (G>D ? 1 : 0)`, combining a local and a
//!   remote candidate's priorities into a single checklist ordering.
//!
//! Candidate *kind* is not carried on the wire (candidates are plain `ip:port`
//! strings end to end), so [`Candidate::classify`] infers it from address scope:
//! a private / link-local / loopback address is a host candidate, anything
//! globally routable is treated as server-reflexive. This is a heuristic, not a
//! gather-time label, but it produces the ordering that matters in practice
//! (LAN before WAN) without a control-plane schema change.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// The kind of an ICE candidate, in RFC 8445 priority order (highest first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CandidateKind {
    /// A directly reachable local address (LAN / loopback). Highest preference:
    /// lowest latency and no third party when peers share a network.
    Host,
    /// A candidate learned from an inbound connectivity check (a peer's observed
    /// source). Ranks just below host per RFC 8445's recommended default.
    PeerReflexive,
    /// A public `ip:port` a NAT maps a local socket to (discovered via STUN).
    ServerReflexive,
    /// An address on a relay; traffic is forwarded by a third party. Lowest
    /// preference — the fallback of last resort.
    Relayed,
}

impl CandidateKind {
    /// The RFC 8445 §5.1.2.2 *recommended* type preference (0–126, higher = more
    /// preferred). These are the values from the spec's examples.
    pub const fn type_preference(self) -> u32 {
        match self {
            CandidateKind::Host => 126,
            CandidateKind::PeerReflexive => 110,
            CandidateKind::ServerReflexive => 100,
            CandidateKind::Relayed => 0,
        }
    }
}

/// Component ID of a single-component (UDP) media stream — RFC 8445 §4.1.1.1.
/// Ferrum carries one component, so this is always 1.
pub const COMPONENT_RTP: u32 = 1;

/// An ICE candidate: a transport address paired with its inferred kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// The candidate transport address.
    pub addr: SocketAddr,
    /// The candidate kind (drives the dominant priority term).
    pub kind: CandidateKind,
}

impl Candidate {
    /// A candidate with an explicit kind (used when the kind is known, e.g. the
    /// relay address is [`CandidateKind::Relayed`]).
    pub fn new(addr: SocketAddr, kind: CandidateKind) -> Self {
        Self { addr, kind }
    }

    /// Infer a candidate's kind from its address scope: a private, link-local, or
    /// loopback address is a [`Host`](CandidateKind::Host) candidate (only
    /// reachable on a shared network but lowest latency there); anything globally
    /// routable is treated as [`ServerReflexive`](CandidateKind::ServerReflexive)
    /// (the public NAT mapping).
    pub fn classify(addr: SocketAddr) -> Self {
        let kind = if is_local_scope(addr.ip()) {
            CandidateKind::Host
        } else {
            CandidateKind::ServerReflexive
        };
        Self { addr, kind }
    }

    /// This candidate's RFC 8445 §5.1.2.1 priority for the single UDP component.
    pub fn priority(&self) -> u32 {
        self.priority_for(COMPONENT_RTP)
    }

    /// This candidate's priority for an explicit `component_id` (1–256).
    pub fn priority_for(&self, component_id: u32) -> u32 {
        self.kind.type_preference() * (1 << 24)
            + local_preference(self.addr.ip()) * (1 << 8)
            + (256 - component_id)
    }
}

/// RFC 8445 §6.1.2.3 candidate-pair priority, combining the priorities of the
/// controlling (`g`) and controlled (`d`) agents' candidates into one ordering
/// key. Returned as `u64` because the formula's leading term scales by 2^32.
pub fn candidate_pair_priority(g: u32, d: u32) -> u64 {
    let (g, d) = (g as u64, d as u64);
    let more_significant = g.min(d);
    let less_significant = g.max(d);
    (1u64 << 32) * more_significant + 2 * less_significant + u64::from(g > d)
}

/// RFC 8421 §4: prefer IPv6 over IPv4 among same-kind candidates. The difference
/// only breaks ties within a kind (the local-preference term is dwarfed by the
/// type-preference term), and is irrelevant for an IPv4-only deployment.
fn local_preference(ip: IpAddr) -> u32 {
    match ip {
        IpAddr::V6(_) => 65_535,
        IpAddr::V4(_) => 65_534,
    }
}

/// Whether an address is reachable only within a local scope (LAN / link / host)
/// rather than globally routable — i.e. a host candidate.
fn is_local_scope(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        // `Ipv6Addr::is_unique_local` / `is_unicast_link_local` are unstable on
        // stable Rust, so test the prefixes directly: fc00::/7 (ULA) and
        // fe80::/10 (link-local).
        IpAddr::V6(v6) => {
            v6.is_loopback() || is_unique_local_v6(&v6) || is_unicast_link_local_v6(&v6)
        }
    }
}

/// fc00::/7 — IPv6 unique-local addresses (RFC 4193).
fn is_unique_local_v6(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xfe00 == 0xfc00
}

/// fe80::/10 — IPv6 link-local unicast addresses.
fn is_unicast_link_local_v6(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

/// Order a peer's probe targets — its advertised `endpoint` plus any gathered
/// `candidates` — by descending ICE priority, deduplicated.
///
/// `endpoint` is always included (it is the path the control plane advertised).
/// The sort is **stable**, so equal-priority targets keep insertion order
/// (`endpoint` first, then candidates as gathered) — preserving the prober's
/// "always try the advertised endpoint" behaviour while floating a reachable LAN
/// (host) candidate ahead of a public (server-reflexive) one.
pub fn prioritized_targets(endpoint: SocketAddr, candidates: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut targets = Vec::with_capacity(candidates.len() + 1);
    targets.push(endpoint);
    for &c in candidates {
        if !targets.contains(&c) {
            targets.push(c);
        }
    }
    // Descending priority; stable to preserve insertion order within a tier.
    targets.sort_by(|a, b| {
        Candidate::classify(*b)
            .priority()
            .cmp(&Candidate::classify(*a).priority())
    });
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn type_preferences_follow_rfc_ordering() {
        assert!(
            CandidateKind::Host.type_preference() > CandidateKind::PeerReflexive.type_preference()
        );
        assert!(
            CandidateKind::PeerReflexive.type_preference()
                > CandidateKind::ServerReflexive.type_preference()
        );
        assert!(
            CandidateKind::ServerReflexive.type_preference()
                > CandidateKind::Relayed.type_preference()
        );
    }

    #[test]
    fn classify_uses_address_scope() {
        assert_eq!(
            Candidate::classify(addr("10.0.0.1:51820")).kind,
            CandidateKind::Host
        );
        assert_eq!(
            Candidate::classify(addr("192.168.1.5:51820")).kind,
            CandidateKind::Host
        );
        assert_eq!(
            Candidate::classify(addr("127.0.0.1:51820")).kind,
            CandidateKind::Host
        );
        assert_eq!(
            Candidate::classify(addr("169.254.1.1:51820")).kind,
            CandidateKind::Host
        );
        assert_eq!(
            Candidate::classify(addr("203.0.113.7:51820")).kind,
            CandidateKind::ServerReflexive
        );
        // IPv6: ULA + link-local are host; a global unicast is server-reflexive.
        assert_eq!(
            Candidate::classify(addr("[fd00::1]:51820")).kind,
            CandidateKind::Host
        );
        assert_eq!(
            Candidate::classify(addr("[fe80::1]:51820")).kind,
            CandidateKind::Host
        );
        assert_eq!(
            Candidate::classify(addr("[2001:db8::1]:51820")).kind,
            CandidateKind::ServerReflexive
        );
    }

    #[test]
    fn host_outranks_srflx_outranks_relayed() {
        let host = Candidate::new(addr("10.0.0.1:1"), CandidateKind::Host).priority();
        let srflx =
            Candidate::new(addr("203.0.113.1:1"), CandidateKind::ServerReflexive).priority();
        let relay = Candidate::new(addr("198.51.100.1:1"), CandidateKind::Relayed).priority();
        assert!(host > srflx, "host {host} should outrank srflx {srflx}");
        assert!(srflx > relay, "srflx {srflx} should outrank relay {relay}");
    }

    #[test]
    fn priority_matches_rfc_formula() {
        // Host, IPv4 (local_pref 65534), component 1.
        let c = Candidate::new(addr("10.0.0.1:1"), CandidateKind::Host);
        let expected = 126 * (1 << 24) + 65_534 * (1 << 8) + (256 - 1);
        assert_eq!(c.priority(), expected);
    }

    #[test]
    fn ipv6_outranks_ipv4_within_a_kind() {
        let v6 = Candidate::new(addr("[fd00::1]:1"), CandidateKind::Host).priority();
        let v4 = Candidate::new(addr("10.0.0.1:1"), CandidateKind::Host).priority();
        assert!(v6 > v4, "RFC 8421 prefers IPv6 within a kind");
    }

    #[test]
    fn pair_priority_is_symmetric_in_min_max_with_tiebreak() {
        // Same {g,d} set: the larger pair priority is the one whose controlling
        // candidate (g) has the higher priority (the +1 tiebreak).
        let a = candidate_pair_priority(100, 50);
        let b = candidate_pair_priority(50, 100);
        assert_eq!(a, b + 1);
        // A pair with a higher minimum dominates one with a lower minimum.
        assert!(candidate_pair_priority(80, 80) > candidate_pair_priority(200, 1));
    }

    #[test]
    fn prioritized_targets_floats_host_ahead_of_public_endpoint() {
        // Advertised endpoint is public (server-reflexive); a LAN host candidate
        // and another public candidate are gathered.
        let endpoint = addr("203.0.113.7:51820");
        let host = addr("192.168.1.10:51820");
        let other_public = addr("198.51.100.4:51820");
        let ordered = prioritized_targets(endpoint, &[other_public, host]);
        assert_eq!(
            ordered,
            vec![host, endpoint, other_public],
            "host first, then the two public targets in insertion order (endpoint first)"
        );
    }

    #[test]
    fn prioritized_targets_dedups_and_keeps_endpoint() {
        let endpoint = addr("203.0.113.7:51820");
        // Candidates repeat the endpoint and each other.
        let ordered = prioritized_targets(endpoint, &[endpoint, endpoint]);
        assert_eq!(ordered, vec![endpoint]);
    }

    #[test]
    fn prioritized_targets_is_stable_within_a_tier() {
        // All loopback/host, equal priority: insertion order (endpoint, then
        // candidates) is preserved.
        let endpoint = addr("127.0.0.1:1");
        let c1 = addr("127.0.0.1:2");
        let c2 = addr("127.0.0.1:3");
        assert_eq!(
            prioritized_targets(endpoint, &[c1, c2]),
            vec![endpoint, c1, c2]
        );
    }
}
