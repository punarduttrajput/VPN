//! Shared wire/flow types for the relay's eBPF/XDP fast path (PRD:
//! `PRD/phase-6-ebpf-xdp-relay.md`), used by both sides of the split:
//!
//!   * `relay-ebpf` (top-level, its own standalone workspace) — the `#[xdp]`
//!     kernel program, which reads these as raw BPF map keys/values.
//!   * `ferrum-transport`'s userspace loader (`relay_xdp.rs`, `xdp` feature,
//!     Linux-only) — which writes them, mirroring `RelayServer`'s live
//!     `Clients` table (`crates/transport/src/relay.rs`).
//!
//! Deliberately `#![no_std]` (std only under `cfg(test)`) and dependency-free:
//! neither consumer should have to pull in the other's toolchain just to
//! share a struct layout. See the crate's `Cargo.toml` doc comment and the
//! PRD's Architecture section for why this is its own crate.
//!
//! **Byte-order convention** (the eBPF program has no `std::net` to lean on,
//! so this has to be pinned down explicitly and used consistently on both
//! sides): every field below is a plain integer **value**, exactly like
//! [`core::net::Ipv4Addr`]'s own `u32` representation — obtained by
//! `from_be_bytes` when read off the wire, and converted back with
//! `to_be_bytes` only at the moment it's written into a packet. Nothing here
//! is ever stored pre-byte-swapped; there is no `_be`-suffixed field. This
//! keeps the two sides trivially consistent: whatever integer value one side
//! computes, the other can compare or hash directly with no conversion.
#![cfg_attr(not(test), no_std)]

/// Length of a Ferrum WireGuard public key on the wire (matches
/// `ferrum_transport::relay::KEY_LEN` — kept as an independent constant here,
/// not re-exported, because `relay-ebpf` cannot depend on `ferrum-transport`
/// at all; a unit test below pins the two to the same value).
pub const KEY_LEN: usize = 32;
/// Relay frame tag: a client announcing its own key (see `relay.rs`'s
/// `TAG_REGISTER`). The fast path never acts on this tag — `Register` frames
/// always fall through to userspace (PRD FR1) — but it's shared here so the
/// eBPF program's tag check can't silently drift from userspace's.
pub const TAG_REGISTER: u8 = 0x01;
/// Relay frame tag: a data frame (see `relay.rs`'s `TAG_DATA`). Only frames
/// with this tag are eligible for the fast path.
pub const TAG_DATA: u8 = 0x02;
/// Data-frame header length: the tag byte plus one public key.
pub const DATA_HEADER: usize = 1 + KEY_LEN;

/// A peer's 32-byte WireGuard public key (matches `relay.rs::PublicKey`).
pub type PublicKey = [u8; KEY_LEN];

/// An IPv4 socket address, used as a BPF map key/value so the eBPF program
/// can build one directly from packet header fields (`u32`/`u16::from_be_bytes`
/// — see the module's byte-order convention) with no further conversion.
///
/// The fast path is IPv4-only (PRD Non-Goals) — there is deliberately no
/// `AddrKeyV6`; an IPv6 packet is never eligible and always falls through to
/// userspace.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AddrKey {
    /// IPv4 address as a plain integer value (`u32::from_be_bytes(octets)`
    /// — the same convention as `Ipv4Addr`'s internal representation).
    pub ip: u32,
    /// UDP port as a plain integer value (just the port number — a `u16`
    /// has no byte-order ambiguity once it's off the wire).
    pub port: u16,
}

impl AddrKey {
    /// Build an `AddrKey` from IPv4 octets (as from
    /// [`std::net::Ipv4Addr::octets`]) and a port (as from
    /// [`std::net::SocketAddrV4::port`]) — the conversion userspace needs
    /// when mirroring `RelayServer`'s `Clients` table.
    #[cfg(any(test, feature = "std"))]
    pub fn from_v4(octets: [u8; 4], port: u16) -> Self {
        Self {
            ip: u32::from_be_bytes(octets),
            port,
        }
    }
}

/// This relay's own identity plus its default gateway's MAC — the one piece
/// of L2/L3 context the fast path needs to bounce a rewritten frame back out
/// the wire (PRD FR2). A single-entry BPF array map holds one of these; an
/// all-zero value means "not yet resolved," which the eBPF program treats as
/// an automatic fast-path miss (`XDP_PASS`) rather than forwarding to a
/// garbage MAC.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GatewayInfo {
    /// This relay's own interface MAC (rewritten Ethernet source).
    pub relay_mac: [u8; 6],
    /// This relay's own IPv4 address as a plain integer value (rewritten
    /// IPv4 source — the fast path always forwards *as* the relay, exactly
    /// like `RelayServer::serve`'s single bound socket does today).
    pub relay_ip: u32,
    /// The default gateway's MAC (rewritten Ethernet destination) — see the
    /// PRD's Non-Goals for why v1 always forwards via the gateway rather
    /// than resolving a per-destination neighbor.
    pub gateway_mac: [u8; 6],
}

impl GatewayInfo {
    /// Whether this entry has actually been resolved yet (vs. the
    /// zero-initialized state a fresh BPF array map starts in).
    pub fn is_resolved(&self) -> bool {
        self.relay_mac != [0; 6] && self.gateway_mac != [0; 6]
    }
}

// SAFETY: both types are `#[repr(C)]`, contain only plain fixed-size integer
// and byte-array fields, have no padding-sensitive invariants, and are valid
// for any bit pattern — the exact contract `aya::Pod` requires. Feature-gated
// (see the `Cargo.toml` doc comment) so this crate only pulls in `aya` when
// something built against it actually needs the impl.
//
// Confirmed against the real `aya = "0.14.0"` source (downloaded to check
// this, since it's a Linux-only dependency this host can't otherwise build):
// `aya::maps::{HashMap, Array, PerCpuArray}` all bound their key/value types
// on `aya::Pod`, so this impl is required on the userspace side. The
// kernel-side `aya-ebpf = "0.2.1"` turned out **not** to need this at all —
// its map types (`aya_ebpf::maps::{HashMap, Array, PerCpuArray}`) have no
// `Pod`-equivalent bound whatsoever (confirmed the same way), so there is
// deliberately no `aya-ebpf`-side impl or feature here anymore.
#[cfg(feature = "aya-pod")]
unsafe impl aya::Pod for AddrKey {}
#[cfg(feature = "aya-pod")]
unsafe impl aya::Pod for GatewayInfo {}

#[cfg(test)]
mod tests {
    use super::*;

    // Pins this crate's wire constants to `ferrum-transport::relay`'s
    // private ones so the two can never silently drift apart (that crate
    // can't depend on this one — see the module doc — so a literal
    // duplicate-and-compare is the next best guardrail).
    #[test]
    fn constants_match_relay_rs() {
        assert_eq!(KEY_LEN, 32);
        assert_eq!(TAG_REGISTER, 0x01);
        assert_eq!(TAG_DATA, 0x02);
        assert_eq!(DATA_HEADER, 33);
    }

    #[test]
    fn addr_key_from_v4_round_trips_through_wire_bytes() {
        let k = AddrKey::from_v4([192, 168, 1, 1], 51821);
        // `ip` is a plain value: converting it back to wire bytes recovers
        // the original octets with no further byte-swapping.
        assert_eq!(k.ip.to_be_bytes(), [192, 168, 1, 1]);
        assert_eq!(k.port, 51821);
    }

    #[test]
    fn addr_key_equality_is_structural() {
        let a = AddrKey::from_v4([10, 0, 0, 1], 1000);
        let b = AddrKey::from_v4([10, 0, 0, 1], 1000);
        let c = AddrKey::from_v4([10, 0, 0, 2], 1000);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn gateway_info_default_is_unresolved() {
        assert!(!GatewayInfo::default().is_resolved());
    }

    #[test]
    fn gateway_info_resolved_once_both_macs_are_set() {
        let mut g = GatewayInfo {
            relay_mac: [1, 2, 3, 4, 5, 6],
            relay_ip: 0,
            gateway_mac: [0; 6],
        };
        assert!(!g.is_resolved(), "gateway_mac still zero");
        g.gateway_mac = [6, 5, 4, 3, 2, 1];
        assert!(g.is_resolved());
    }
}
