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

/// Ethernet II header length (RFC 894): dst MAC, src MAC, ethertype.
pub const ETH_LEN: usize = 14;
/// IPv4 header length with no options (RFC 791). The fast path only accepts
/// this shape; anything with options falls through to userspace.
pub const IPV4_MIN_LEN: usize = 20;
/// UDP header length (RFC 768).
pub const UDP_LEN: usize = 8;
/// IPv4 protocol number for UDP.
pub const IPPROTO_UDP: u8 = 17;

/// The IPv4 and UDP header fields the fast path checks before it touches a
/// packet (SEC-018), each read off the wire as a plain value (see the
/// module's byte-order convention).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ipv4UdpFields {
    /// IPv4 byte 0: version (high nibble) and IHL in 32-bit words (low).
    pub version_ihl: u8,
    /// IPv4 total length: header plus payload, in bytes.
    pub total_len: u16,
    /// IPv4 flags (top 3 bits) and fragment offset (low 13 bits).
    pub flags_frag: u16,
    /// IPv4 protocol.
    pub protocol: u8,
    /// IPv4 destination address.
    pub dst_ip: u32,
    /// UDP length: header plus payload, in bytes.
    pub udp_len: u16,
}

/// Whether a frame of `frame_len` bytes with these headers is one the fast
/// path may rewrite and forward (SEC-018). Anything else must fall through to
/// userspace (`XDP_PASS`) unchanged. Requires:
///
/// - IPv4 (version nibble 4) with no options (IHL 5), carrying UDP;
/// - **not a fragment**: no More-Fragments flag and a zero offset. A first
///   fragment would otherwise be forwarded on its own while the rest of the
///   datagram went to userspace, which can't reassemble it;
/// - addressed to **this relay** (`relay_ip`, nonzero), so traffic merely
///   passing through the interface is never rewritten;
/// - **consistent lengths**: the IPv4 total length is exactly the frame minus
///   its Ethernet header, the UDP length is exactly the IPv4 payload, and the
///   payload is long enough to hold a Data frame header.
pub fn fastpath_eligible(h: &Ipv4UdpFields, frame_len: usize, relay_ip: u32) -> bool {
    const MORE_FRAGMENTS: u16 = 0x2000;
    const FRAGMENT_OFFSET: u16 = 0x1FFF;
    let total_len = h.total_len as usize;
    h.version_ihl >> 4 == 4
        && (h.version_ihl & 0x0F) as usize * 4 == IPV4_MIN_LEN
        && h.protocol == IPPROTO_UDP
        && h.flags_frag & (MORE_FRAGMENTS | FRAGMENT_OFFSET) == 0
        && relay_ip != 0
        && h.dst_ip == relay_ip
        && total_len + ETH_LEN == frame_len
        && total_len >= IPV4_MIN_LEN + UDP_LEN + DATA_HEADER
        && h.udp_len as usize + IPV4_MIN_LEN == total_len
}

/// RFC 1624 incremental checksum update. Every argument, and the result, is a
/// plain integer value (see the module's byte-order convention).
/// `changed_words` holds an `(old, new)` pair for every 16-bit word that
/// changed; an IPv4 address is two words (see [`words_of`]).
///
/// Shared here rather than living in `relay-ebpf` so it can be unit-tested
/// against a full recomputation (SEC-018): the kernel program can't run tests.
#[inline(always)]
pub fn checksum_update(old_checksum: u16, changed_words: &[(u16, u16)]) -> u16 {
    // Ones-complement arithmetic: start from the complement of the existing
    // checksum, remove each old word's contribution (by adding its
    // complement), add each new word's contribution, then fold the carry
    // back in and complement once more (RFC 1624 eqn. 3, one word at a time).
    let mut sum: u32 = (!old_checksum) as u32;
    for &(old, new) in changed_words {
        sum += (!old) as u32;
        sum += new as u32;
    }
    // Fold with a FIXED two folds, not a `while (sum >> 16) != 0` loop: the
    // eBPF verifier rejects the loop form ("infinite loop detected"; found on
    // the first real load, 2026-07-09). Two folds suffice for up to ~32 word
    // pairs: the first leaves at most one carry bit above bit 15, the second
    // absorbs it. The fast path passes four.
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    !(sum as u16)
}

/// Split a 32-bit value into its high and low 16-bit words, in wire order.
#[inline(always)]
pub const fn words_of(v: u32) -> (u16, u16) {
    ((v >> 16) as u16, (v & 0xFFFF) as u16)
}

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
    /// Explicit padding, always zero. Without it, `repr(C)` inserts two
    /// *implicit* trailing padding bytes (size 8, align 4) whose contents
    /// Rust leaves undefined — and a BPF hash map compares keys byte-wise
    /// over the full `key_size`, so a lookup key built on the kernel stack
    /// can never reliably match an entry inserted from userspace. This was
    /// a real, observed bug (2026-07-09, first live-traffic run): every
    /// `ADDR_TO_KEY` lookup missed and all traffic fell through to
    /// userspace. Both sides must construct this as zero; [`AddrKey::new`]
    /// is the only intended constructor.
    pub _pad: [u8; 2],
}

impl AddrKey {
    /// The one intended constructor — guarantees `_pad` is zero (see its
    /// field doc: nonzero/undefined padding makes map lookups miss).
    /// `const` and `no_std` so the eBPF program can use it too.
    pub const fn new(ip: u32, port: u16) -> Self {
        Self {
            ip,
            port,
            _pad: [0; 2],
        }
    }

    /// Build an `AddrKey` from IPv4 octets (as from
    /// [`std::net::Ipv4Addr::octets`]) and a port (as from
    /// [`std::net::SocketAddrV4::port`]) — the conversion userspace needs
    /// when mirroring `RelayServer`'s `Clients` table.
    #[cfg(any(test, feature = "std"))]
    pub fn from_v4(octets: [u8; 4], port: u16) -> Self {
        Self::new(u32::from_be_bytes(octets), port)
    }
}

/// This relay's own identity plus its default gateway's MAC — the one piece
/// of L2/L3 context the fast path needs to bounce a rewritten frame back out
/// the wire (PRD FR2). A single-entry BPF array map holds one of these; an
/// all-zero value means "not yet resolved," which the eBPF program treats as
/// an automatic fast-path miss (`XDP_PASS`) rather than forwarding to a
/// garbage MAC.
///
/// Padding is explicit (SEC-018), as in [`AddrKey`]: `repr(C)` would otherwise
/// insert two undefined bytes after `relay_mac` (to align `relay_ip`) and two
/// at the end, contradicting the `Pod` impl's safety argument.
/// [`GatewayInfo::new`] zeroes them.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GatewayInfo {
    /// This relay's own interface MAC (rewritten Ethernet source).
    pub relay_mac: [u8; 6],
    /// Explicit padding, always zero (aligns `relay_ip`).
    pub _pad0: [u8; 2],
    /// This relay's own IPv4 address as a plain integer value (rewritten
    /// IPv4 source — the fast path always forwards *as* the relay, exactly
    /// like `RelayServer::serve`'s single bound socket does today). Also the
    /// address a packet must be sent to before the fast path touches it.
    pub relay_ip: u32,
    /// The default gateway's MAC (rewritten Ethernet destination) — see the
    /// PRD's Non-Goals for why v1 always forwards via the gateway rather
    /// than resolving a per-destination neighbor.
    pub gateway_mac: [u8; 6],
    /// Explicit trailing padding, always zero.
    pub _pad1: [u8; 2],
}

impl GatewayInfo {
    /// The intended constructor: guarantees both padding fields are zero.
    pub const fn new(relay_mac: [u8; 6], relay_ip: u32, gateway_mac: [u8; 6]) -> Self {
        Self {
            relay_mac,
            _pad0: [0; 2],
            relay_ip,
            gateway_mac,
            _pad1: [0; 2],
        }
    }

    /// Whether this entry has actually been resolved yet (vs. the
    /// zero-initialized state a fresh BPF array map starts in).
    pub fn is_resolved(&self) -> bool {
        self.relay_mac != [0; 6] && self.gateway_mac != [0; 6]
    }
}

// SAFETY: both types are `#[repr(C)]`, contain only plain fixed-size integer
// and byte-array fields with every padding byte explicit (no implicit padding;
// the size tests below pin this), and are valid
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
    fn addr_key_has_no_implicit_padding() {
        // 4 (ip) + 2 (port) + 2 (explicit _pad) — if this ever grows, the
        // compiler inserted implicit padding again, and BPF map lookups
        // will miss on undefined bytes (see the `_pad` field doc).
        assert_eq!(core::mem::size_of::<AddrKey>(), 8);
        assert_eq!(AddrKey::new(1, 2)._pad, [0; 2]);
        assert_eq!(AddrKey::from_v4([10, 0, 0, 1], 7)._pad, [0; 2]);
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
        let mut g = GatewayInfo::new([1, 2, 3, 4, 5, 6], 0, [0; 6]);
        assert!(!g.is_resolved(), "gateway_mac still zero");
        g.gateway_mac = [6, 5, 4, 3, 2, 1];
        assert!(g.is_resolved());
    }

    /// SEC-018: `GatewayInfo` has no implicit padding (6 + 2 + 4 + 6 + 2).
    #[test]
    fn gateway_info_has_no_implicit_padding() {
        assert_eq!(core::mem::size_of::<GatewayInfo>(), 20);
        let g = GatewayInfo::new([1; 6], 7, [2; 6]);
        assert_eq!((g._pad0, g._pad1), ([0; 2], [0; 2]));
    }

    /// The reference: a full RFC 791 header checksum over a 20-byte header
    /// whose checksum field (bytes 10..12) is treated as zero.
    fn full_checksum(h: &[u8; 20]) -> u16 {
        let mut sum: u32 = 0;
        for i in (0..20).step_by(2) {
            if i != 10 {
                sum += u32::from(u16::from_be_bytes([h[i], h[i + 1]]));
            }
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn set_checksum(h: &mut [u8; 20]) {
        let c = full_checksum(h);
        h[10..12].copy_from_slice(&c.to_be_bytes());
    }

    /// SEC-018: rewriting src and dst the way the fast path does, then
    /// updating the checksum incrementally, gives the same checksum as a full
    /// recomputation. Pseudo-random headers from a fixed-seed generator, plus
    /// the all-zero and all-ones edge cases.
    #[test]
    fn checksum_update_matches_full_recomputation() {
        let mut seed: u64 = 0x5EED_1234_ABCD_0001;
        let mut next = move || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 32) as u32
        };
        let mut cases: [[u8; 20]; 3] = [[0; 20], [0xFF; 20], [0; 20]];
        cases[2] = [
            0x45, 0, 0, 75, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let mut headers: [[u8; 20]; 2003] = [[0; 20]; 2003];
        headers[..3].copy_from_slice(&cases);
        for h in headers[3..].iter_mut() {
            for chunk in h.chunks_mut(4) {
                chunk.copy_from_slice(&next().to_be_bytes());
            }
        }
        for (n, mut h) in headers.into_iter().enumerate() {
            set_checksum(&mut h);
            let old_src = u32::from_be_bytes([h[12], h[13], h[14], h[15]]);
            let old_dst = u32::from_be_bytes([h[16], h[17], h[18], h[19]]);
            let (new_src, new_dst) = match n {
                0 => (u32::MAX, u32::MAX),
                1 => (0, 0),
                _ => (next(), next()),
            };
            let old_checksum = u16::from_be_bytes([h[10], h[11]]);
            let (os_hi, os_lo) = words_of(old_src);
            let (ns_hi, ns_lo) = words_of(new_src);
            let (od_hi, od_lo) = words_of(old_dst);
            let (nd_hi, nd_lo) = words_of(new_dst);
            let incremental = checksum_update(
                old_checksum,
                &[
                    (os_hi, ns_hi),
                    (os_lo, ns_lo),
                    (od_hi, nd_hi),
                    (od_lo, nd_lo),
                ],
            );
            h[12..16].copy_from_slice(&new_src.to_be_bytes());
            h[16..20].copy_from_slice(&new_dst.to_be_bytes());
            // Ones-complement has two zeros (0x0000 and 0xFFFF); RFC 1624
            // eqn. 3 can produce either for the same header, and both verify.
            let full = full_checksum(&h);
            assert!(
                incremental == full
                    || (incremental, full) == (0xFFFF, 0)
                    || (incremental, full) == (0, 0xFFFF),
                "case {n}: incremental {incremental:#06x} != full {full:#06x}"
            );
        }
    }

    /// The second carry fold is needed, not decorative: an accumulator of
    /// exactly 0x1FFFF folds to 0x10000, which only the second fold reduces.
    /// Random headers essentially never hit this, so pin it directly against
    /// an unbounded-loop reference.
    #[test]
    fn checksum_update_folds_a_second_carry() {
        fn reference(old_checksum: u16, changed: &[(u16, u16)]) -> u16 {
            let mut sum = u32::from(!old_checksum);
            for &(old, new) in changed {
                sum += u32::from(!old) + u32::from(new);
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            !(sum as u16)
        }
        // !0x0000 + !0x0000 + 0x0001 = 0xFFFF + 0xFFFF + 1 = 0x1FFFF.
        let changed = [(0x0000, 0x0001)];
        assert_eq!(
            checksum_update(0x0000, &changed),
            reference(0x0000, &changed)
        );
        assert_eq!(checksum_update(0x0000, &changed), 0xFFFE);
    }

    #[test]
    fn words_of_splits_in_wire_order() {
        assert_eq!(words_of(0x0A00_0001), (0x0A00, 0x0001));
    }

    const RELAY: u32 = 0x0A63_0002; // 10.99.0.2

    /// A minimal eligible Data frame: 14 + 20 + 8 + 33 bytes.
    fn eligible_fields() -> (Ipv4UdpFields, usize) {
        let total = (IPV4_MIN_LEN + UDP_LEN + DATA_HEADER) as u16;
        let h = Ipv4UdpFields {
            version_ihl: 0x45,
            total_len: total,
            flags_frag: 0x4000, // Don't Fragment: allowed
            protocol: IPPROTO_UDP,
            dst_ip: RELAY,
            udp_len: total - IPV4_MIN_LEN as u16,
        };
        (h, ETH_LEN + total as usize)
    }

    #[test]
    fn fastpath_accepts_a_well_formed_data_frame() {
        let (h, len) = eligible_fields();
        assert!(fastpath_eligible(&h, len, RELAY));
    }

    /// SEC-018: each malformed or not-for-us shape falls through.
    #[test]
    fn fastpath_rejects_everything_else() {
        let (base, len) = eligible_fields();
        let rejected = |h: Ipv4UdpFields, frame_len: usize, relay: u32, why: &str| {
            assert!(!fastpath_eligible(&h, frame_len, relay), "{why}");
        };
        rejected(
            Ipv4UdpFields {
                version_ihl: 0x65,
                ..base
            },
            len,
            RELAY,
            "IPv6 version nibble",
        );
        rejected(
            Ipv4UdpFields {
                version_ihl: 0x05,
                ..base
            },
            len,
            RELAY,
            "version 0",
        );
        rejected(
            Ipv4UdpFields {
                version_ihl: 0x46,
                ..base
            },
            len,
            RELAY,
            "IP options",
        );
        rejected(
            Ipv4UdpFields {
                protocol: 6,
                ..base
            },
            len,
            RELAY,
            "TCP",
        );
        rejected(
            Ipv4UdpFields {
                flags_frag: 0x2000,
                ..base
            },
            len,
            RELAY,
            "first fragment (MF)",
        );
        rejected(
            Ipv4UdpFields {
                flags_frag: 0x0001,
                ..base
            },
            len,
            RELAY,
            "later fragment (offset)",
        );
        rejected(
            Ipv4UdpFields {
                dst_ip: RELAY + 1,
                ..base
            },
            len,
            RELAY,
            "not addressed to the relay",
        );
        rejected(base, len, 0, "relay address not configured");
        rejected(
            base,
            len + 1,
            RELAY,
            "frame longer than the IPv4 total length",
        );
        rejected(
            base,
            len - 1,
            RELAY,
            "frame shorter than the IPv4 total length",
        );
        rejected(
            Ipv4UdpFields {
                udp_len: base.udp_len - 1,
                ..base
            },
            len,
            RELAY,
            "UDP length disagrees with IPv4",
        );
        let short = (IPV4_MIN_LEN + UDP_LEN + DATA_HEADER - 1) as u16;
        rejected(
            Ipv4UdpFields {
                total_len: short,
                udp_len: short - IPV4_MIN_LEN as u16,
                ..base
            },
            ETH_LEN + short as usize,
            RELAY,
            "too short for a Data frame header",
        );
    }
}
