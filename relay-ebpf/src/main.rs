//! `ferrum-relay-ebpf` — the relay's XDP fast path (PRD:
//! `PRD/phase-6-ebpf-xdp-relay.md`, FR1).
//!
//! Runs on the NIC's receive path, before the kernel network stack. It
//! recognizes exactly one shape of packet — a Ferrum relay `Data` frame
//! (`crates/transport/src/relay.rs`'s wire protocol) for a flow the
//! userspace `RelayServer` has already told it about — and forwards it
//! in-kernel (`XDP_TX`) with no round trip through userspace at all.
//! Everything else (`Register` frames, IPv6, wrong port, malformed frames,
//! or a flow it hasn't been told about yet) is `XDP_PASS`ed through to the
//! existing userspace relay loop, unchanged.
//!
//! **Status: verified end-to-end with live traffic (2026-07-10)** — this
//! program builds (nightly + `bpf-linker`, `bpfel-unknown-none`), passes
//! the kernel eBPF verifier, attaches via the production loader, and
//! forwards real relay `Data` frames in-kernel with valid rewritten IPv4
//! checksums (netns+veth test bed; see the crate `README.md`'s "Verify"
//! section and STATUS.md's 2026-07-09/-10 entries). It was authored blind
//! on an offline-Windows host; getting from "compiles" to "forwards"
//! found five real bugs, each documented at the site of its fix (the
//! `checksum_update` fold, `AddrKey`'s padding via `AddrKey::new`, the
//! UDP src-port rewrite below, plus two loader-side bugs in
//! `relay_xdp.rs`).
//!
//! The `aya-ebpf = "0.2.1"` map/program API calls here (`#[map]`/`#[xdp]`,
//! `HashMap`/`Array`/`PerCpuArray`'s exact method signatures, `XdpContext`,
//! `xdp_action`) were checked against that version's actual downloaded
//! source rather than guessed, and held up on the first real build.
#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray};
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::debug;
use ferrum_relay_xdp_common::{
    checksum_update, fastpath_eligible, words_of, AddrKey, GatewayInfo, Ipv4UdpFields, ETH_LEN,
    IPV4_MIN_LEN, KEY_LEN, TAG_DATA, UDP_LEN,
};

/// Mirrors `Clients::by_addr` (`relay.rs`) — a sender's source address to
/// their public key, so a forwarded frame's rewritten payload can carry the
/// *sender's* key exactly like `RelayServer::serve`'s `data_frame(&src_key,
/// payload)` does today. Populated only by the userspace loader (PRD FR3) —
/// this program only ever reads it.
#[map]
static ADDR_TO_KEY: HashMap<AddrKey, [u8; KEY_LEN]> = HashMap::with_max_entries(4096, 0);

/// Mirrors `Clients::by_key` — a destination public key to its current
/// address. Same population rule as `ADDR_TO_KEY`.
#[map]
static KEY_TO_ADDR: HashMap<[u8; KEY_LEN], AddrKey> = HashMap::with_max_entries(4096, 0);

/// This relay's own identity + its default gateway's MAC (PRD FR2) — one
/// entry, refreshed periodically by the userspace loader. All-zero (the
/// map's initial state) means "not resolved yet," which this program
/// treats as an automatic fast-path miss.
#[map]
static GATEWAY: Array<GatewayInfo> = Array::with_max_entries(1, 0);

/// The relay's own UDP listen port, set once by the loader from `--listen`.
/// Zero (the map's initial state) means "not configured yet" — never a
/// legitimate port for the relay itself to listen on, so it doubles as an
/// "unconfigured" sentinel with no extra state needed.
#[map]
static RELAY_PORT: Array<u16> = Array::with_max_entries(1, 0);

/// Fast-pathed frame/byte counters (PRD FR4) — index 0 = frames, index 1 =
/// bytes, one slot per CPU (the loader sums across CPUs before merging into
/// `RelayMetrics`). Aggregate-only; no per-flow data ever lands here (NFR5).
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);
const STAT_FRAMES: u32 = 0;
const STAT_BYTES: u32 = 1;

#[xdp]
pub fn ferrum_relay_fastpath(ctx: XdpContext) -> u32 {
    match try_fastpath(&ctx) {
        Ok(action) => action,
        // Anything that doesn't fit the fast path — or any bounds check
        // that fails along the way — always falls back to userspace. There
        // is no "drop" outcome in this program (PRD NFR3): only PASS or a
        // successful TX, mirroring the *fail-open* requirement in the PRD.
        Err(()) => xdp_action::XDP_PASS,
    }
}

// --- Wire layout (hand-rolled, not a header-struct crate, so every byte
// this program touches — and the bounds check that must precede it for the
// verifier — is explicit here rather than hidden behind a dependency's
// field accessors). Ethernet II (RFC 894), IPv4 with no options (RFC 791),
// UDP (RFC 768).

// ETH_LEN, IPV4_MIN_LEN, UDP_LEN and the eligibility rules live in
// ferrum-relay-xdp-common, where they're unit-tested (SEC-018).
const ETH_DST_OFF: usize = 0;
const ETH_SRC_OFF: usize = 6;
const ETH_TYPE_OFF: usize = 12;
const ETH_TYPE_IPV4: u16 = 0x0800;

const IPV4_VERSION_IHL_OFF: usize = 0; // relative to the IPv4 header's start
const IPV4_TOTAL_LEN_OFF: usize = 2;
const IPV4_FLAGS_FRAG_OFF: usize = 6;
const IPV4_PROTO_OFF: usize = 9;
const IPV4_CHECKSUM_OFF: usize = 10;
const IPV4_SRC_OFF: usize = 12;
const IPV4_DST_OFF: usize = 16;

// Relative offsets, within the UDP header.
const UDP_SRC_PORT_OFF: usize = 0;
const UDP_DST_PORT_OFF: usize = 2;
const UDP_LEN_OFF: usize = 4;
const UDP_CHECKSUM_OFF: usize = 6;

/// Bounds-checked read of `size_of::<T>()` bytes at `offset` from the start
/// of the packet. This is the pattern the eBPF verifier requires: it can
/// only prove a memory access safe if it can see a preceding comparison
/// against `ctx.data_end()` that dominates the access — so this check has
/// to happen right here, inline, immediately before the read, not
/// factored out in a way the verifier's static analysis can't follow.
#[inline(always)]
fn bounds_check(ctx: &XdpContext, offset: usize, len: usize) -> Result<usize, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + len > end {
        return Err(());
    }
    Ok(start + offset)
}

#[inline(always)]
fn read_u8(ctx: &XdpContext, offset: usize) -> Result<u8, ()> {
    let ptr = bounds_check(ctx, offset, 1)? as *const u8;
    // SAFETY: `bounds_check` just proved `[ptr, ptr+1)` is within the
    // packet's own data pages.
    Ok(unsafe { *ptr })
}

/// Read a big-endian 16-bit field as a plain value (see
/// `ferrum-relay-xdp-common`'s byte-order convention doc comment — the same
/// convention is used here).
#[inline(always)]
fn read_u16(ctx: &XdpContext, offset: usize) -> Result<u16, ()> {
    let ptr = bounds_check(ctx, offset, 2)? as *const [u8; 2];
    // SAFETY: see `read_u8`.
    Ok(u16::from_be_bytes(unsafe { *ptr }))
}

/// Read a big-endian 32-bit field as a plain value.
#[inline(always)]
fn read_u32(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    let ptr = bounds_check(ctx, offset, 4)? as *const [u8; 4];
    // SAFETY: see `read_u8`.
    Ok(u32::from_be_bytes(unsafe { *ptr }))
}

/// Overwrite `bytes.len()` bytes at `offset` — used both for raw byte
/// arrays (MAC addresses, the 32-byte key field) and, by the `write_u16`/
/// `write_u32` helpers below, for already-`to_be_bytes()`-converted values.
#[inline(always)]
fn write_bytes(ctx: &XdpContext, offset: usize, bytes: &[u8]) -> Result<(), ()> {
    let ptr = bounds_check(ctx, offset, bytes.len())? as *mut u8;
    // SAFETY: `bounds_check` just proved the destination range is within
    // the packet's own (writable) data pages; `bytes` is a distinct,
    // non-overlapping source.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()) };
    Ok(())
}

#[inline(always)]
fn write_u16(ctx: &XdpContext, offset: usize, value: u16) -> Result<(), ()> {
    write_bytes(ctx, offset, &value.to_be_bytes())
}

#[inline(always)]
fn write_u32(ctx: &XdpContext, offset: usize, value: u32) -> Result<(), ()> {
    write_bytes(ctx, offset, &value.to_be_bytes())
}

// `checksum_update` and `words_of` are in ferrum-relay-xdp-common, unit-tested
// there against a full checksum recomputation (SEC-018).

fn try_fastpath(ctx: &XdpContext) -> Result<u32, ()> {
    // --- Ethernet: must be IPv4, else PASS (covers ARP/IPv6/etc.) ---
    if read_u16(ctx, ETH_TYPE_OFF)? != ETH_TYPE_IPV4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // --- IPv4 + UDP: eligible shape, addressed to this relay, else PASS ---
    // SEC-018: version nibble, no options, UDP, not a fragment, destination
    // is the relay itself, and IPv4/UDP lengths that agree with the frame
    // (`fastpath_eligible`, unit-tested in ferrum-relay-xdp-common). The
    // gateway entry carries the relay's own address, so it's read first; an
    // unresolved entry is a silent miss (no log: this runs for every IPv4
    // packet on the interface, not just relay traffic).
    let ip_off = ETH_LEN;
    let udp_off = ip_off + IPV4_MIN_LEN;
    // `Array::get` is a safe call (checked against the real `aya-ebpf =
    // "0.2.1"` source — `fn get(&self, index: u32) -> Option<&T>`).
    let gw = GATEWAY.get(0).copied().ok_or(())?;
    if !gw.is_resolved() {
        return Ok(xdp_action::XDP_PASS);
    }
    let fields = Ipv4UdpFields {
        version_ihl: read_u8(ctx, ip_off + IPV4_VERSION_IHL_OFF)?,
        total_len: read_u16(ctx, ip_off + IPV4_TOTAL_LEN_OFF)?,
        flags_frag: read_u16(ctx, ip_off + IPV4_FLAGS_FRAG_OFF)?,
        protocol: read_u8(ctx, ip_off + IPV4_PROTO_OFF)?,
        dst_ip: read_u32(ctx, ip_off + IPV4_DST_OFF)?,
        udp_len: read_u16(ctx, udp_off + UDP_LEN_OFF)?,
    };
    let frame_len = ctx.data_end() - ctx.data();
    if !fastpath_eligible(&fields, frame_len, gw.relay_ip) {
        return Ok(xdp_action::XDP_PASS);
    }
    let src_ip = read_u32(ctx, ip_off + IPV4_SRC_OFF)?;

    // --- UDP: must target the relay's configured listen port ---
    let relay_port = RELAY_PORT.get(0).copied().unwrap_or(0);
    if relay_port == 0 {
        // Loader hasn't configured the port yet — always miss until it has.
        return Ok(xdp_action::XDP_PASS);
    }
    if read_u16(ctx, udp_off + UDP_DST_PORT_OFF)? != relay_port {
        return Ok(xdp_action::XDP_PASS);
    }
    let src_port = read_u16(ctx, udp_off + UDP_SRC_PORT_OFF)?;

    // --- Relay frame: must be a Data frame (tag 0x02) with a full key ---
    let payload_off = udp_off + UDP_LEN;
    if read_u8(ctx, payload_off)? != TAG_DATA {
        // `Register` frames (and anything malformed) always fall through —
        // registration stays exclusively a userspace decision (PRD FR3).
        return Ok(xdp_action::XDP_PASS);
    }
    // Bounds-check the full key field up front (one check covering all 32
    // bytes) rather than byte-by-byte in the copy loop below.
    let key_start = bounds_check(ctx, payload_off + 1, KEY_LEN)?;
    let mut dst_key = [0u8; KEY_LEN];
    // SAFETY: `key_start` was just proven to have `KEY_LEN` readable bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(key_start as *const u8, dst_key.as_mut_ptr(), KEY_LEN)
    };

    // --- Two map lookups, mirroring `Clients` exactly (PRD FR1) ---
    // `AddrKey::new` zeroes the struct's explicit padding — a BPF hash map
    // compares keys byte-wise over the full `key_size`, so every byte must
    // be deterministic on both sides. (The first live-traffic run,
    // 2026-07-09, missed 100% of lookups on exactly this: the old struct
    // had *implicit* padding, undefined on both the BPF stack and the
    // userspace mirror.)
    let src_addr = AddrKey::new(src_ip, src_port);
    // SAFETY (both lookups): `HashMap::get` is `unsafe fn` in the real
    // `aya-ebpf = "0.2.1"` source — not because the FFI call itself is
    // risky, but because the kernel doesn't guarantee `insert`/`remove`
    // atomicity, so a concurrently-removed entry could in principle alias
    // another; we only ever read the returned value by copy (`*...`)
    // immediately, never hold the reference across another map operation,
    // so that hazard doesn't apply here. Passing the keys by value (`Copy`
    // types) rather than by reference sidesteps any ambiguity in exactly
    // which `Borrow<K>` impl would apply.
    //
    // The misses below are `debug!`-logged rather than silent: they only
    // fire for Data frames already on the relay's own port (never for
    // unrelated traffic), and they're exactly the signal needed to
    // distinguish "fast path not matching" from "no traffic" during
    // bring-up. The success path deliberately has NO per-packet log — at
    // line rate a ring-buffer write per forwarded frame is real overhead,
    // and the `STATS` counters already tell that story.
    let Some(sender_key) = (unsafe { ADDR_TO_KEY.get(src_addr) }).copied() else {
        debug!(
            ctx,
            "relay xdp: data frame, addr_to_key miss (unregistered sender)"
        );
        return Ok(xdp_action::XDP_PASS);
    };
    let Some(dest_addr) = (unsafe { KEY_TO_ADDR.get(dst_key) }).copied() else {
        debug!(
            ctx,
            "relay xdp: data frame, key_to_addr miss (unknown destination)"
        );
        return Ok(xdp_action::XDP_PASS);
    };

    // --- Rewrite in place: the frame's length never changes, so there's no
    // head/tail room adjustment to make — only field rewrites. ---

    // Ethernet: bounce back out toward the gateway, from this relay's MAC.
    write_bytes(ctx, ETH_DST_OFF, &gw.gateway_mac)?;
    write_bytes(ctx, ETH_SRC_OFF, &gw.relay_mac)?;

    // IPv4: src = this relay's own address, dst = the resolved
    // destination's address. Recompute the header checksum incrementally
    // (only these two 32-bit fields changed).
    let old_dst_ip = fields.dst_ip;
    let old_checksum = read_u16(ctx, ip_off + IPV4_CHECKSUM_OFF)?;
    write_u32(ctx, ip_off + IPV4_SRC_OFF, gw.relay_ip)?;
    write_u32(ctx, ip_off + IPV4_DST_OFF, dest_addr.ip)?;
    let (old_src_hi, old_src_lo) = words_of(src_ip);
    let (new_src_hi, new_src_lo) = words_of(gw.relay_ip);
    let (old_dst_hi, old_dst_lo) = words_of(old_dst_ip);
    let (new_dst_hi, new_dst_lo) = words_of(dest_addr.ip);
    let new_checksum = checksum_update(
        old_checksum,
        &[
            (old_src_hi, new_src_hi),
            (old_src_lo, new_src_lo),
            (old_dst_hi, new_dst_hi),
            (old_dst_lo, new_dst_lo),
        ],
    );
    write_u16(ctx, ip_off + IPV4_CHECKSUM_OFF, new_checksum)?;

    // UDP: src port ← the relay's own listen port. This must be an
    // explicit REWRITE: the inbound packet's source port is the *sending
    // client's* ephemeral port, and a forwarded frame has to look exactly
    // like `RelayServer::serve`'s single bound socket sent it — clients
    // (`RelayMeshTransport::recv_from`) drop anything not from precisely
    // `relay_ip:relay_port`. (The PRD's FR1 text called this field
    // "unchanged", reasoning from the relay's *outbound* perspective —
    // wrong for an in-place rewrite of the inbound packet; caught live
    // 2026-07-09: every fast-pathed frame arrived from the sender's port
    // and was filtered out by the receiving client.) Dst port = the
    // resolved destination's port. Checksum is zeroed rather than
    // recomputed — valid for IPv4 per RFC 768 §4, and the same shortcut
    // XDP-based L4 forwarders conventionally take.
    write_u16(ctx, udp_off + UDP_SRC_PORT_OFF, relay_port)?;
    write_u16(ctx, udp_off + UDP_DST_PORT_OFF, dest_addr.port)?;
    write_u16(ctx, udp_off + UDP_CHECKSUM_OFF, 0)?;

    // Payload: overwrite the key field with the *sender's* key — this is
    // exactly `relay.rs`'s `data_frame(&src_key, payload)` rewrite.
    write_bytes(ctx, payload_off + 1, &sender_key)?;

    note_fastpathed(frame_len as u64);
    // No per-packet success log — see the lookup comment above; the STATS
    // counters are the observable.
    Ok(xdp_action::XDP_TX)
}

#[inline(always)]
fn note_fastpathed(frame_len: u64) {
    // `PerCpuArray::get_ptr_mut` itself is a safe call (each CPU has its own
    // slot, so there's no concurrent-write race for it to guard against);
    // only dereferencing the raw pointer it returns is `unsafe`.
    if let Some(frames) = STATS.get_ptr_mut(STAT_FRAMES) {
        unsafe { *frames += 1 };
    }
    if let Some(bytes) = STATS.get_ptr_mut(STAT_BYTES) {
        unsafe { *bytes += frame_len };
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // eBPF programs can never actually unwind or abort at runtime — the
    // verifier rejects any path that could reach a real panic before the
    // program is even loaded — so this only needs to satisfy the compiler.
    loop {}
}
