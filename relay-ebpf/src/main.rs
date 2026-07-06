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
//! **This file is unbuilt and unverified on the host it was authored on** —
//! see the crate's `README.md` and the PRD's Risks section. It targets
//! `bpfel-unknown-none` via `aya-ebpf`, which needs a real Linux kernel to
//! load against (the eBPF verifier is not something you can satisfy by
//! inspection) and a `bpf-linker`+nightly toolchain to even produce the
//! `.o` this program compiles to.
//!
//! The `aya-ebpf = "0.2.1"` map/program API calls here (`#[map]`/`#[xdp]`,
//! `HashMap`/`Array`/`PerCpuArray`'s exact method signatures, `XdpContext`,
//! `xdp_action`) *were* checked against that version's actual downloaded
//! source rather than guessed — this crate's dependency itself doesn't need
//! a BPF toolchain to fetch, just to compile for the `bpfel-unknown-none`
//! target, so `cargo fetch` alone was enough to read the real API. What
//! remains genuinely unverified, and needs a real kernel to check, is
//! everything that source can't tell you: whether the eBPF **verifier**
//! accepts this program's control flow and bounds checks, and whether the
//! RFC 1624 incremental IPv4 checksum update is arithmetically correct
//! against a real packet (both flagged again at their own definitions
//! below).
#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray};
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::debug;
use ferrum_relay_xdp_common::{AddrKey, GatewayInfo, DATA_HEADER, KEY_LEN, TAG_DATA};

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

const ETH_LEN: usize = 14; // 6 (dst mac) + 6 (src mac) + 2 (ethertype)
const ETH_DST_OFF: usize = 0;
const ETH_SRC_OFF: usize = 6;
const ETH_TYPE_OFF: usize = 12;
const ETH_TYPE_IPV4: u16 = 0x0800;

const IPV4_VERSION_IHL_OFF: usize = 0; // relative to the IPv4 header's start
const IPV4_PROTO_OFF: usize = 9;
const IPV4_CHECKSUM_OFF: usize = 10;
const IPV4_SRC_OFF: usize = 12;
const IPV4_DST_OFF: usize = 16;
const IPV4_MIN_LEN: usize = 20; // no options — anything else falls through
const IPPROTO_UDP: u8 = 17;

const UDP_LEN: usize = 8; // relative offsets, within the UDP header
const UDP_SRC_PORT_OFF: usize = 0;
const UDP_DST_PORT_OFF: usize = 2;
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

/// RFC 1624 incremental checksum update. Every argument — and the result —
/// is a plain integer *value* (see the byte-order convention above), not
/// raw wire bytes: the caller reads the existing checksum and every changed
/// 16-bit word via `read_u16`/manual splitting first, and writes the result
/// back via `write_u16`.
///
/// `changed_words` is `(old_value, new_value)` pairs for every 16-bit word
/// that changed between the original and rewritten header (for an IPv4
/// address, that's its high and low 16 bits as two separate pairs).
fn checksum_update(old_checksum: u16, changed_words: &[(u16, u16)]) -> u16 {
    // Ones-complement arithmetic: start from the complement of the existing
    // checksum, remove each old word's contribution (by adding its
    // complement), add each new word's contribution, then fold the 32-bit
    // accumulator's carry back in until it fits 16 bits, and complement
    // once more for the final checksum. This is the textbook RFC 1624
    // "adjust for a changed field" formula, applied one word at a time.
    let mut sum: u32 = (!old_checksum) as u32;
    for &(old, new) in changed_words {
        sum += (!old) as u32;
        sum += new as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Split a 32-bit value into its high/low 16-bit words, in the order the
/// checksum needs them (matching how the two are laid out on the wire).
#[inline(always)]
fn words_of(v: u32) -> (u16, u16) {
    ((v >> 16) as u16, (v & 0xFFFF) as u16)
}

fn try_fastpath(ctx: &XdpContext) -> Result<u32, ()> {
    // --- Ethernet: must be IPv4, else PASS (covers ARP/IPv6/etc.) ---
    if read_u16(ctx, ETH_TYPE_OFF)? != ETH_TYPE_IPV4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // --- IPv4: must be UDP with no options, else PASS ---
    let ip_off = ETH_LEN;
    let ihl = read_u8(ctx, ip_off + IPV4_VERSION_IHL_OFF)? & 0x0F;
    let ip_hdr_len = (ihl as usize) * 4;
    if ip_hdr_len != IPV4_MIN_LEN {
        // Options present. Rare for this relay's own traffic and not worth
        // the extra bounds-check complexity in a first fast-path version.
        return Ok(xdp_action::XDP_PASS);
    }
    if read_u8(ctx, ip_off + IPV4_PROTO_OFF)? != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }
    let src_ip = read_u32(ctx, ip_off + IPV4_SRC_OFF)?;

    // --- UDP: must target the relay's configured listen port ---
    let udp_off = ip_off + ip_hdr_len;
    // `Array::get` is a safe call (checked against the real `aya-ebpf =
    // "0.2.1"` source — its signature is `fn get(&self, index: u32) ->
    // Option<&T>`, bounds-checked internally, no `unsafe` needed here).
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
    let src_addr = AddrKey {
        ip: src_ip,
        port: src_port,
    };
    // SAFETY (both lookups): `HashMap::get` is `unsafe fn` in the real
    // `aya-ebpf = "0.2.1"` source — not because the FFI call itself is
    // risky, but because the kernel doesn't guarantee `insert`/`remove`
    // atomicity, so a concurrently-removed entry could in principle alias
    // another; we only ever read the returned value by copy (`*...`)
    // immediately, never hold the reference across another map operation,
    // so that hazard doesn't apply here. Passing the keys by value (`Copy`
    // types) rather than by reference sidesteps any ambiguity in exactly
    // which `Borrow<K>` impl would apply.
    let sender_key = *unsafe { ADDR_TO_KEY.get(src_addr) }.ok_or(())?;
    let dest_addr = *unsafe { KEY_TO_ADDR.get(dst_key) }.ok_or(())?;
    // `Array::get` is safe — see the `RELAY_PORT` lookup above.
    let gw = GATEWAY.get(0).copied().ok_or(())?;
    if !gw.is_resolved() {
        return Err(());
    }

    // --- Rewrite in place: the frame's length never changes, so there's no
    // head/tail room adjustment to make — only field rewrites. ---

    // Ethernet: bounce back out toward the gateway, from this relay's MAC.
    write_bytes(ctx, ETH_DST_OFF, &gw.gateway_mac)?;
    write_bytes(ctx, ETH_SRC_OFF, &gw.relay_mac)?;

    // IPv4: src = this relay's own address, dst = the resolved
    // destination's address. Recompute the header checksum incrementally
    // (only these two 32-bit fields changed).
    let old_dst_ip = read_u32(ctx, ip_off + IPV4_DST_OFF)?;
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

    // UDP: src port unchanged (the relay always forwards from the one
    // listen port it's bound on, exactly like `RelayServer::serve`'s single
    // socket); dst port = the resolved destination's port. Checksum is
    // zeroed rather than recomputed — valid for IPv4 per RFC 768 §4, and
    // the same shortcut XDP-based L4 forwarders conventionally take.
    write_u16(ctx, udp_off + UDP_DST_PORT_OFF, dest_addr.port)?;
    write_u16(ctx, udp_off + UDP_CHECKSUM_OFF, 0)?;

    // Payload: overwrite the key field with the *sender's* key — this is
    // exactly `relay.rs`'s `data_frame(&src_key, payload)` rewrite.
    write_bytes(ctx, payload_off + 1, &sender_key)?;

    let frame_len = (ctx.data_end() - ctx.data()) as u64;
    note_fastpathed(frame_len);
    debug!(ctx, "relay xdp fast path: forwarded");
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
