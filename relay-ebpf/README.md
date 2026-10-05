# `ferrum-relay-ebpf`

The relay's XDP fast path — see [PRD/phase-6-ebpf-xdp-relay.md](../PRD/phase-6-ebpf-xdp-relay.md)
for the design and [src/main.rs](src/main.rs) for the program itself.

**Status: verified end-to-end with live traffic (2026-07-10).** On a real
Linux host (kernel 7.0, rustup nightly + the prebuilt `bpf-linker` v0.10.4
release binary), this program compiles clean, **passes the kernel eBPF
verifier**, attaches through the production loader (`ferrum relay
--xdp-iface … --xdp-program …` → `relay xdp fast path enabled`), and
**forwards live relay `Data` frames entirely in-kernel** on a netns+veth
test bed: 2000/2000 frames delivered client→client with
`ferrum_relay_xdp_frames_forwarded_total` = 2000 and the userspace
`frames_forwarded_total` staying at **0**, every fast-pathed packet
carrying a **valid IPv4 header checksum** in a tcpdump capture (the RFC
1624 incremental update confirmed against real packets), and 99.97%
delivery under a ~1 Gbps flood vs the userspace relay's 92.6% (see the
"Verified" section below and `STATUS.md`'s 2026-07-09/-10 entries).

Getting there took **five real bugs across two passes**, all in the
categories the "what to check first" list below predicted: the first
load found the loader's `EbpfLogger` drop (EBADF before `BPF_PROG_LOAD`)
and the verifier-rejected `while`-carry-fold in `checksum_update` (now a
fixed two-fold); live traffic then found `AddrKey`'s **implicit `repr(C)`
padding** (BPF map keys compare byte-wise; undefined padding ⇒ 100%
lookup miss), a **tokio-mutex deadlock** in the loader's stats poll (a
match-scrutinee `MutexGuard` outliving into a second `lock().await`), and
a **missing UDP source-port rewrite** (the inbound packet's src port is
the *sender's* ephemeral port, not the relay's — clients drop frames not
from exactly `relay_ip:relay_port`). `src/main.rs` documents its own
reasoning inline (byte-order convention, checksum math, bounds-check
placement, and each of those fixes at the site it lives).

**Still open for FR1/NFR1:** the ≥10 Gbps benchmark. The veth number
above is a *functional* comparison — generic (SKB) mode on a veth pair
with a single-socket sender saturates around 1 Gbps offered. The line-rate
claim needs real hardware, native (driver) XDP mode, and a multi-queue
sender.

This crate is its own standalone Cargo workspace (`[workspace]` in its
`Cargo.toml`, and listed in the repo root's `exclude`) — it is never touched
by `cargo build --workspace` from the repo root, on any host, so a missing
BPF toolchain here never breaks anything else in this repo.

## What to check first — outcomes from the first real build/load (2026-07-09)

1. **The `aya-ebpf`/`aya-log-ebpf` API surface — ✅ held up exactly.** The
   `cargo fetch`-based source check (map/program call shapes, the discovery
   that this version's map types have no `Pod`-style trait bound) proved
   accurate: the crate compiled on the **first attempt**, with a single
   unused-import warning as the only diagnostic. Now also clippy- and
   fmt-clean.
2. **The eBPF verifier — ❌ one real rejection, now fixed.** The bounds
   checks themselves all passed (every packet access was accepted), but the
   verifier rejected `checksum_update`'s `while (sum >> 16) != 0` carry
   fold with "infinite loop detected at insn 447": its interval analysis
   can't prove the carry stops regenerating. Fixed as a **fixed two-fold**
   (sufficient for this accumulator's bound — see the comment at the
   function). Note `bpftool prog load` can NOT be used for this check:
   libbpf v1.0+ rejects aya's legacy `maps` ELF section before the verifier
   ever runs ("legacy map definitions in 'maps' section are not
   supported") — load through the production loader (`ferrum relay
   --xdp-iface lo --xdp-program …`, needs the `xdp` feature + root) and
   watch for `relay xdp fast path enabled`. That first load also flushed
   out a **userspace loader bug**: `relay_xdp.rs` dropped `aya-log`'s
   `EbpfLogger` immediately after init (its `Ok` was discarded), closing
   the `AYA_LOGS` map fd that was already patched into the program's
   instructions — `BPF_PROG_LOAD` then failed with EBADF ("fd N is not
   pointing to valid bpf_map") before verification. The logger is now
   initialized *after* `program.load()` and kept alive in a spawned
   flush task.
3. **The RFC 1624 incremental IPv4 checksum update — ✅ verified live
   (2026-07-10).** A tcpdump capture on the far side of the veth showed
   all 2000 fast-pathed packets with a valid IPv4 header checksum
   (validated word-sum == 0xFFFF per packet), UDP checksum zeroed as
   designed, and the key field rewritten to the sender's key.

## What live traffic found that attach-only couldn't (2026-07-10)

The netns+veth pass (see "Verify" below for the recipe) found three more
real bugs, none of which the verifier or a loopback attach could surface —
worth knowing about for any future map or rewrite change:

4. **BPF hash-map keys must have zero implicit padding.** `AddrKey` was
   `#[repr(C)] { ip: u32, port: u16 }` — size 8 with two *implicit*
   trailing padding bytes. The kernel compares map keys byte-wise over the
   full `key_size`, and Rust leaves implicit padding undefined on both the
   BPF stack and in userspace's `Pod` byte-copy — so every `ADDR_TO_KEY`
   lookup missed and 100% of traffic silently fell through to userspace
   (fail-open masking the bug; only the flat XDP counters gave it away).
   Fix: an explicit always-zero `_pad: [u8; 2]` field with `AddrKey::new`
   as the only constructor, pinned by a `size_of == 8` unit test in
   `ferrum-relay-xdp-common`.
5. **The loader's stats poll deadlocked on its first tick** —
   `match self.stats.lock().await.get(..)` keeps the `MutexGuard` (a match-
   scrutinee temporary) alive across a second `lock().await` of the same
   tokio mutex inside the arm. Kernel counters climbed; `/metrics` stayed
   at 0 forever, with no error logged. Fix in `relay_xdp.rs`: take the
   lock once for both index reads in a scoped block.
6. **The UDP source port must be explicitly rewritten to the relay's
   port.** The original code (and the PRD's FR1 text) called it
   "unchanged," reasoning from the relay's outbound socket — but in an
   in-place rewrite of the *inbound* packet, that field holds the sending
   client's ephemeral port. `RelayMeshTransport::recv_from` drops anything
   not from exactly `relay_ip:relay_port`, so every fast-pathed frame was
   delivered and then filtered out client-side. Diagnosed byte-for-byte
   with `relay_traffic`'s `rawdump` mode after `/proc/net/snmp` showed the
   frames *were* reaching a socket.

## Build

```sh
bash ../scripts/install-bpf-linker.sh   # pinned prebuilt, digest-verified — see below
cd relay-ebpf
cargo build --release   # rust-toolchain.toml pins nightly-2026-07-09 (rustup installs it)
# -> target/bpfel-unknown-none/release/ferrum-relay-ebpf
```

Don't pass `+nightly`: an explicit toolchain overrides `rust-toolchain.toml`
and would pick today's nightly instead of the pinned one.

`bpf-linker` produces the kernel XDP object, so it is **pinned** (SEC-008).
[`scripts/install-bpf-linker.sh`](../scripts/install-bpf-linker.sh) downloads
the prebuilt static musl binary from the aya-rs release and checks its SHA-256
*before* extracting it into `~/.cargo/bin/` (`--dest DIR` to override). It is
statically linked, so no system LLVM install is needed; this is the path used
for the first real build, 2026-07-09.

**Its LLVM must match rustc's.** bpf-linker reads the LLVM bitcode rustc emits,
and v0.10.4 is built against **LLVM 22**. A nightly on a newer LLVM major (23
since the 1.99 cycle) produces bitcode it can't read. That's why
`rust-toolchain.toml` pins `nightly-2026-07-09` (rustc 1.99.0-nightly
`14cae6813`, LLVM 22.1.8) rather than floating `nightly`. Check with
`rustc -vV` inside this directory. Move the pin and bpf-linker together.

| Field | Value |
|-------|-------|
| Version | `v0.10.4` |
| Source | <https://github.com/aya-rs/bpf-linker/releases/tag/v0.10.4> |
| `bpf-linker-x86_64-unknown-linux-musl.tar.zst` SHA-256 | `4dda77daab6c5f120a468e6d3ede2498f5bd47ece712172cfb7290176d93d015` |
| `bpf-linker-aarch64-unknown-linux-musl.tar.zst` SHA-256 | `c3638cd3cb735ff85705905a07e0df61c0f9426480334c8e2efe5cb92fd9d3de` |
| Upstream signature | none published (no signature or GitHub build attestation), so the digest is the trust anchor |

The digests come from GitHub's release-asset metadata. The x86_64 one was
confirmed against an independent download on 2026-09-29, and CI re-checks it on
every run. `cargo install bpf-linker` (built from source against `llvm-sys`,
which needs a matching LLVM dev install) still works if you'd rather not use a
prebuilt binary.

(`.cargo/config.toml` pins the target and `build-std`; `rust-toolchain.toml`
pins the dated nightly. A plain `cargo build --release` from inside this
directory picks up both.)

## Load and attach (via the userspace loader — `crates/transport/src/relay_xdp.rs`,
built with the `xdp` feature: `cargo build -p ferrum-cli --features xdp`)

```sh
sudo ferrum relay --listen 0.0.0.0:51821 \
  --xdp-iface eth0 \
  --xdp-program relay-ebpf/target/bpfel-unknown-none/release/ferrum-relay-ebpf
```

Generic (SKB) XDP mode is the default the loader should request — broadly
compatible across drivers/kernels, at some cost vs. native/driver mode
(a deployment-time tuning choice, not a code difference — see the PRD's
Risks section).

## Verify

Steps 1–3 were **done live on 2026-07-10** with the netns+veth recipe
below; step 4's real-hardware half is the remaining open item.

1. `sudo bpftool prog show` — confirm the program loaded and is attached to
   the named interface. (`bpftool map dump name STATS` is also the
   ground-truth read of the fast-path counters, bypassing the loader.)
2. Register two test clients against the relay and exchange `Data` frames.
   The committed harness for this is
   `crates/transport/examples/relay_traffic.rs` (two fixed-key roles over
   `RelayMeshTransport`; `recv`/`send` verify modes, `bench-recv`/
   `bench-send` flood modes, and a `rawdump` mode that prints every raw
   datagram byte-for-byte — the tool that found the src-port bug). XDP
   doesn't fire on loopback, so this needs two hosts or netns+veth; the
   recipe that works (both clients in the root netns, relay + XDP inside a
   netns):

   ```sh
   ip netns add frxdp
   ip link add veth-host type veth peer name veth-relay
   ip link set veth-relay netns frxdp
   ip addr add 10.99.0.1/24 dev veth-host && ip link set veth-host up
   ip netns exec frxdp ip addr add 10.99.0.2/24 dev veth-relay
   ip netns exec frxdp ip link set veth-relay up
   ip netns exec frxdp ip route add default via 10.99.0.1   # FR2 gateway
   ethtool -K veth-host tx off rx off gso off gro off       # real checksums
   ip netns exec frxdp ethtool -K veth-relay tx off rx off gso off gro off
   ip netns exec frxdp ping -c1 10.99.0.1                   # warm ARP
   ip netns exec frxdp ferrum relay --listen 0.0.0.0:51821 \
     --metrics-listen 10.99.0.2:9101 \
     --xdp-iface veth-relay --xdp-program target/bpfel-unknown-none/release/ferrum-relay-ebpf &
   relay_traffic 10.99.0.2:51821 b recv 2000 30 &   # root netns, unprivileged
   relay_traffic 10.99.0.2:51821 a send 2000 1400 5000
   ```

   Note that tcpdump **inside** the netns on `veth-relay` will *not* show
   fast-pathed frames — generic XDP consumes them before the tap — while a
   capture on `veth-host` shows the rewritten packets. That asymmetry is
   itself a useful "the fast path is on" signal.
3. Confirm packets stop reaching `RelayServer::serve`'s own `recv_from`
   loop once the maps are warm: `ferrum_relay_frames_forwarded_total`
   stays flat (measured: exactly 0) while
   `ferrum_relay_xdp_frames_forwarded_total` /
   `ferrum_relay_xdp_bytes_forwarded_total` climb (PRD FR4 — separate
   metric names, not a label on the existing ones). Capture on the far
   veth end and check the IPv4 checksums validate (done — all 2000 valid;
   Wireshark/`tcpdump -v` flags a bad one immediately).
4. Benchmark against the existing userspace relay. **Measured on this bed**
   (generic mode, single-socket sender — a functional comparison only):
   at ~1.04 Gbps offered / 1400-byte payloads, the XDP path delivered
   99.97% (1039 Mbps, ~92.8k pps) with the relay process forwarding zero
   packets in userspace, vs the userspace relay's 92.6% (971 Mbps — 7.4%
   socket-overrun loss). **The ≥10 Gbps NFR1 claim remains open**: it
   needs real hardware, native (driver) XDP mode, and a multi-queue
   line-rate sender.
