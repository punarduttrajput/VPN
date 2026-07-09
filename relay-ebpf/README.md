# `ferrum-relay-ebpf`

The relay's XDP fast path — see [PRD/phase-6-ebpf-xdp-relay.md](../PRD/phase-6-ebpf-xdp-relay.md)
for the design and [src/main.rs](src/main.rs) for the program itself.

**Status: built, verifier-accepted, and attached (2026-07-09).** On a real
Linux host (kernel 7.0, rustup nightly + the prebuilt `bpf-linker` v0.10.4
release binary), this program compiles clean, **passes the kernel eBPF
verifier**, and attaches through the production loader (`ferrum relay
--xdp-iface lo --xdp-program …` → `relay xdp fast path enabled`). Two real
bugs were found and fixed on that first load, both predicted by the "what
to check first" list below (details in `STATUS.md`'s 2026-07-09 entry): the
userspace loader dropped `aya-log`'s `EbpfLogger` before `BPF_PROG_LOAD`
(closing the `AYA_LOGS` map fd out from under the already-patched
instructions → EBADF before verification), and the verifier rejected
`checksum_update`'s `while`-carry-fold as "infinite loop detected" (now a
fixed two-fold). **Still remaining: live traffic through the fast path** —
XDP doesn't fire on loopback, so end-to-end forwarding, the
checksum-correctness capture (item 3 below), and the NFR1 benchmark (steps
2–4 under "Verify") still need two hosts or a netns+veth pair.
`src/main.rs` documents its own reasoning inline (byte-order convention,
checksum math, bounds-check placement) so that remaining pass can find and
fix anything wrong, rather than starting from nothing.

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
3. **The RFC 1624 incremental IPv4 checksum update — ⬜ still open.**
   Arithmetically unchanged by the two-fold fix, but still never run
   against a real packet (XDP doesn't fire on loopback). The check stands:
   capture a fast-pathed packet with `tcpdump`/Wireshark and confirm it
   reports a **valid** IPv4 checksum — Wireshark will flag a bad one
   immediately.

## Build

```sh
rustup toolchain install nightly --component rust-src
cargo install bpf-linker   # OR: grab the prebuilt static musl binary — see below
cd relay-ebpf
cargo +nightly build --release
# -> target/bpfel-unknown-none/release/ferrum-relay-ebpf
```

`cargo install bpf-linker` builds against `llvm-sys` and needs a matching
LLVM dev install; the path of least resistance (used for the first real
build, 2026-07-09) is the **prebuilt static binary** from
`https://github.com/aya-rs/bpf-linker/releases`
(`bpf-linker-x86_64-unknown-linux-musl.tar.zst` — statically linked, no
LLVM version matching), dropped into `~/.cargo/bin/` and `chmod +x`ed.

(`.cargo/config.toml` already pins the target and `build-std`;
`rust-toolchain.toml` pins nightly, so a plain `cargo build --release` from
inside this directory should pick both up without needing `+nightly`
explicitly — listed above for clarity in case a toolchain override elsewhere
interferes.)

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

1. `sudo bpftool prog show` — confirm the program loaded and is attached to
   the named interface.
2. Register two test clients against the relay and exchange a few `Data`
   frames (e.g. two short-lived `RelayMeshTransport` instances, or the
   existing `relay.rs` integration test's pattern against a real interface
   instead of loopback — XDP doesn't fire on loopback in most configs, so
   this specifically needs two real hosts or netns-with-veth).
3. Confirm packets stop reaching `RelayServer::serve`'s own `recv_from`
   loop for that flow once it's warm (add a temporary log line, or watch
   `ferrum_relay_frames_forwarded_total` stop incrementing for it) while
   the relay's new `ferrum_relay_xdp_frames_forwarded_total` /
   `ferrum_relay_xdp_bytes_forwarded_total` Prometheus counters climb (PRD
   FR4 — separate metric names, not a label on the existing ones).
4. Benchmark against the existing userspace relay (same two hosts, `--xdp-
   iface` unset vs. set) to validate the NFR1 target.
