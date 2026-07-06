# `ferrum-relay-ebpf`

The relay's XDP fast path — see [PRD/phase-6-ebpf-xdp-relay.md](../PRD/phase-6-ebpf-xdp-relay.md)
for the design and [src/main.rs](src/main.rs) for the program itself.

**Status: written, not yet built or run.** This was authored on a host with
no LLVM/clang, no `bpf-linker`, no `bpfel-unknown-none` Rust target, and no
Linux kernel to load against — so nothing in this directory has been
compiled, linked, loaded, or verified. `src/main.rs` documents its own
reasoning inline (byte-order convention, checksum math, bounds-check
placement) precisely so the steps below can find and fix anything wrong,
rather than starting from nothing.

This crate is its own standalone Cargo workspace (`[workspace]` in its
`Cargo.toml`, and listed in the repo root's `exclude`) — it is never touched
by `cargo build --workspace` from the repo root, on any host, so a missing
BPF toolchain here never breaks anything else in this repo.

## What to check first (the parts that couldn't be verified here)

1. **The `aya-ebpf`/`aya-log-ebpf` API surface — largely de-risked, but
   worth a glance.** `cargo fetch` (not a full build — that still needs the
   BPF toolchain) pulled the actual `aya-ebpf = "0.2.1"` source to this host,
   so the map/program call shapes here (`#[map]`/`#[xdp]`,
   `HashMap`/`Array`/`PerCpuArray`'s methods, `XdpContext`, `xdp_action`)
   were checked against real source, not guessed — including the discovery
   that this version's map types have **no `Pod`-style trait bound at all**
   (an earlier draft assumed one; `ferrum-relay-xdp-common` no longer has an
   `aya-ebpf`-side feature because of this). Still worth a first-compile
   pass in case a patch version changed something after this was written.
2. **The eBPF verifier.** Every packet field access is preceded by a
   `bounds_check` call for exactly this reason (`src/main.rs`'s doc comment
   on `bounds_check` explains why the check has to be inline, not
   factored out) — but whether the verifier's static analysis actually
   accepts the resulting bytecode can only be confirmed by loading it on a
   real kernel. If it rejects the program, `bpftool prog load` /
   `RUST_LOG=debug` on the loader (once written) will print exactly which
   instruction it rejected.
3. **The RFC 1624 incremental IPv4 checksum update** (`checksum_update` in
   `src/main.rs`). Worked through by hand in the design and cross-checked
   against the byte-order convention doc comment, but has never been run
   against a real packet. A quick sanity check: capture a fast-pathed
   packet with `tcpdump`/Wireshark and confirm it reports a **valid** IPv4
   checksum — Wireshark will flag a bad one immediately.

## Build

```sh
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cd relay-ebpf
cargo +nightly build --release
# -> target/bpfel-unknown-none/release/ferrum-relay-ebpf
```

(`.cargo/config.toml` already pins the target and `build-std`;
`rust-toolchain.toml` pins nightly, so a plain `cargo build --release` from
inside this directory should pick both up without needing `+nightly`
explicitly — listed above for clarity in case a toolchain override elsewhere
interferes.)

## Load and attach (once the userspace loader — `crates/transport/src/relay_xdp.rs`,
see the PRD — exists and is built with the `xdp` feature)

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
