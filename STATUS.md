# Phase 1 Implementation Status

**Phase:** 1 of 6 — MVP Encrypted Tunnel
**Spec:** [PRD/phase-1-mvp-tunnel.md](PRD/phase-1-mvp-tunnel.md)
**Started:** 2026-06-16
**Last updated:** 2026-06-16
**Build host:** Windows 11 (Rust 1.96.0)

> Note on platform: the PRD scopes the real TUN device to Linux/macOS. On this
> Windows build host the OS packet path cannot run, so the TUN device sits behind
> the `TunDevice` trait with a real impl (Unix, `real-tun` feature) and a mock for
> tests. All crypto / handshake / transport logic is platform-independent and is
> fully tested in-process here.

---

## Milestone Status

| ID | Milestone | Status | Notes |
|----|-----------|--------|-------|
| M1 | Workspace bootstrap — 3 crates compile | ✅ Done | `cargo build` clean; `core`, `tunnel`, `cli` |
| M2 | Key management — keygen, config parse/validate | ✅ Done | 12 unit tests; `vpn keygen` verified |
| M3 | TUN I/O — create/configure/teardown | 🟡 Impl + scripted | Real Unix device behind `real-tun` feature + trait + mock. Automated verification scripted in [scripts/verify-linux.sh](scripts/verify-linux.sh); run on a Linux host to close |
| M4 | Crypto session — boringtun handshake | ✅ Done | `handshake_and_packet_roundtrip` test passes |
| M5 | End-to-end — event loop, packet across tunnel | ✅ Done | `loopback` integration test (in-proc); real ping also scripted in verify-linux.sh |
| M6 | Benchmark — iperf3 throughput/latency | 🟡 Scripted | [scripts/verify-linux.sh](scripts/verify-linux.sh) runs iperf3 (NFR1) + latency (NFR2) via netns on one Linux box; run there to close |

Legend: ⬜ Not started · 🟡 In progress/partial · ✅ Done · ⚠️ Blocked/Deferred

---

## Test Results

`CARGO_NET_OFFLINE=false cargo test` — **18 passed, 0 failed**

| Suite | Tests | Result | Covers |
|-------|-------|--------|--------|
| `vpn-core` (keys) | 5 | ✅ | keygen, base64 roundtrip, public derivation, length/format rejection |
| `vpn-core` (config) | 7 | ✅ | TOML parse, CIDR (v4/v6), reject zero-port/bad-endpoint/bad-key/empty-allowed-ips |
| `vpn-tunnel` (session) | 4 | ✅ | handshake + encrypt/decrypt roundtrip, peer-restart re-handshake recovery (NFR5), mismatched-key rejection, base64 ctor |
| `vpn-tunnel` (device) | 1 | ✅ | mock TUN read/write |
| `loopback` (integration) | 1 | ✅ | full path: handshake → encapsulate → UDP → decapsulate → TUN write |

Other checks:
- `cargo clippy --all-targets` → **clean, no warnings**
- `vpn keygen` → emits valid base64 keypair
- `vpn up --config <malformed>` → clear error, **exit code 1** (FR4 fail-fast ✓)

---

## Acceptance Criteria (PRD §9)

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Two peers establish tunnel + exchange traffic | ✅ (in-proc) | `loopback` test; real `ping` scripted in verify-linux.sh |
| iperf3 meets NFR1/NFR2 | 🟡 Scripted | verify-linux.sh measures both; run on Linux to close |
| Peer restart re-handshakes | ✅ | `recovers_when_peer_restarts_and_rehandshakes` test passes (NFR5) |
| Malformed config → clear error, non-zero exit | ✅ | verified above |
| No keys/payloads in logs | ✅ | logs carry only metadata; payloads never formatted |
| clippy clean; `core` is `#![forbid(unsafe_code)]` | ✅ | clippy clean; forbid attribute in `crates/core/src/lib.rs` |

---

## To close on a Linux host (one command)

All remaining Linux-only checks are automated in
[scripts/verify-linux.sh](scripts/verify-linux.sh) — it runs both peers in network
namespaces on a single box (no second machine needed):

```sh
sudo ./scripts/verify-linux.sh   # needs root, iproute2, iperf3
```

It verifies, with PASS/FAIL output and a non-zero exit on failure:
- **M3** — real TUN `vpn0` comes up in each namespace; clean teardown on signal (FR1).
- **M5** — `ping` succeeds across the encrypted tunnel both directions.
- **M6/NFR1** — tunnel throughput ≥ 70% of underlay baseline (iperf3).
- **M6/NFR2** — added latency < 2 ms vs. baseline (ping).

> The re-handshake recovery requirement (NFR5) is now covered by an in-process
> unit test and no longer needs a host to verify.

---

## Artifacts

- Workspace: [Cargo.toml](Cargo.toml) · crates in [crates/](crates/)
- CLI binary: `target/debug/vpn` (`keygen`, `up`)
- Example config: [config.example.toml](config.example.toml)
- Overview: [README.md](README.md)

---

## Log

- 2026-06-16 — Status file created; beginning M1.
- 2026-06-16 — M1 done: workspace of 3 crates compiles.
- 2026-06-16 — M2 done: keys + config modules, 12 tests; `keygen` verified.
- 2026-06-16 — M4 done: boringtun session wrapper; handshake + roundtrip test green.
- 2026-06-16 — M5 done: async event loop + loopback integration test green (17/17 total).
- 2026-06-16 — M3 implemented behind `real-tun` feature (real run deferred to Unix).
- 2026-06-16 — clippy clean; README + example config added.
- 2026-06-16 — Added NFR5 peer-restart re-handshake test (18/18 tests green).
- 2026-06-16 — Added scripts/verify-linux.sh (netns-based M3/M5/M6 automation); syntax-checked.
- 2026-06-16 — Formatted workspace (rustfmt clean); added GitHub Actions CI (.github/workflows/ci.yml): tests on Linux+Windows every push, plus verify-linux.sh on a Linux runner.
- 2026-06-16 — First CI run: `test` (Linux+Windows) ✅; `verify-linux` 6/8 — M3, M5, NFR2 latency all PASS on a real Linux runner. Two issues found and fixed:
  - **Teardown false-failure** — the FR1 check used `pgrep -f "vpn up"` which matched its own shell command; replaced with a precise `kill -0` liveness test. Also added real SIGTERM handling in the CLI (was Ctrl-C/SIGINT only).
  - **Throughput gate** — compared the userspace tunnel (~417 Mbps) against a 27 Gbps in-kernel veth baseline and demanded 70%, which is not a fair target on shared CI. Fixed: eliminated a 64 KB per-packet heap allocation in the runner (real throughput bug); switched to a hard functional floor (≥100 Mbps) + multi-stream iperf3; NFR1's 70% ratio is now a hard gate only on real hardware (`STRICT_THROUGHPUT=1`), informational on CI. Real-hardware NFR1 validation remains the close-out for M6.
