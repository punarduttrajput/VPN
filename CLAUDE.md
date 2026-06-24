# CLAUDE.md — agent context for the Ferrum

Orientation for an AI agent (or developer) picking up this repo. Read this first,
then [STATUS.md](STATUS.md) for the detailed, dated progress log.

## What this is

A Rust, WireGuard-based VPN built to a **6-phase roadmap** (see [PRD/](PRD/)):
1. MVP encrypted tunnel · 2. Transport & obfuscation (QUIC/MASQUE) ·
3. Control plane (coordinator) · 4. Mesh & NAT traversal ·
5. Cross-platform clients · 6. Scale & acceleration.

The crypto/transport/control **core is mature**; the client apps, full NAT
traversal, and kernel-level scale work are the remaining frontier.

## Workspace (crates/)

| Crate | Role |
|-------|------|
| `ferrum-core` | Keys, config, errors. `#![forbid(unsafe_code)]`. |
| `ferrum-transport` | `Transport` (point-to-point) + `MeshTransport` (multi-peer) traits; UDP, QUIC (`quic`), MASQUE (`masque`) impls, padding + jitter decorators. |
| `ferrum-tunnel` | boringtun session wrapper, `TunDevice` trait (real on Unix behind `real-tun`, mock otherwise), point-to-point `run` and multi-peer `run_mesh`. |
| `ferrum-cli` | `ferrum` binary: `keygen`, `up` (point-to-point), `up-mesh` (coordinator mesh, runs on the supervised `FerrumClient` session → auto-reconnect), `relay`. |
| `ferrum-control-proto` | gRPC `Coordinator` contract (tonic/prost, vendored `protoc`). |
| `ferrum-coordinator` | Coordinator: registry, IP allocation, network map, ACL/policy, streaming, SQLite (`sqlite`), mTLS (`mtls`), OIDC (`oidc`). |
| `ferrum-client-core` | `ControlClient` (gRPC) + `FerrumClient` (Phase 5 facade: connection state machine + event stream). `uniffi` feature exposes `FfiFerrumClient` → generated Swift/Kotlin (incl. `run(tun_fd,…)`/`stop()` with `data-plane`). `data-plane` feature adds `run_mesh_session` (ties the facade to `ferrum-tunnel::run_mesh`; consumes a `device::from_fd` TUN). |

Outside `crates/`: **`apps/desktop`** is a Tauri v2 desktop shell (Phase 5 FR4) —
its own standalone workspace (excluded from this one) driving `ferrum-client-core`.

## Build / test / lint

```sh
cargo build --workspace
cargo test  --workspace                       # default features
cargo fmt --all -- --check                    # CI gate
cargo clippy --all-targets -- -D warnings     # CI gate
```

**Feature matrix** — CI runs clippy + tests for each; keep them all green:
```sh
cargo test  --workspace --features ferrum-cli/quic
cargo test  --workspace --features ferrum-cli/masque
cargo test  -p ferrum-coordinator --features sqlite
cargo test  -p ferrum-coordinator --features oidc
cargo test  -p ferrum-client-core -p ferrum-coordinator --features ferrum-coordinator/mtls,ferrum-client-core/mtls
cargo test  -p ferrum-client-core --features uniffi      # FFI Object + bindings (Phase 5)
cargo test  -p ferrum-client-core --features data-plane  # FerrumClient-driven mesh runner (Phase 5)
```
`uniffi` bindings (Swift/Kotlin) are generated from the built cdylib — see
[crates/client-core/bindings/README.md](crates/client-core/bindings/README.md).
Real-device/throughput checks live in [scripts/verify-linux.sh](scripts/verify-linux.sh)
(root + iproute2 + iperf3; runs both peers in netns). Opt-in env flags:
`TEST_QUIC=1`, `TEST_MESH=1`, `MESH_QUIC=1`, `STRICT_THROUGHPUT=1`.

## Conventions

- **Focused PRs.** One coherent change per branch/PR; keep them reviewable.
- **CI gates must pass:** `cargo fmt --all --check` and `cargo clippy --all-targets -- -D warnings`
  across the feature matrix above. Run them before pushing.
- Commit messages end with: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Don't commit/push to `main` directly; branch, PR, let the owner merge.
- rustfmt is **stable** (no toolchain pin); `cargo fmt --all` is the source of truth.

## ⚠️ Environment note — constraints differ per machine

Most of this codebase was written on an **offline Windows** host. Several
limitations there are **not fundamental** and should be **re-checked on a
Linux / online machine** — several "deferred / blocked" items may now be doable:

| Was blocked on offline-Windows | Re-check on the new box |
|---|---|
| **`cargo add <crate>`** — registry was offline-pinned (`--offline`). This forced workarounds (e.g. OIDC JWT verify hand-rolled on the in-tree `ring` instead of `jsonwebtoken`; no `uniffi`). | If cargo is online, new deps (`uniffi`, STUN/ICE crates, etc.) become available — Phase 5 bindings and more open up. |
| **Real TUN device** — Windows host can't run the OS packet path; tests use a mock and `verify-linux.sh` was run via Codespaces. | On Linux you can run the real data plane + `verify-linux.sh` locally (root). |
| **Real-hardware NFR1 throughput** — only informational on shared CI (~0.52 of a 1 Gbps shaped link vs 0.70 target). | Measure on real/representative hardware with `STRICT_THROUGHPUT=1`. |
| **Windows UDP gotcha** — sending to a dead port triggers ICMP-unreachable → `WSAECONNRESET` on the next `recv_from`, killing the loop (a test had to use a drained "sink" socket, not a blackhole). | Linux doesn't do this; the workaround is harmless but unnecessary there. |
| Live **third-party MASQUE proxy** interop — no external proxy available. | Test against a real RFC 9298 proxy if one is reachable. |

When you hit something marked "deferred because offline/Windows," **try it first**
on the new environment before assuming it's still blocked.

## Architecture decisions & non-obvious bits

- **Mesh routing is crypto-demux, not address-demux.** `run_mesh` routes an inbound
  datagram to whichever peer's WireGuard session *decrypts* it (not by source
  address), and **roams** that peer's endpoint to the observed source on a valid
  packet. This is what makes the mesh work through relays (MASQUE) and NAT. See
  `crates/tunnel/src/mesh.rs`.
- **`MeshTransport` trait** abstracts the mesh wire protocol: `UdpMeshTransport`,
  `QuicMeshTransport` (one quinn endpoint, per-peer connections, "hello" announces
  the dialer's advertised addr), `MasqueMeshTransport` (one CONNECT-UDP session per
  peer through a proxy). Selected by `[transport] mode` in config.
- **OIDC** (`ferrum-coordinator`, `oidc` feature): coordinator is a JWT *resource
  server* — verifies RS256/ES256 against a JWKS offline via `ring`, derives device
  tags from a verified claim (so ACL tags become an auth boundary). No external IdP
  needed to test.
- **TLS in QUIC/MASQUE** uses a self-signed cert with a permissive verifier on
  purpose: peer identity is the inner WireGuard handshake, not TLS (the TLS layer
  is for encryption/camouflage). See `crates/transport/src/quic.rs`.

## Completion snapshot (see STATUS.md for detail)

- **Phases 1–3:** functionally complete (tunnel; QUIC/MASQUE transports + QUIC
  connection migration + padding/timing-jitter obfuscation + batch I/O; full control
  plane with ACL/streaming/SQLite/mTLS/OIDC + static-key rotation). Phase 2's only
  open items are external-only (third-party MASQUE interop; nDPI DPI check).
- **Phase 4 (NAT traversal — ✅ functionally complete):** mesh data plane
  (UDP/QUIC/MASQUE) + crypto-demux + roaming, STUN client + coordinator candidate
  signaling + candidate gathering/publishing + candidate probing (M1/M2), a
  **DERP-style public-key-keyed relay** (`RelayServer` + `RelayMeshTransport`,
  runnable via `ferrum relay`; M3), the per-peer `idle→connecting→relay→direct`
  **state machine** (`tunnel::path`), its **automatic relay-fallback wiring with
  path upgrade/downgrade** (`run_mesh_relayed` runs direct + relay underlays at
  once; the `PathMachine` selects per peer; a peer comes up over the relay and
  upgrades to direct when punched), and the bring-up to use it — a local
  `transport.relay = "ip:port"` override *and* **coordinator-advertised relay**
  (`coordinator --relay <addr>` → `NetworkMapResponse.relay`; clients resolve
  local-override-else-advertised in `up-mesh` / `run_mesh_session` / the FFI).
  Remaining is hardening only: fuller ICE pairing/prioritization and a desktop-GUI
  relay/STUN field.
- **Phase 5 (~35%):** shared `FerrumClient` core (M1) + `uniffi` bindings (Swift/Kotlin
  generate from `FfiFerrumClient`) + data-plane glue (`run_mesh_session`) + the
  TUN-from-fd FFI entry (`device::from_fd` + `FfiFerrumClient::run`/`stop`) + a Tauri
  desktop shell (`apps/desktop`) whose **`connect` drives the real data plane on the
  always-on supervisor** (`run_mesh_session_supervised` with TUN/socket factories) + the
  **reliability core (FR5)**: `connect_with_retry` (exponential-backoff control-plane
  reconnect via the `Reconnecting` state, cancellable by `disconnect`), a kill-switch policy
  (`set_kill_switch`/`traffic_blocked` + a `TrafficBlocked` change event), and
  `data_plane::run_mesh_session_supervised` (reruns the whole mesh session with backoff
  on any drop, rebuilding device+transport via caller factories) — **adopted by both the
  CLI (`ferrum up-mesh`) and the desktop shell**, the latter also **enforcing the kill-switch
  in the OS firewall** (an `nftables` leak-block engaged on the `TrafficBlocked` signal,
  allow-listing loopback/tunnel/coordinator; Linux — see `apps/desktop/.../killswitch.rs`).
  Remaining: iOS/Android shells, a privileged-helper for the desktop TUN, and macOS/Windows
  kill-switch enforcement.
- **Phase 6 (~10%):** `sendmmsg` batching + **coordinator observability M1 started**
  (privacy-preserving Prometheus metrics on `--metrics-listen`'s `/metrics`: aggregate
  RPC counters + device/active-stream gauges, no per-user/flow labels — NFR5; hand-rolled,
  dependency-free). eBPF/XDP, anycast, autoscaling, relay metrics + tracing not started.

## Recommended next work (highest-value, buildable in Rust)

1. **Phase 5 — reliability (FR5)** ✅ *(core + CLI + desktop done)*: `connect_with_retry`
   (exponential-backoff control-plane reconnect) + a kill-switch policy (`set_kill_switch`/
   `traffic_blocked` + `TrafficBlocked` event) + `data_plane::run_mesh_session_supervised`
   (data-plane auto-restart with backoff via device/transport factories) land on the
   `FerrumClient` facade / data-plane glue and FFI; **both `ferrum up-mesh` and the Tauri
   desktop run on the supervisor** (always-on auto-reconnect; OIDC token via
   `FerrumClient::set_token`), and the **desktop enforces the kill-switch in the OS firewall**
   (`nftables`, Linux — `apps/desktop/.../killswitch.rs`). Remaining: macOS (`pf`)/Windows
   (WFP) kill-switch enforcement; a privileged-helper for the desktop TUN.
   (Phase 4 NAT traversal is functionally complete:
   signaling, STUN, relay, state machine, automatic fallback, and both local +
   coordinator-advertised relay selection all land. Optional Phase 4 hardening: fuller
   ICE candidate-pair prioritization; a desktop-GUI relay/STUN field.)
2. **Phase 5 — native shells**: iOS (NetworkExtension + SwiftUI) / Android
   (FerrumService + Compose) over the existing `uniffi` bindings (needs Apple/Android toolchains).
3. **Phase 6 — observability (M1, buildable here)** 🟡: coordinator Prometheus metrics
   land (`--metrics-listen` → `/metrics`, aggregate counts only per NFR5). Next: relay
   metrics (relay-vs-direct, forwarded packet counts) + `tracing`/OpenTelemetry spans.
4. **Phase 6 / NFR1**: real-hardware throughput; UDP GSO/GRO; eBPF/XDP fast path (Linux).
