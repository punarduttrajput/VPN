# CLAUDE.md — agent context for the Next-Gen VPN

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
| `vpn-core` | Keys, config, errors. `#![forbid(unsafe_code)]`. |
| `vpn-transport` | `Transport` (point-to-point) + `MeshTransport` (multi-peer) traits; UDP, QUIC (`quic`), MASQUE (`masque`) impls, padding + jitter decorators. |
| `vpn-tunnel` | boringtun session wrapper, `TunDevice` trait (real on Unix behind `real-tun`, mock otherwise), point-to-point `run` and multi-peer `run_mesh`. |
| `vpn-cli` | `vpn` binary: `keygen`, `up` (point-to-point), `up-mesh` (coordinator mesh). |
| `vpn-control-proto` | gRPC `Coordinator` contract (tonic/prost, vendored `protoc`). |
| `vpn-coordinator` | Coordinator: registry, IP allocation, network map, ACL/policy, streaming, SQLite (`sqlite`), mTLS (`mtls`), OIDC (`oidc`). |
| `vpn-client-core` | `ControlClient` (gRPC) + `VpnClient` (Phase 5 facade: connection state machine + event stream). `uniffi` feature exposes `FfiVpnClient` → generated Swift/Kotlin. |

## Build / test / lint

```sh
cargo build --workspace
cargo test  --workspace                       # default features
cargo fmt --all -- --check                    # CI gate
cargo clippy --all-targets -- -D warnings     # CI gate
```

**Feature matrix** — CI runs clippy + tests for each; keep them all green:
```sh
cargo test  --workspace --features vpn-cli/quic
cargo test  --workspace --features vpn-cli/masque
cargo test  -p vpn-coordinator --features sqlite
cargo test  -p vpn-coordinator --features oidc
cargo test  -p vpn-client-core -p vpn-coordinator --features vpn-coordinator/mtls,vpn-client-core/mtls
cargo test  -p vpn-client-core --features uniffi   # FFI Object + bindings (Phase 5)
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
- **OIDC** (`vpn-coordinator`, `oidc` feature): coordinator is a JWT *resource
  server* — verifies RS256/ES256 against a JWKS offline via `ring`, derives device
  tags from a verified claim (so ACL tags become an auth boundary). No external IdP
  needed to test.
- **TLS in QUIC/MASQUE** uses a self-signed cert with a permissive verifier on
  purpose: peer identity is the inner WireGuard handshake, not TLS (the TLS layer
  is for encryption/camouflage). See `crates/transport/src/quic.rs`.

## Completion snapshot (see STATUS.md for detail)

- **Phases 1–3:** functionally complete (tunnel; QUIC/MASQUE transports + migration
  + obfuscation + batch I/O; full control plane with ACL/streaming/SQLite/mTLS/OIDC).
- **Phase 4 (~25%):** mesh data plane (UDP/QUIC/MASQUE) + crypto-demux + roaming are
  built; **ICE/STUN/TURN, DERP-style relays, path upgrade/downgrade, and the per-peer
  connection state machine are not.**
- **Phase 5 (~15%):** shared `VpnClient` core (M1) + `uniffi` bindings (Swift/Kotlin
  generate from `FfiVpnClient`); no native shells, no reliability features yet.
- **Phase 6 (~5%):** only `sendmmsg` batching; eBPF/XDP, anycast, scale not started.

## Recommended next work (highest-value, buildable in Rust)

1. **Phase 4 — NAT traversal**: coordinator signaling for ICE candidate exchange
   (extend the gRPC streams), STUN client for server-reflexive candidates, a
   DERP-style relay keyed by public key, and the per-peer `idle→relay→connecting→
   direct` state machine with path upgrade/downgrade. All expressible in Rust.
2. **Phase 5 — data-plane glue**: a `VpnClient`-driven mesh runner that a native
   shell hands a TUN fd to (connect the facade to `run_mesh`).
3. **Phase 5 — `uniffi` bindings** (now that cargo may be online): annotate the
   `VpnClient` facade, generate Swift/Kotlin.
4. **Phase 6 / NFR1**: real-hardware throughput; UDP GSO/GRO; eBPF/XDP fast path (Linux).
