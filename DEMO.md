# Ferrum — Demo & Client Handover Guide

_Generated for a live client walkthrough. Covers: how to run everything, how to
talk to the control-plane API, what's built, what's different from a "finished"
product, and what's coming next. See `CLAUDE.md`/`STATUS.md` for the full
engineering log this is condensed from._

## 30-second pitch

Ferrum is a Rust, WireGuard-based VPN: an encrypted point-to-point tunnel,
pluggable transports (UDP / QUIC / MASQUE obfuscation), a gRPC **control-plane
coordinator** (device registry, IP allocation, ACL policy, live network-map
push), a multi-peer **mesh** data plane with NAT traversal (STUN + a DERP-style
relay fallback), cross-platform clients (desktop for Windows/Linux, Android),
and a metrics/tracing/alerting stack. Built to a 6-phase roadmap; phases 1–4 are
functionally complete, phase 5 (clients) is ~95%, phase 6 (scale/observability)
is ~15% with the observability half done.

---

## 1. Running things for the demo

All commands from the repo root unless noted. First build (or if the cargo
cache is cold):
```sh
cargo build --workspace --config net.offline=false   # override the global offline pin once
```

### A. Simplest demo — two-peer tunnel, no coordinator (Phase 1)

```sh
cargo run -p ferrum-cli -- keygen        # run once per peer, note the printed keys
```
Fill in `config.example.toml` on each side (private key, the *other* peer's
public key, `endpoint`, `allowed_ips`) and bring the tunnel up:
```sh
# needs the real-tun feature + root/admin (opens an actual OS TUN device)
cargo build --features ferrum-tunnel/real-tun
sudo ./target/debug/ferrum up --config config.example.toml
```
Good for showing the raw encrypted tunnel + a `ping` across it. Skip the
`sudo`/`real-tun` step (just build/run without it) to show the handshake logic
without needing root — the OS device path cleanly reports "unsupported" instead.

### B. The real demo — coordinator-managed mesh (Phase 3/4)

1. Start the coordinator:
   ```sh
   cargo run -p ferrum-coordinator -- --listen 0.0.0.0:50051 \
       --metrics-listen 0.0.0.0:9095
   ```
   (Add `--policy policy.example.toml` to show ACL enforcement — see `policy.example.toml`
   at repo root for the rule format; omit it for allow-all/full-mesh.)

2. Bring up two or more clients against it:
   ```sh
   cargo run -p ferrum-cli -- up-mesh \
       --config <your-config.toml> \
       --coordinator http://<coordinator-ip>:50051 \
       --endpoint <this-machine-ip>:51820 \
       --name laptop --tag dev
   ```
   Only `private_key`/`listen_port` are read from the config in this mode —
   peers come from the coordinator, not the config's `[peer]` block.

3. Talking points while it's running:
   - Kill a client and restart it — the always-on supervisor
     (`connect_with_retry` / `run_mesh_session_supervised`) auto-reconnects
     with backoff, no manual re-handshake.
   - Add `--stun-server <ip:port>` to show NAT-traversal candidate gathering;
     peers behind NAT still connect (direct if punched, relay fallback
     otherwise — start `cargo run -p ferrum-cli -- relay --listen
     0.0.0.0:51821` to show the fallback path live).
   - Tag two devices differently (`--tag dev` / `--tag server`) with a
     `--policy` file restricting `dev -> server` to show ACL enforcement
     denying an unauthorized peer pair.

### C. Desktop GUI (Tauri — Windows/Linux)

```sh
cd apps/desktop/src-tauri
cargo run --bin ferrum-desktop
```
No Node/build step — the frontend is static. First run shows the **identity
setup screen** (generate/import a WireGuard key); after that it's a
streamlined Connect screen with an Advanced disclosure for protocol fields.
**Real TUN + kill-switch enforcement needs elevated privileges** unless the
one-time privileged-helper daemon is installed (`apps/desktop/README.md` →
"Privileged helper (Linux)" section: `groupadd`, install `ferrum-helper`,
enable the systemd unit — lets the GUI itself stay unprivileged). On Windows
the equivalent is the `ferrum-helper` Windows service (same README).

### D. Android

Signed release APKs build via `clients/android/build-android.ps1` (cross-
compiles the shared Rust core for all four ABIs, then a Compose UI over it,
Keystore-backed credentials). Needs an actual device/emulator to install on —
confirm a build is available before promising a live phone demo.

### E. Observability stack (Grafana/Prometheus/Jaeger/Alertmanager)

```sh
docker compose -f deploy/observability/docker-compose.yml up -d
```
Grafana at **http://localhost:3000** (anonymous read-only; `admin`/`admin` to
edit) with a pre-provisioned **"Ferrum — Control Plane Overview"** dashboard.
Point the coordinator at it with `--metrics-listen 0.0.0.0:9095
--otlp-endpoint http://localhost:4317` (the `otlp` feature flag is only needed
for trace export — metrics work on a default build). Jaeger traces at
**http://localhost:16686**. All metrics/traces are aggregate-only — no
per-user IPs, keys, or traffic content ever leave the process (a privacy
guarantee that's actually enforced by an automated test, `tracing_privacy.rs`).

---

## 2. Talking to the coordinator API

The coordinator is **gRPC only today** (contract in
`crates/control-proto/proto/coordinator.proto`) — there is no REST/HTTP API
for device operations (only a `GET /metrics` Prometheus text endpoint). Two
ways to call it live in a demo:

**Via the CLI** (easiest — shown above): `ferrum keygen` / `up-mesh` do the
registration + network-map calls for you.

**Directly via `grpcurl`** (to show the raw protocol), since the server has no
reflection enabled, point it at the `.proto` file:
```sh
grpcurl -plaintext -proto crates/control-proto/proto/coordinator.proto \
  -d '{"public_key":"<base64-pubkey>","name":"demo-device","endpoint":"203.0.113.5:51820","tags":["dev"]}' \
  localhost:50051 ferrum.coordinator.v1.Coordinator/RegisterDevice
```
Other RPCs to demo the same way: `GetNetworkMap`, `WatchNetworkMap` (streams —
good for showing live push when a second device registers), `PublishCandidates`,
`RotateKey`.

**Auth**: open by default (tags are self-declared). Add `--oidc-issuer
<url> --oidc-audience <aud> --oidc-jwks <path>` when starting the coordinator
to require a bearer JWT on every RPC (tags then come from the verified claim,
not the request) — good for a security-conscious client to see. `--tls-cert/
--tls-key/--tls-ca` similarly turns on mutual TLS on the gRPC channel.

---

## 3. What's built vs. what's different vs. what's next

| Phase | Status | Notes |
|---|---|---|
| **1 — MVP tunnel** | ✅ Done | WireGuard crypto/handshake, real TUN (Linux/macOS/Windows), UDP transport. |
| **2 — Transport & obfuscation** | ✅ Done | QUIC + MASQUE (RFC 9298) transports, padding/jitter. Only gap: no live third-party MASQUE proxy tested against (external dependency). |
| **3 — Control plane** | ✅ Done | Coordinator: registration, IP allocation, full network map, ACL policy engine, live streaming, SQLite persistence, mTLS, OIDC auth, key rotation. |
| **4 — Mesh & NAT traversal** | ✅ Done | Crypto-demux mesh routing + roaming, STUN candidates, DERP-style relay, per-peer path state machine with automatic direct/relay fallback + upgrade, ICE candidate-pair prioritization. |
| **5 — Cross-platform clients** | 🟡 ~95% | Desktop (Windows + Linux, Tauri) with kill-switch (`nftables`/WFP) and unprivileged operation via a privileged-helper daemon/service; Android (signed APK). **iOS and macOS are deferred — need an Apple toolchain/host this project doesn't target yet.** |
| **6 — Scale & observability** | 🟡 ~15% | Observability half is **done**: Prometheus metrics, OTLP tracing, Grafana/Jaeger/Alertmanager stack, SLO burn-rate alerting. UDP GSO/GRO batching done (Linux). **Not started**: eBPF/XDP fast path, anycast, autoscaling, real-hardware throughput validation at scale. |

### Things to explicitly caveat if asked live

- **No web admin dashboard yet.** There is currently no way to view/revoke
  devices or edit ACL policy except by editing the `--policy` TOML file and
  restarting the coordinator. **This is actively being built right now**
  (device list + revoke + live policy editing, gated behind OIDC + an admin
  claim) but is not ready to demo today — don't show it live.
- **ACL policy changes require a coordinator restart** today (load-once from
  the TOML file at startup) — the in-progress admin panel will make this a
  live edit, but even then it will be runtime-only (not written back to the
  file) unless asked for as a follow-up.
- **macOS and iOS aren't supported** — both need an Apple development host
  this project doesn't have access to yet; explicitly deferred, not a bug.
- **Real-hardware throughput** is only validated in shared CI so far (~0.52 of
  a 1 Gbps shaped link vs. a 0.70 target) — dedicated hardware numbers aren't
  measured yet.
- **MASQUE obfuscation** hasn't been tested against a real third-party MASQUE
  proxy (only in-project), since none was available during development.

### Recommended next work (in priority order)

1. **Admin panel web UI** (in progress this session) — device list, revoke,
   live ACL policy editing over a new authenticated HTTP API on the
   coordinator.
2. **eBPF/XDP fast path + real-hardware throughput validation** (Phase 6) —
   the remaining scale work; UDP GSO/GRO batching already landed.
3. **macOS/iOS clients** — blocked on getting an Apple toolchain/host, not a
   design gap (the shared Rust core + `uniffi` Swift bindings already
   generate; only the native shell + macOS `pf` kill-switch are missing).
4. **Anycast + autoscaling** for the coordinator/relay at fleet scale.
