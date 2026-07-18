# PRD — Phase 1: MVP Encrypted Tunnel

| Field | Value |
|---|---|
| **Product** | Ferrum (Rust) |
| **Phase** | 1 of 6 — MVP Data Plane |
| **Status** | Draft |
| **Owner** | punar@ferrum.dev |
| **Last updated** | 2026-06-16 |
| **Language / Runtime** | Rust (stable), Tokio async |

---

## 1. Summary

Build the foundational data plane: a minimal, working WireGuard-based encrypted
tunnel between two peers, exchanging IP packets over UDP. This phase proves the
core crypto path, the virtual network interface integration, and raw throughput —
the technical bedrock every later phase (transport obfuscation, control plane,
mesh, clients) builds on.

This is **not** a product release. It is an internal, headless, command-line
proof of the tunnel. No GUI, no control plane, no key distribution server — keys
are configured manually via files, exactly like reference WireGuard.

---

## 2. Goals & Non-Goals

### Goals
- G1. Establish an encrypted tunnel between exactly two peers (point-to-point).
- G2. Capture host IP packets via a TUN virtual interface and tunnel them.
- G3. Use the WireGuard cryptographic suite (Curve25519, ChaCha20-Poly1305, BLAKE2s) via `boringtun`.
- G4. Carry tunnel traffic over plain UDP (no obfuscation yet — Phase 2).
- G5. Manual key/config provisioning via a static config file.
- G6. Demonstrate and measure throughput and latency vs. a baseline.

### Non-Goals (explicitly deferred)
- ❌ Control plane / coordination server (Phase 3)
- ❌ QUIC / MASQUE / DPI-evasion transport (Phase 2)
- ❌ NAT traversal, ICE, relays, mesh (Phase 4)
- ❌ Mobile / desktop GUI clients (Phase 5)
- ❌ eBPF/XDP acceleration, anycast (Phase 6)
- ❌ Automatic key rotation, OIDC auth, ACLs
- ❌ Windows support (Linux + macOS only this phase)

---

## 3. Background & Rationale

The riskiest, most security-critical part of any VPN is the data path. By
isolating it in Phase 1 — with manual config and no networked control plane — we
de-risk the crypto and packet I/O before adding distributed-systems complexity.
`boringtun` (Cloudflare's audited userspace WireGuard) gives us a proven crypto
core so we do not hand-roll primitives.

Related decisions live in the broader architecture (see workspace layout). This
PRD covers only the `core`, `tunnel`, and `cli` crates.

---

## 4. Users & Use Case

- **Primary user (this phase):** the engineering team.
- **Use case:** On two Linux/macOS hosts, run the CLI with a config file on each.
  The hosts can then ping each other and pass TCP/UDP traffic over the encrypted
  tunnel using private tunnel IPs (e.g., `10.8.0.1` ↔ `10.8.0.2`).

---

## 5. Functional Requirements

### FR1 — TUN Interface
- Create and configure a TUN device on startup (`tun` crate on Linux/macOS).
- Assign the tunnel IP and bring the interface up.
- Read outbound IP packets from the device; write inbound decrypted packets to it.
- Clean teardown of the interface on exit (Ctrl-C / SIGTERM).

### FR2 — WireGuard Session (`boringtun`)
- Initialize a `Tunn` (boringtun session) from local private key + peer public key.
- Perform the Noise handshake with the peer.
- Encrypt outbound packets; decrypt inbound packets.
- Handle handshake initiation, response, and periodic re-handshake / keepalive
  timers as driven by boringtun.

### FR3 — UDP Transport
- Bind a UDP socket on a configurable local port.
- Send encrypted datagrams to the configured peer endpoint (IP:port).
- Receive datagrams and feed them into the boringtun session.
- Async event loop (Tokio): multiplex TUN read, UDP read, and timer ticks.

### FR4 — Configuration
- Load a static config file (TOML) at startup. Fields:
  - `private_key` (base64), `listen_port`
  - `interface_address` (CIDR, e.g. `10.8.0.1/24`)
  - `[peer]`: `public_key`, `endpoint` (IP:port), `allowed_ips`
- Validate config; fail fast with a clear error on malformed input.
- Provide a `keygen` subcommand to generate a Curve25519 keypair (base64).

### FR5 — CLI
- `ferrum keygen` → prints a new private/public keypair.
- `ferrum up --config <path>` → brings up the tunnel and runs until interrupted.
- Structured logging via `tracing` (levels controlled by `RUST_LOG`).
- **No packet payloads or keys are ever logged.**

---

## 6. Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR1 | Throughput | ≥ 70% of raw link bandwidth on a 1 Gbps LAN |
| NFR2 | Added latency | < 2 ms over direct connection on LAN |
| NFR3 | Memory safety | No `unsafe` outside vetted FFI/`tun` boundaries; `#![forbid(unsafe_code)]` in `core` |
| NFR4 | Startup time | Tunnel established in < 1 s after both peers up |
| NFR5 | Reliability | Survives peer restart (re-handshake automatically) |
| NFR6 | Crypto | Only audited crates; no custom primitives |

---

## 7. Architecture (Phase 1 scope)

```
            host network stack
                   │
            ┌──────▼───────┐   reads outbound / writes inbound IP packets
            │  TUN device  │
            └──────┬───────┘
                   │ plaintext IP packets
            ┌──────▼───────────────────────┐
            │   tunnel crate (Tokio loop)   │
            │  ┌─────────────────────────┐  │
            │  │ boringtun Tunn session  │  │  encrypt / decrypt + handshake
            │  └─────────────────────────┘  │
            └──────┬───────────────────────┘
                   │ encrypted datagrams
            ┌──────▼───────┐
            │  UDP socket  │ ──────────►  peer endpoint (IP:port)
            └──────────────┘
```

### Crates touched
- `crates/core` — keys, config types, protocol constants (`#![forbid(unsafe_code)]`).
- `crates/tunnel` — boringtun integration, TUN I/O, UDP I/O, async event loop.
- `crates/cli` — argument parsing, config loading, `keygen` / `up` commands.

### Key dependencies
`boringtun`, `tokio`, `tun`, `x25519-dalek`, `base64`, `serde` + `toml`,
`clap`, `tracing`, `tracing-subscriber`, `thiserror`, `anyhow`.

---

## 8. Milestones / Task Breakdown

1. **M1 — Workspace bootstrap:** Cargo workspace + three crates compile.
2. **M2 — Key management:** `keygen`, config parsing/validation, key types.
3. **M3 — TUN I/O:** create/configure/teardown interface; echo raw packets.
4. **M4 — Crypto session:** wire boringtun; complete handshake between two peers.
5. **M5 — End-to-end:** full event loop; `ping` succeeds across the tunnel.
6. **M6 — Benchmark:** `iperf3` throughput + latency report vs. baseline (NFR1/2).

---

## 9. Acceptance Criteria

- ✅ Two hosts with valid configs establish a tunnel and bidirectionally `ping`
  each other on their tunnel IPs.
- ✅ `iperf3` over the tunnel meets NFR1 (≥70% link) and NFR2 (<2 ms added latency).
- ✅ Killing and restarting one peer re-establishes the tunnel automatically (NFR5).
- ✅ Malformed config produces a clear, actionable error and non-zero exit.
- ✅ No keys or packet payloads appear in logs at any log level.
- ✅ `cargo clippy` clean; `core` crate enforces `#![forbid(unsafe_code)]`.

---

## 10. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| TUN device perms / platform differences | Blocks dev | Document `sudo`/capabilities; abstract device behind a trait |
| boringtun timer/handshake misuse | Silent tunnel failures | Follow reference event-loop pattern; integration test the handshake |
| Userspace throughput below target | Misses NFR1 | Profile; batch I/O; note kernel-WireGuard path as future option |
| macOS `utun` quirks vs Linux `tun` | Platform bugs | CI on both; keep platform code isolated in `tunnel` crate |

---

## 11. Out-of-Scope Follow-ups (feed into later PRDs)

- Phase 2: QUIC/MASQUE transport + DPI-evasion obfuscation.
- Phase 3: Control plane (coordinator), OIDC auth, key distribution, ACLs.
- Phase 4: ICE NAT traversal, DERP-style relays, mesh topology.
- Phase 5: `uniffi` client core + iOS/Android/desktop shells.
- Phase 6: eBPF/XDP acceleration, anycast edge, observability at scale.
