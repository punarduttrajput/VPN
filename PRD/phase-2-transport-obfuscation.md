# PRD — Phase 2: QUIC Transport & DPI-Evasion

| Field | Value |
|---|---|
| **Product** | Next-Gen VPN (Rust) |
| **Phase** | 2 of 6 — Transport & Obfuscation Layer |
| **Status** | Draft |
| **Owner** | punarr@plasmacomp.com |
| **Last updated** | 2026-06-16 |
| **Depends on** | Phase 1 (MVP tunnel) |

---

## 1. Summary

Wrap the Phase 1 WireGuard data path in a modern, multiplexed, obfuscation-capable
transport so the VPN survives mobile network changes, traverses restrictive
middleboxes, and resists DPI fingerprinting. The transport rides on **QUIC**
(via `quinn`), with a **MASQUE (CONNECT-UDP over HTTP/3)** mode so tunnel traffic
is indistinguishable from ordinary HTTPS/3 web traffic.

Phase 1 carried encrypted datagrams over plain UDP — trivially fingerprinted and
blocked. Phase 2 makes the wire look like the rest of the internet.

---

## 2. Goals & Non-Goals

### Goals
- G1. Carry the WireGuard tunnel inside a QUIC connection (`quinn`).
- G2. Implement a **MASQUE / CONNECT-UDP over HTTP/3** mode for HTTPS-like camouflage.
- G3. Seamless connection migration — survive IP/network changes (Wi-Fi ↔ cellular).
- G4. Pluggable transport abstraction: `udp` (Phase 1) and `quic`/`masque` selectable via config.
- G5. Padding / timing obfuscation to defeat packet-size fingerprinting.
- G6. Maintain Phase 1 throughput targets within an acceptable overhead budget.

### Non-Goals
- ❌ Control plane / key distribution (Phase 3) — still manual config.
- ❌ NAT traversal / relays / mesh (Phase 4).
- ❌ Pluggable third-party transports (obfs4, Shadowsocks) — QUIC/MASQUE only this phase.
- ❌ GUI clients.

---

## 3. Background & Rationale

Raw WireGuard-over-UDP has a fixed header signature and is increasingly blocked by
national firewalls and corporate DPI. QUIC is now ubiquitous (HTTP/3), encrypted
end-to-end, and natively supports connection migration — making it both fast and
hard to distinguish from normal web traffic. MASQUE (RFC 9298) standardizes
proxying UDP inside HTTP/3, which is exactly the camouflage we want and is already
used by Apple iCloud Private Relay.

---

## 4. Users & Use Case

- **Primary user:** engineering team + early dogfooders on hostile networks.
- **Use case:** A user on a network that blocks UDP/WireGuard selects `masque`
  transport; the tunnel connects over what appears to be HTTPS/3 to a server on
  443/udp, and stays connected as the user moves between Wi-Fi and cellular.

---

## 5. Functional Requirements

### FR1 — Transport Abstraction
- Define a `Transport` trait: `send_datagram`, `recv_datagram`, `connect`, `migrate`, `close`.
- Phase 1 UDP becomes one implementation; QUIC and MASQUE are new implementations.
- Transport selected via config (`transport = "udp" | "quic" | "masque"`).

### FR2 — QUIC Transport (`quinn`)
- Establish a QUIC connection to the peer/server endpoint with `rustls`.
- Carry WireGuard packets as QUIC **datagrams** (unreliable, low-latency) by default;
  optional reliable-stream fallback for constrained networks.
- TLS 1.3 with a realistic certificate / ALPN (`h3`) to blend with HTTP/3.

### FR3 — MASQUE Mode (CONNECT-UDP / HTTP/3)
- Implement RFC 9298 CONNECT-UDP: client issues an HTTP/3 `CONNECT` to a MASQUE
  proxy, then tunnels UDP datagrams through it.
- Server side terminates HTTP/3 and forwards UDP to the WireGuard endpoint.
- Listen on 443/udp so traffic is indistinguishable from web QUIC.

### FR4 — Connection Migration & Roaming
- Use QUIC connection IDs to survive client IP/port changes without re-handshake.
- Detect local network change and trigger migration; tunnel stays up.
- Idle keepalive tuned for mobile (battery vs. responsiveness trade-off documented).

### FR5 — Obfuscation
- Optional packet padding to normalize datagram sizes.
- Optional timing jitter to blunt traffic-analysis fingerprints.
- All obfuscation toggetable; off by default for max throughput on safe networks.

### FR6 — Config & CLI
- Extend Phase 1 config with `[transport]` block (mode, server name, cert/SNI, padding).
- `vpn up` honors the selected transport transparently.

---

## 6. Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR1 | QUIC overhead vs. Phase 1 UDP | < 15% throughput reduction on LAN |
| NFR2 | Migration time on network switch | Tunnel recovers in < 2 s, no app-visible drop |
| NFR3 | DPI resistance | Passive DPI cannot distinguish from HTTP/3 (validated with `nDPI`/Wireshark) |
| NFR4 | Handshake time over MASQUE | < 1.5 s on a 50 ms RTT link |
| NFR5 | Memory safety | No new `unsafe`; transport crate `#![forbid(unsafe_code)]` where feasible |

---

## 7. Architecture

```
   tunnel crate (boringtun)  ── encrypted WG packets ──┐
                                                       │
                                        ┌──────────────▼───────────────┐
                                        │   transport crate (trait)     │
                                        │  ┌────────┬────────┬───────┐  │
                                        │  │  udp   │  quic  │ masque│  │
                                        │  └────────┴────────┴───────┘  │
                                        └──────────────┬───────────────┘
                                                       │ QUIC/HTTP3 datagrams (443/udp)
                                              looks like normal HTTPS/3
```

### Crates
- `crates/transport` — new: the `Transport` trait + UDP/QUIC/MASQUE impls.
- `crates/tunnel` — refactored to depend on `Transport` instead of raw UDP.
- `crates/core` — shared transport config types.

### Key dependencies
`quinn`, `rustls`, `rcgen`, `h3` / `h3-quinn`, `bytes`, plus Phase 1 deps.

---

## 8. Milestones

1. **M1** — Extract `Transport` trait; port Phase 1 UDP behind it (no behavior change).
2. **M2** — QUIC datagram transport via `quinn`; tunnel works over QUIC.
3. **M3** — Connection migration on simulated network switch.
4. **M4** — MASQUE CONNECT-UDP client + server on 443/udp.
5. **M5** — Padding/jitter obfuscation toggles.
6. **M6** — DPI validation + throughput/migration benchmarks.

---

## 9. Acceptance Criteria

- ✅ Tunnel passes traffic over `quic` and `masque` transports, selectable by config.
- ✅ Switching the client's network interface keeps the tunnel alive (NFR2).
- ✅ MASQUE traffic on 443/udp is not flagged as VPN by `nDPI` (NFR3).
- ✅ QUIC overhead within NFR1 budget on benchmark.
- ✅ Falling back to `udp` still works (regression-safe).

---

## 10. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| QUIC userspace overhead hurts throughput | Misses NFR1 | Use unreliable datagrams; enable GSO/GRO; profile |
| MASQUE/HTTP3 spec complexity | Slips timeline | Lean on `h3` crate; start with minimal CONNECT-UDP subset |
| Cert/SNI mismatch reveals VPN | Weakens NFR3 | Use valid certs + realistic SNI; document deployment |
| Migration edge cases on mobile | Dropped sessions | Extensive network-switch test matrix |

---

## 11. Feeds Into
- Phase 3 control plane will distribute transport config + endpoints automatically.
- Phase 4 relays will speak this transport for NAT traversal fallback.
