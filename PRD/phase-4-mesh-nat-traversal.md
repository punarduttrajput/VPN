# PRD — Phase 4: Mesh, NAT Traversal & Relays

| Field | Value |
|---|---|
| **Product** | Next-Gen VPN (Rust) |
| **Phase** | 4 of 6 — Mesh Networking |
| **Status** | Draft |
| **Owner** | punarr@plasmacomp.com |
| **Last updated** | 2026-06-16 |
| **Depends on** | Phases 1–3 |

---

## 1. Summary

Evolve the topology from gateway/hub-and-spoke to a **peer-to-peer mesh**: devices
connect **directly** to each other whenever the network allows, falling back to
**relay servers** only when direct connectivity is impossible. This delivers the
lowest possible latency and offloads bandwidth from central servers. Direct
connectivity is achieved via **ICE (STUN/TURN)** with the coordinator (Phase 3)
acting as the signaling broker; relays use a **DERP-style** encrypted packet-relay
protocol.

---

## 2. Goals & Non-Goals

### Goals
- G1. Establish direct peer-to-peer tunnels through NATs using ICE (STUN-based hole punching).
- G2. DERP-style relay servers as automatic fallback when direct connection fails.
- G3. Coordinator-brokered signaling (candidate exchange) reusing Phase 3 streams.
- G4. Automatic, transparent upgrade from relay → direct once a path is found.
- G5. Multi-relay selection by latency (pick nearest/fastest relay).
- G6. Full mesh peer map: any permitted device can reach any other directly or via relay.

### Non-Goals
- ❌ GUI (Phase 5).
- ❌ eBPF/XDP relay acceleration & anycast (Phase 6).
- ❌ Exit-node / internet-gateway routing features (future product phase).

---

## 3. Background & Rationale

Hub-and-spoke routes all traffic through central servers — added latency, bandwidth
cost, and a scaling bottleneck. A mesh (the Tailscale model) connects peers directly
for the common case, using relays only as a safety net. Most NATs can be traversed
with STUN hole-punching; the minority that can't (symmetric NATs, strict firewalls)
fall back to relays. Crucially, relays only ever see **encrypted** WireGuard packets —
they cannot read traffic, preserving end-to-end confidentiality.

---

## 4. Users & Use Case

- **Primary users:** end-user devices across diverse networks (home NAT, mobile CGNAT, corporate).
- **Use case:** Two laptops behind different home routers connect directly after hole
  punching — LAN-like latency. A phone on strict carrier CGNAT can't punch through, so it
  connects via the nearest relay; when it later joins Wi-Fi, it transparently upgrades to direct.

---

## 5. Functional Requirements

### FR1 — ICE / NAT Traversal
- Gather ICE candidates (host, server-reflexive via STUN, relayed via TURN).
- Exchange candidates with the peer through the coordinator's signaling stream.
- Perform connectivity checks; select the best working candidate pair.
- Establish the WireGuard tunnel (Phase 1/2 transport) over the chosen path.

### FR2 — STUN / TURN
- Run or integrate STUN servers for server-reflexive candidate discovery.
- TURN support for relayed candidates where required.

### FR3 — DERP-Style Relays
- Relay server that forwards **encrypted** packets between peers keyed by public key.
- Relays authenticate clients (via Phase 3 session) but never decrypt payloads.
- Geo-distributed relays; client measures RTT and selects the fastest.

### FR4 — Path Upgrade / Downgrade
- Start via relay for instant connectivity, attempt direct path in background.
- Seamlessly migrate to direct once a candidate pair succeeds (no session drop).
- Detect direct-path failure and fall back to relay automatically.

### FR5 — Coordinator Signaling Extensions
- Extend Phase 3 gRPC streams to carry ICE candidate exchange between peers.
- Distribute relay list + per-peer reachability hints in the network map.

### FR6 — Mesh Peer Management
- Each device maintains live tunnels to its active peer set (lazy/on-demand setup).
- Connection state machine per peer: `idle → relay → connecting → direct`.

---

## 6. Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR1 | Direct-connection success rate | ≥ 90% of peer pairs (industry-typical) |
| NFR2 | Hole-punch time | < 3 s p95 |
| NFR3 | Relay→direct upgrade | Transparent, < 5 s, no app-visible drop |
| NFR4 | Relay overhead | Adds < 30 ms vs direct on same region |
| NFR5 | Relay confidentiality | Relays cannot decrypt traffic (E2E preserved) |
| NFR6 | Relay scale | 5k concurrent relayed sessions per node |

---

## 7. Architecture

```
        ┌─────────────────────────────┐
        │   Coordinator (Phase 3)     │  signaling: ICE candidate exchange
        └───────┬─────────────┬───────┘
                │             │
          ┌─────▼───┐   ┌─────▼───┐
          │ Device A│   │ Device B│
          └──┬───┬──┘   └──┬───┬──┘
             │   │  direct │   │
             │   └─────────┘   │   ◄── preferred: P2P after hole punch
             │                 │
          ┌──▼─────────────────▼──┐
          │   DERP-style Relay     │   ◄── fallback: forwards ENCRYPTED packets only
          └────────────────────────┘
```

### Crates
- `crates/relay` — DERP-style encrypted packet relay server binary.
- `crates/client-core` — ICE, candidate gathering, path selection, peer state machine.
- `crates/coordinator` — signaling extensions + relay-list distribution.
- `crates/control-proto` — candidate-exchange messages.

### Key dependencies
`str0m` or `webrtc` ICE/STUN/TURN crates, Phase 1–3 deps, `tracing`.

---

## 8. Milestones

1. **M1** — STUN candidate gathering + coordinator candidate-exchange signaling.
2. **M2** — Connectivity checks + direct P2P tunnel establishment.
3. **M3** — DERP-style relay server forwarding encrypted packets.
4. **M4** — Relay selection by latency + relay-as-default-then-upgrade flow.
5. **M5** — Transparent relay→direct upgrade & failure fallback state machine.
6. **M6** — Connectivity matrix testing across NAT types + scale tests.

---

## 9. Acceptance Criteria

- ✅ Two peers behind different NATs establish a direct tunnel (NFR1/NFR2).
- ✅ A peer behind symmetric NAT connects via relay and later upgrades to direct (NFR3).
- ✅ Relay forwards traffic but provably cannot decrypt it (NFR5).
- ✅ Client picks the lowest-latency relay from several regions.
- ✅ Direct-path loss falls back to relay without dropping the user's session.

---

## 10. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Symmetric/CGNAT defeats hole punching | Lower direct rate | Robust TURN/relay fallback; document expected rates |
| ICE complexity / edge cases | Bugs, flaky connects | Use battle-tested ICE crate; broad NAT-type test matrix |
| Relay becomes bandwidth bottleneck | Cost/latency | Geo-distribute; prioritize direct; Phase 6 acceleration |
| Signaling races during upgrade | Session drops | Versioned candidate exchange; idempotent path switching |

---

## 11. Feeds Into
- Phase 5 surfaces connection state (direct vs relay) in client UIs.
- Phase 6 accelerates relays (eBPF/XDP) and fronts them with anycast.
