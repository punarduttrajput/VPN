# PRD — Phase 3: Control Plane, Auth & Key Distribution

| Field | Value |
|---|---|
| **Product** | Ferrum (Rust) |
| **Phase** | 3 of 6 — Control Plane |
| **Status** | Draft |
| **Owner** | punar@ferrum.dev |
| **Last updated** | 2026-06-16 |
| **Depends on** | Phase 1 (tunnel), Phase 2 (transport) |

---

## 1. Summary

Replace manual, file-based key configuration with a networked **coordination
server** that authenticates users, registers devices, distributes public keys and
endpoints, and enforces access policy. This is the leap from a two-peer demo to a
managed, multi-device VPN network. Clients authenticate via **OIDC/OAuth2**
(optionally passkeys), receive their tunnel config dynamically, and re-sync as the
network changes.

---

## 2. Goals & Non-Goals

### Goals
- G1. Coordination server (gRPC API via `tonic`) for device registration & config sync.
- G2. Identity-based auth via **OIDC/OAuth2** (Google/Okta/Azure AD); optional WebAuthn/passkeys.
- G3. Automatic key distribution: clients publish their public key, receive peer keys + endpoints.
- G4. Short-lived keys with automatic rotation.
- G5. Policy engine: ACLs-as-code controlling which devices may reach which peers/subnets.
- G6. Client auto-configures the Phase 1/2 data plane from server-provided state.

### Non-Goals
- ❌ P2P NAT traversal / relays / mesh data path (Phase 4) — clients still connect to a gateway.
- ❌ GUI (Phase 5).
- ❌ Billing, multi-tenant org management, admin dashboard UI (future product phases).
- ❌ Storing or logging user traffic (privacy-by-design: control metadata only).

---

## 3. Background & Rationale

Manual key exchange does not scale beyond a handful of peers and is error-prone.
A control plane is what turns WireGuard into a product: it manages identity,
distributes the constantly-changing map of peers and endpoints, and enforces
who-can-reach-what. Using OIDC means we never store passwords and integrate with
existing corporate identity. Keeping the control plane strictly metadata (keys,
endpoints, policy — never traffic) preserves the no-logs privacy promise.

---

## 4. Users & Use Case

- **Primary users:** end users (devices) + a network administrator.
- **Use case:** A user installs the client, logs in via their company SSO, and the
  device is automatically issued a tunnel IP, given the current peer map, and
  connected — no manual key copying. An admin defines ACLs (e.g., "contractors may
  reach only the staging subnet") that the server enforces.

---

## 5. Functional Requirements

### FR1 — Coordination Server (`tonic` gRPC)
- Device registration endpoint: client submits public key + device metadata; server
  assigns a tunnel IP and persists device record.
- Network-map endpoint: returns the set of peers (public keys, endpoints, allowed IPs)
  the calling device is permitted to reach.
- Streaming updates: push network-map changes to connected clients (long-lived stream).
- Heartbeat / liveness; mark devices offline after timeout.

### FR2 — Authentication
- OIDC/OAuth2 login flow (authorization code + PKCE) producing a verified identity.
- Map identity → user → devices; enforce per-user device limits.
- Optional WebAuthn/passkey binding for device authentication.
- Issue short-lived signed session tokens (e.g., JWT) for API calls.

### FR3 — Key & Endpoint Distribution
- Clients never share private keys; only public keys reach the server.
- Server distributes the authoritative peer map; clients reconfigure the data plane live.
- Automatic key rotation on a configurable interval; graceful re-handshake.

### FR4 — Policy Engine (ACLs-as-code)
- Declarative policy file (e.g., HuJSON/TOML): groups, tags, allow rules.
- Server computes per-device allowed-peer sets from policy + identity.
- Policy changes propagate to affected devices via the update stream.

### FR5 — Persistence
- Store devices, users, keys (public only), endpoints, policy, and assignments.
- Backing store: PostgreSQL (via `sqlx`); RAM-cached hot path.
- No traffic data, ever. Schema documents the privacy boundary.

### FR6 — Client Integration
- Client gains `login`, `logout`, `status` commands.
- On login, client fetches map, configures the Phase 1/2 tunnel, and subscribes to updates.

---

## 6. Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR1 | Map sync latency (change → client applied) | < 3 s p95 |
| NFR2 | Server scale | 10k devices per coordinator instance |
| NFR3 | API auth | All endpoints require valid session; mTLS between client/server |
| NFR4 | Privacy | No traffic content/metadata persisted; only control-plane state |
| NFR5 | Availability | Coordinator stateless-where-possible; horizontal scale behind LB |
| NFR6 | Key handling | Private keys never leave the device |

---

## 7. Architecture

```
   ┌──────────┐  OIDC login   ┌─────────────────┐
   │  Client  │──────────────►│  Identity (IdP)  │
   └────┬─────┘               └─────────────────┘
        │ gRPC (mTLS): register key, fetch map, subscribe updates
        ▼
   ┌─────────────────────────────────────┐
   │      Coordinator (tonic server)      │
   │  auth · device registry · policy     │
   │  engine · network-map distribution   │
   └───────────────┬─────────────────────┘
                   │
            ┌──────▼───────┐
            │  PostgreSQL  │  (devices, users, public keys, endpoints, policy)
            └──────────────┘

   Data path: client ──(Phase 2 transport)──► gateway/peer  (configured from map)
```

### Crates
- `crates/control-proto` — protobuf/gRPC service definitions (`prost` + `tonic`).
- `crates/coordinator` — server binary: auth, registry, policy, persistence.
- `crates/client-core` — client logic: login, map sync, data-plane reconfiguration.

### Key dependencies
`tonic`, `prost`, `sqlx` (PostgreSQL), `jsonwebtoken`, an OIDC client crate,
`rustls` (mTLS), `serde`, `tracing`.

---

## 8. Milestones

1. **M1** — gRPC service contract (`control-proto`) + skeleton coordinator.
2. **M2** — Device registration + tunnel-IP assignment + PostgreSQL persistence.
3. **M3** — OIDC login flow end-to-end; session tokens; mTLS.
4. **M4** — Network-map distribution + live update stream; client reconfigures tunnel.
5. **M5** — Policy engine (ACLs-as-code) enforcing allowed-peer sets.
6. **M6** — Key rotation + scale/load test to NFR2.

---

## 9. Acceptance Criteria

- ✅ A new device logs in via OIDC and connects with zero manual key handling.
- ✅ Adding/removing a device updates other devices' peer maps within NFR1.
- ✅ An ACL denying a device a subnet is enforced (traffic blocked).
- ✅ Key rotation completes without dropping established tunnels.
- ✅ DB contains no traffic data; only control-plane state (audited).
- ✅ Load test sustains NFR2 devices on one coordinator.

---

## 10. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| OIDC integration complexity | Timeline slip | Start with one IdP (Google), generalize after |
| Map-distribution consistency at scale | Stale routes | Versioned maps + reconciliation; idempotent apply |
| Policy engine correctness | Security holes | Property tests; deny-by-default; audit logging of decisions |
| DB as availability bottleneck | Outages | Read replicas + cache; stateless coordinators |

---

## 11. Feeds Into
- Phase 4 uses the coordinator to broker NAT traversal (signaling) and relay assignment.
- Phase 5 clients build their UI on `client-core`'s login/status/map APIs.
