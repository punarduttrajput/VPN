# PRD — Relay mesh: forwarding between relays

| Field | Value |
|---|---|
| **Product** | Ferrum (Rust) |
| **Phase** | 6 — Scale & Acceleration (prerequisite for anycast M5 and multi-PoP M4) |
| **Status** | M1 (static relay mesh) and M2 (coordinator membership) implemented and verified in-process; M3 (autoscaling templates) committed and CI-validated (2026-10-05) |
| **Owner** | punarduttrajput |
| **Depends on** | the Phase 4 relay (`crates/transport/src/relay.rs`), the relay registry (`phase-6-anycast-autoscaling.md` FR3), the XDP fast path (`phase-6-ebpf-xdp-relay.md`) |

## 1. Problem

A relay forwards a `Data` frame only when both the sender and the destination
are registered **on that relay** (`RelayServer::serve`; anything else is
dropped). That's fine while the coordinator advertises one relay to everyone.
It breaks as soon as there is more than one live relay:

- **Anycast (anycast M4):** peers in different regions land on different PoPs
  and can't relay to each other. The M4 docs limit anycast to one ready PoP.
- **A scaled-out pool (anycast M5):** a load balancer can hash two peers to
  different instances, with the same result.

So the relay tier can't scale out until relays forward to each other.

## 2. Goals and non-goals

**Goals**
- G1. A frame for a key registered on a *sibling* relay reaches it in one
  extra hop, with no client change.
- G2. Siblings learn where each key is without a central lookup on the data
  path.
- G3. A client that moves between relays (anycast flip, pool rebalance,
  drain) is found at its new relay within seconds.
- G4. Mesh links are authenticated: nothing outside the mesh can inject
  frames, announce keys or redirect traffic through it.
- G5. Opt-in and additive: a relay with no mesh flags behaves exactly as
  today.

**Non-goals**
- Multi-hop routing or partial meshes. Every relay talks to every sibling
  (a full mesh), like Tailscale's DERP mesh. That's fine to tens of relays per
  region; beyond that is a later design.
- Encrypting mesh traffic. The forwarded payload is already WireGuard
  ciphertext; the mesh adds authentication, not confidentiality. Mesh links
  are expected on a private network.
- Mesh forwarding in the XDP fast path. Frames for a sibling's key fall
  through to userspace (`XDP_PASS`), as any unknown destination does today.

## 3. Design

### 3.1 Membership

A relay's siblings are a list of **mesh addresses** (each relay's unicast
`ip:port` mesh listener, separate from its client-facing port):

- **M1, static:** `ferrum relay --mesh-listen <ip:port> --mesh-peer <ip:port>
  … --mesh-key-file <path>`.
- **M2, from the coordinator:** `RelayHeartbeat` gains the relay's
  `mesh_addr`; the response lists the other live relays' mesh addresses. The
  registry is then keyed by mesh address rather than client-facing address,
  so anycast PoPs sharing one client-facing address each get their own entry,
  and one PoP's goodbye no longer withdraws the shared advertisement. That
  lifts the M4 one-ready-PoP limit.

### 3.2 Wire format (mesh socket only)

```
magic "FRM1" (4) | type (1) | sender (8) | counter (8) | body | tag (16)
tag = keyed BLAKE2s-128 (mesh key) over everything before it
```

`sender` is a random id per relay process; `counter` increases with every
message it sends. Types:

| Type | Body | Meaning |
|---|---|---|
| `0x01` Present | up to 32 × (key 32 B + age_ms u32) | "I hold these keys; I last heard from each `age_ms` ago" |
| `0x02` Gone | up to 32 × key | "These keys aren't (or are no longer) here" |
| `0x03` Data | src key 32 B, dst key 32 B, payload | a client `Data` frame for one of the receiver's clients |
| `0x04` Sync | empty | "Send me your full key list" |

A datagram is accepted only from a configured sibling address and only with
a valid tag. Control messages (Present, Gone, Sync) also need a counter
above the last one seen from that `sender`, so they can't be replayed. Data
isn't counter-checked: its payload is WireGuard, which rejects replays, and a
replayed frame costs no more than one sent to the client directly.

### 3.3 Location

- Each relay keeps, next to its own clients, a **remote table**
  `key → (sibling, heard_at)`.
- **Announce:** when a key is committed locally for the first time or roams,
  the relay sends Present to every sibling at once. It also re-announces its
  whole table every 30 s, and to a sibling that sends Sync (one does on
  start). Remote entries not refreshed for 90 s expire, so a sibling that
  dies without a word is forgotten.
- **Moves:** a relay tracks when it last heard from each of its own clients
  (register, keepalive or data). On Present(K, age) from a sibling, if it
  also holds K locally and its own last-heard is **older** than the sibling's
  `age`, the client has moved: it drops K locally (and from the XDP maps).
  Comparing ages rather than timestamps needs no clock sync, and two crossed
  announcements can't both delete the client: only the relay that heard from
  it less recently gives it up.
- **Forwarding:** a `Data` frame from a local client for a key that isn't
  local but is in the remote table is sent to that sibling as mesh Data. The
  receiver delivers it as an ordinary `Data` frame from the source key. A
  receiver that doesn't hold the destination answers Gone, and the sender
  drops that remote entry. Mesh frames are never forwarded again (one hop, so
  no loops).
- Local always wins: a key held locally is delivered locally.

### 3.4 Drain and GoAway

Unchanged. A draining relay keeps serving its clients; as they re-register
elsewhere, the new relay's Present makes the draining one drop them.

### 3.5 Metrics (aggregate only, NFR5)

`ferrum_relay_mesh_peers` (gauge), `ferrum_relay_mesh_remote_keys` (gauge),
`ferrum_relay_mesh_frames_forwarded_total`,
`ferrum_relay_mesh_frames_delivered_total`,
`ferrum_relay_mesh_rejected_total` (bad tag, unknown sender, replay).

## 4. Milestones

1. **M1 — Static relay mesh** ✅ *(2026-10-05)*. The protocol above, static
   membership, the XDP hook learns removals, metrics. Verified in-process:
   two relays, a client on each, traffic both ways; a client moving between
   relays is found again; crossed announcements keep the client; bad tag,
   unknown sender and replayed control messages are rejected; a relay
   without mesh flags is unchanged.
   *As built:* `crates/transport/src/relay_mesh.rs` (protocol, replay
   check, sibling table, the yield rule) + `RelayServer::bind_with_mesh` /
   `set_mesh_peers` (the latter is what M2's coordinator membership will
   call) + `ferrum relay --mesh-listen/--mesh-peer/--mesh-key-file`. A
   relay that keeps a client because it heard from it more recently answers
   the sibling's Present with its own, so the sibling gives the client up at
   once rather than at its next announce. The XDP loader removes a moved
   client from both kernel maps (`RelayXdpHook::on_remove`).
2. **M2 — Coordinator membership** ✅ *(2026-10-05)*. `mesh_addr` in the
   heartbeat, sibling list in the response, registry keyed by mesh address;
   the anycast docs' one-ready-PoP limit lifted.
   *As built:* `RelayHeartbeatRequest.mesh_addr` / `RelayHeartbeatResponse.
   mesh_peers`. The coordinator refuses a mesh address that's unspecified or
   port 0 (siblings match a datagram's source against it), and so does
   `ferrum relay` when it has `--coordinator`. A draining mesh relay stops
   being advertised at once but stays in its siblings' lists until its
   heartbeats lapse (45 s, longer than the 20 s default drain), so they keep
   forwarding to the clients it still serves. The heartbeat loop moved from
   the CLI into `ferrum_client_core::relay_heartbeat` (so it's testable
   against a real coordinator); it merges the coordinator's list with any
   `--mesh-peer`s and calls `set_mesh_peers` on every beat. Siblings learn a
   new relay within one heartbeat interval (15 s).
3. **M3 — Autoscaling (anycast M5)** ✅ *(2026-10-05)*. The OCI instance pool,
   scaling signals and policies, Ansible node config, and the CI validation
   job, now that a scaled-out pool works. See `deploy/autoscaling/README.md`.

## 5. Risks

| Risk | Mitigation |
|---|---|
| Full-mesh announce traffic grows with relays × clients | 36 B per key per 30 s per sibling: 10k clients is ~12 KB/s per sibling. Fine for tens of relays; larger fleets are a non-goal. |
| A lost Present leaves a key unfindable | Periodic full re-announce (≤ 30 s), plus Sync on start |
| A stolen mesh key lets an attacker redirect frames | The payload stays WireGuard ciphertext (no decryption, no injection into sessions); the key is per deployment and file-based, rotated by restarting relays with a new one |
| Clock skew | None used: ages, not timestamps |
