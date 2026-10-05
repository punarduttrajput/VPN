# PRD — Phase 6 Addendum: Anycast Edge & Autoscaling

| Field | Value |
|---|---|
| **Product** | Ferrum (Rust) |
| **Phase** | 6 of 6 — Scale & Acceleration (FR2 + FR3 drill-down) |
| **Status** | M1 (health/readiness + relay graceful drain) and M2 (relay registry & dynamic advertisement) implemented and live-verified (2026-07-12); M3 (GoAway + rolling relay deploy) and M4 (anycast health gate) implemented and verified in-process (2026-10-05; the netns and bird runs are in the Linux runbook); M5 (autoscaling templates) committed and CI-validated (2026-10-05; a live cloud run is external) |
| **Owner** | punarduttrajput |
| **Last updated** | 2026-10-05 |
| **Depends on** | [phase-6-scale-acceleration.md](phase-6-scale-acceleration.md) FR2/FR3/FR6; the Phase 4 relay (`RelayServer`, `crates/transport/src/relay.rs`); the Phase 3 coordinator (`ferrum-coordinator`) and its relay advertisement (`--relay` → `NetworkMapResponse.relay`); the Phase 6 FR4 metrics endpoints |

---

## 1. Summary

[phase-6-scale-acceleration.md](phase-6-scale-acceleration.md) FR2 calls for an
anycast-fronted edge (BGP announcement, health-aware withdrawal) and FR3 for
horizontal autoscaling of coordinators and relays (scale on load, zero-downtime
rolling deploys, graceful connection draining). Both are written as if the
fleet already exists; neither can be *fully* verified on this project's single
Linux development box — there is no BGP-capable provider, no PoP fleet, no
cloud orchestrator.

What **is** buildable and verifiable here is the software contract every one of
those infrastructure behaviors depends on, and that contract is currently
missing entirely:

- **No health signal.** Neither the relay nor the coordinator exposes a
  liveness or readiness endpoint. An anycast route-controller, load balancer,
  or orchestrator has nothing to probe; "health-aware withdrawal" (FR2) and
  rolling deploys (FR3) have no input signal.
- **No graceful drain.** `ferrum relay` dies on the first SIGTERM: every
  relayed session on it drops at once. "Drain connections gracefully on
  scale-in" (FR3) has no mechanism.
- **No dynamic relay advertisement.** The coordinator advertises one static
  `--relay` string fixed at process start (`CoordinatorService::with_relay`).
  A newly scaled-out relay can't enter service, and a draining/dead one can't
  leave it, without restarting the coordinator — which defeats both FR2's
  withdrawal and FR3's < 90 s scale-out target (parent NFR4).

This addendum specifies that contract as concrete, locally testable Rust
milestones (M1–M3), then layers the infrastructure pieces that consume it
(M4 anycast/BGP, M5 IaC/autoscaling) as committed configuration + documentation
whose full verification is explicitly marked **external** (needs real network
infrastructure), the same honesty rule the XDP addendum used for its ≥10 Gbps
NFR.

---

## 2. Goals & Non-Goals

### Goals
- G1. A **liveness/readiness surface** (`/healthz`, `/readyz`) on both the
  relay and the coordinator, served from the existing hand-rolled
  `--metrics-listen` HTTP endpoints (no new dependency, no new port).
- G2. **Graceful relay drain**: a draining relay immediately signals
  not-ready (so anycast/LB/coordinator stop steering new clients to it),
  refuses *new* client registrations, but keeps forwarding for its existing
  clients through a configurable grace window — zero mid-session drops caused
  by the drain itself.
- G3. **Dynamic relay advertisement**: relays announce themselves to the
  coordinator with a liveness heartbeat; the coordinator advertises a live,
  healthy relay in the network map and pushes changes over the existing
  `WatchNetworkMap` stream, so connected clients fail over without restart.
- G4. **Anycast integration as configuration**: a committed, documented BGP
  (bird2) health-gated announce/withdraw setup keyed on `/readyz`, so a real
  deployment is a config drop, not a design project.
- G5. Everything additive and opt-in: no flag given → both binaries behave
  exactly as today.

### Non-Goals
- ❌ Running our own BGP stack in Rust. Route announcement is the BGP
  daemon's job (bird2/FRR); Ferrum's job is the health signal that gates it.
- ❌ A cluster scheduler. Autoscaling *policies* target whatever orchestrator
  a deployment uses (systemd + cloud ASG, Nomad, k8s); Ferrum provides the
  metrics, health, and drain semantics they need.
- ❌ Coordinator multi-writer HA (shared PostgreSQL, leader election). The
  parent PRD names it; it is a separate work item with real schema
  consequences (`Store` is SQLite write-through today) and is out of scope
  for this addendum beyond documenting the boundary.
- ❌ DDoS mitigation (parent FR6) beyond what drain/health already give —
  separate addendum when reached.

---

## 3. Current state (what this builds on)

- **Relay** (`crates/transport/src/relay.rs`): `RelayServer` holds a live
  `key <-> addr` table (no expiry — entries persist until overwritten by a
  roam/reassign), forwards `Data` frames, and exposes `RelayMetrics`
  (Prometheus text) via `ferrum relay --metrics-listen`. Clients
  (`RelayMeshTransport`) re-register every 25 s (`KEEPALIVE`). The optional
  XDP fast path mirrors the table into kernel maps via `RelayXdpHook` —
  **any drain semantics must fire the same refusal on both paths** (a
  drained relay must not keep fast-pathing a *new* flow the userspace path
  would have refused; existing flows keep working on both paths by design).
- **Coordinator**: `--relay <addr>` → `CoordinatorService::with_relay` →
  `NetworkMapResponse.relay`, static for the process lifetime. Clients
  resolve local-override-else-advertised (`up-mesh`, `run_mesh_session`,
  FFI). `WatchNetworkMap` already pushes map changes live.
- **Data plane**: `run_mesh_relayed` + `tunnel::path`'s `PathMachine` already
  handle per-peer relay↔direct transitions; the Phase 5 supervisor
  (`run_mesh_session_supervised`) already rebuilds the whole session (and
  re-resolves the relay) with backoff on any drop. Client-side failover
  machinery therefore mostly exists — what's missing is the *signal* that a
  relay is going away.
- **Observability**: both binaries already serve `/metrics` from a tiny
  hand-rolled HTTP/1 listener (CLI `serve_relay_metrics`, coordinator
  `serve_metrics`); SLO alerting (including relay-forwarding burn rate) is
  live in `deploy/observability/`.

---

## 4. Functional Requirements

### FR1 — Health & readiness endpoints (M1)
- `GET /healthz` → `200 ok` while the process is serving (liveness).
- `GET /readyz` → `200 ready` normally; `503 draining` once drain begins
  (readiness). Bodies are constant strings — nothing user- or peer-derived
  ever appears (parent NFR5).
- Served by the **existing** `--metrics-listen` listeners on both the relay
  and the coordinator; no listener configured → no endpoints (unchanged
  default), and the relay/coordinator run exactly as today.
- This endpoint is the input for every downstream consumer: the M4 BGP
  health gate, an LB target-group check, an orchestrator's
  readiness/liveness probes, and the M2 coordinator heartbeat judgment.

### FR2 — Graceful relay drain (M1)
- `RelayServer::begin_drain()`: flips an atomic drain flag. While draining:
  - `/readyz` returns 503.
  - `Register` frames from **unknown keys are refused** (dropped + counted);
    re-registrations (keepalives) from already-registered keys are still
    honored, so existing sessions' NAT mappings stay fresh.
  - `Data` forwarding continues unchanged for registered clients.
- `ferrum relay`: first SIGTERM/Ctrl-C → `begin_drain()` + log, then keep
  serving for `--drain-grace <secs>` (default **20**; `0` = exit
  immediately, the pre-existing behavior). A second signal during the grace
  window exits immediately. Rationale for 20 s: an anycast health check at
  a typical 3 × 2 s fail threshold withdraws in ≤ 6 s, and the M2
  coordinator heartbeat judgment fits well inside it, leaving new
  connections nowhere to land while existing ones ride out the window.
- New aggregate metrics (NFR5-clean): `ferrum_relay_draining` (gauge 0/1),
  `ferrum_relay_registers_refused_total` (counter).

### FR3 — Relay registry & dynamic advertisement (M2) — ✅ implemented 2026-07-12
- **`RelayHeartbeat` RPC** (`coordinator.proto`): a relay announces its
  client-reachable `addr` and heartbeats at the coordinator-directed cadence
  (`interval_secs`, currently 15 s); `draining: true` is the goodbye. The RPC
  is authenticated exactly like every other (`ferrum relay --token-file` for
  OIDC-protected coordinators).
- **Coordinator relay registry** (`service.rs`): live entries expire after a
  45 s TTL (3 missed beats) — enforced lazily at map-build time and by a
  5 s **sweeper task** (`spawn_relay_sweeper`, spawned automatically when no
  static `--relay` is given) that also pushes a fresh map to watchers when
  the passage of time alone changed the advertisement. Selection is
  **stable**: the earliest-joined live relay is advertised; a newly
  scaled-out relay takes over only when the current one drains or dies.
  (Known cosmetic quirk: the sweeper's change detection lags the heartbeat
  handler's by one tick, so one redundant identical map push can follow a
  relay's arrival — clients treat it as a no-op.)
- `NetworkMapResponse.relay` is now the currently-selected live relay;
  changes push over `WatchNetworkMap`. The client session (no local
  override) **tracks** the advertised relay via the new
  `NetworkMapStream::next_update()` and, on a retarget, ends with a
  restartable error so the supervisor rebuilds it against the new relay.
  (In-place underlay retargeting without a session restart was considered
  and deferred to M3 alongside `GOAWAY` — the supervised restart is the same
  path every other drop takes, and peers simply re-handshake.)
- Static `--relay` remains a fixed override with unchanged semantics; it
  disables the registry entirely.
- Scale-out acceptance **met**: in-process test asserts a watcher learns a
  newly heartbeating relay within seconds (NFR-A3 « 90 s), and the live
  two-relay run confirmed announce → advertise ≈ 1 s and goodbye →
  withdrawal push ≈ 3 ms.

### FR4 — Client drain handling & zero-drop rolling deploy (M3)
- **Primary path (M2, unchanged):** the draining relay's goodbye withdraws it
  from the coordinator's advertisement, the new map is pushed over
  `WatchNetworkMap`, and the client session restarts onto the replacement.
- **Fallback: a relay→client `GoAway` frame**, one byte, tag **`0x05`**
  (`0x03`/`0x04` were already taken by the SEC challenge/response). The relay
  sends it to every registered client when the drain starts
  (`RelayServer::announce_goaway`, called by `ferrum relay` right after
  `begin_drain`) and again in reply to any keepalive during the drain, in case
  the first was lost. Only the relay's own address can deliver it. Clients
  from before it ignore unknown tags, so it's backward-compatible.
- **The client never restarts on the GoAway alone.** It re-reads the advertised
  relay every 500 ms (for up to 30 s) and restarts only once the
  advertisement names a *different* relay. Restarting earlier would rebuild
  the session against the same draining relay, which refuses new
  registrations. A failed lookup counts as "not yet". With a local
  `transport.relay` override there's nothing to move to, so the GoAway is
  only logged. This covers a missed watch push (a stream that was
  reconnecting when the goodbye landed).
- Acceptance: two meshed peers whose only path is the relay; roll it (start
  replacement → drain old + GoAway + goodbye → stop old) → **no session
  dropped, no outage longer than one supervised restart**.
- **Verified in-process (2026-10-05)** by
  `rolling_relay_deploy_drops_no_session` (`ferrum-client-core`,
  `data-plane`): real relays, a real coordinator, two supervised sessions with
  an unreachable direct endpoint, a numbered packet every 20 ms. Across the
  roll: 1–2 packets lost, longest gap ≈ 65 ms (asserted < 3 s), the
  replacement relay carries both clients, both supervisors stay Connected.
  Unit tests cover the GoAway follow-up's safety rules (restart only on a
  changed advertisement; never onto the same relay; failed lookups are "not
  yet"; nothing before the GoAway). The real-process netns run is
  [runbook §7](../docs/linux-verification-runbook.md#7-rolling-relay-deploy-anycast-m3).

### FR5 — Anycast/BGP health gate (M4)
- Committed `deploy/anycast/` (bird2 config template + a health-gate unit
  that polls `/readyz` and enables/disables the announced prefix, + README):
  a PoP announces the anycast prefix only while its relay is ready.
- Local verification: config syntax (`bird -p`) + the health-gate logic
  against a real draining relay. **External (documented, not claimed):**
  real BGP announcement/withdrawal convergence and the parent NFR2
  (< 20 ms RTT for 90% of users) — needs a provider and a fleet.
- **As built (2026-10-05):** the gate is a `ferrum anycast-gate`
  subcommand (`crates/cli/src/anycast_gate.rs`), not a script, so it's
  tested against a real relay in-process. It runs `birdc enable|disable` on
  the static protocols carrying the prefix (they start `disabled yes`):
  announce after 3 ready probes 2 s apart, withdraw **at once on a 503**,
  after 3 failed probes, on start and on exit (a systemd `ExecStopPost`
  covers a crash). A `birdc` reply must confirm the new state; failures are
  retried, and the decision is re-applied every 30 s because a restarted
  bird comes back disabled. Files: `bird.conf`, `ferrum-relay.service`,
  `ferrum-anycast-gate.service`, `README.md`.
- **Anycast relays and the registry.** The relay registry (FR3) was keyed by
  client-facing address, so PoPs sharing the anycast address would share one
  entry, and one PoP's drain goodbye would withdraw it for all. Since relay
  mesh M2 ([relay-mesh.md](relay-mesh.md)) a relay with a mesh address is
  keyed by that instead, so meshed anycast relays can heartbeat normally.
  Unmeshed anycast relays still shouldn't: the coordinator then advertises
  the anycast address statically (`--relay`).
- **Faster re-registration after a GoAway.** Behind an anycast address, a
  client whose traffic moves to another PoP isn't registered there until its
  next keepalive, up to 25 s later. After a GoAway the client now
  re-registers every 1 s for 30 s (`GOAWAY_KEEPALIVE`), so it's registered
  at the next PoP about a second after the route moves. Refreshes cost the
  relay no rate-limit budget. The relay must also bind the anycast address
  itself, so replies come from the address clients sent to.
- **Multi-PoP needs relay-to-relay forwarding.** A relay forwards only
  between clients registered on itself, so peers on different PoPs couldn't
  relay to each other. The relay mesh ([relay-mesh.md](relay-mesh.md), M1
  2026-10-05) fixes that with static membership: mesh the PoPs and several
  can be ready at once. Without the mesh, anycast is correct only with one
  ready PoP (active/standby). The same applies to a scaled-out pool (M5).

### FR6 — Autoscaling policies & IaC (M5)
- Scaling signals from existing metrics (`ferrum_relay_clients_registered`,
  `ferrum_relay_bytes_forwarded_total` rate, coordinator RPC latency SLI) +
  the FR1 probes + the FR2 drain lifecycle = everything an ASG/orchestrator
  needs; committed as documented policy templates alongside Terraform/
  Ansible skeletons (parent FR5). **External:** live scale-out/-in against
  a real cloud; NFR4 is *pre*-verified in-process by FR3's acceptance.
- **As built (2026-10-05):** waited on the relay mesh ([relay-mesh.md](relay-mesh.md)),
  since a scaled-out pool behind a load balancer can put two peers on
  different relays. Then, on Oracle Cloud (the owner's platform):
  `deploy/autoscaling/terraform/oci-relay-pool/` is an instance pool behind
  a UDP network load balancer (health check = `/readyz`, source address
  preserved, two-tuple hashing), OCI autoscaling on CPU (OCI pools scale
  natively on CPU or memory only), a security group (clients UDP 51821,
  mesh UDP 51822 between relays only, probes TCP 9101 from the VCN), and a
  cloud-init template that installs the pinned binary (SHA-256 checked) and
  runs a meshed relay announcing the NLB address to the coordinator.
  `deploy/observability/prometheus/rules/relay_scaling.yml` records pool
  clients, throughput and ready count and raises `FerrumRelayPoolScaleOut`,
  `…ScaleIn` (not below two) and `…NoReadyRelay`; a draining relay's
  clients count against the ready ones. `deploy/ansible/` (role
  `ferrum_relay`) configures relays on fixed hosts. A new "Deploy templates"
  workflow checks `terraform fmt/validate`, the rendered cloud-init against
  `cloud-init schema`, the Ansible syntax and rendered unit
  (`systemd-analyze verify`), and `bird -p` on the anycast config; the
  observability job runs the scaling rules' promtool tests. **External:**
  `terraform apply`, the NLB's UDP behaviour, scale-out time against NFR4,
  and whether OCI scale-in shuts instances down cleanly (so they drain).

---

## 5. Non-Functional Requirements

| ID | Requirement | Target | Verifiable here? |
|---|---|---|---|
| NFR-A1 | Drain data-plane impact | Zero drops attributable to drain within the grace window | ✅ netns/in-process |
| NFR-A2 | Readiness propagation | `/readyz` flips within 1 poll interval of `begin_drain()` | ✅ in-process |
| NFR-A3 | Scale-out reaction (parent NFR4) | New relay advertised & serving < 90 s | ✅ in-process/netns |
| NFR-A4 | Privacy (parent NFR5) | Health/heartbeat surfaces carry zero user/peer identity | ✅ tests + constant bodies |
| NFR-A5 | Anycast entry RTT (parent NFR2) | Nearest-PoP; < 20 ms p90 | ❌ external (fleet) |
| NFR-A6 | Deploy safety (parent NFR6) | Rolling relay deploy, zero dropped sessions | ✅ netns (M3) |

---

## 6. Milestones

1. **M1 — Health/readiness + graceful relay drain** ✅ *(2026-07-12)*:
   FR1 + FR2; unit + integration tests (drain refuses new keys, keeps
   existing flows, metrics/endpoints correct) + live probe/drain run.
2. **M2 — Relay registry & dynamic advertisement** ✅ *(2026-07-12)*: FR3;
   heartbeat RPC, TTL/sweeper withdrawal, stable selection, live watch push,
   client retarget-restart, < 90 s scale-out test + live two-relay
   handover run.
3. **M3 — Client drain handling + rolling-deploy verification** ✅
   *(2026-10-05, in-process)*: FR4; GoAway (`0x05`) as a fallback to the
   M2 goodbye, in-process zero-drop roll test; netns run in the Linux
   runbook §7.
4. **M4 — Anycast/BGP health gate** ✅ *(2026-10-05, in-process)*: FR5;
   `deploy/anycast/` + `ferrum anycast-gate`, gate verified against a real
   draining relay; the real-bird run is in the Linux runbook §8; BGP
   convergence documented as external.
5. **M5 — Autoscaling policies + IaC** ✅ *(2026-10-05, CI-validated)*:
   FR6; OCI relay pool module, Prometheus scaling rules, Ansible relay role,
   Deploy templates workflow; cloud verification external.

---

## 7. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Drain refuses a *roaming existing* client (its keepalive arrives from a new addr, looking like a new key→addr pair) | A NATted client that rebinds mid-drain loses the relay | Refusal keys on **unknown key**, not unknown addr — a roam re-registers a known key and stays honored |
| XDP fast path keeps serving a flow userspace would refuse | Drain semantics diverge between paths | New flows only enter the XDP maps via `RelayXdpHook::on_register`, which fires only after userspace *accepts* a registration — refusal upstream starves both paths identically; test in M1 |
| Coordinator advertises a relay that just died between heartbeats | Clients briefly steered at a dead relay | Client supervisor + path machine already retry/fail over; heartbeat interval × K bounds the window; M2 tunes constants |
| Anycast flow-shift breaks long UDP flows on route change | Mid-session relay swap | Relay is stateless per-frame and clients re-register on the new node (keepalive), same as a roam — document; verified logically in netns (M3) |
| Health endpoint leaks state (NFR5) | Privacy regression | Constant-string bodies; no counts, no addrs, no keys in `/healthz`/`/readyz` |

---

## 8. Outcome

After M1–M3, a Ferrum deployment can be rolled, scaled out, and scaled in
without dropping user sessions, and exposes the exact health surface anycast
routing and autoscalers consume — all tested on this box. M4–M5 make the
remaining infrastructure work a matter of applying committed configuration,
with the externally-verifiable claims (BGP convergence, p90 RTT, live cloud
scaling) explicitly left unclaimed until a real fleet exists.
