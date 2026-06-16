# PRD — Phase 6: Scale, Acceleration & Observability

| Field | Value |
|---|---|
| **Product** | Next-Gen VPN (Rust) |
| **Phase** | 6 of 6 — Production Scale |
| **Status** | Draft |
| **Owner** | punarr@plasmacomp.com |
| **Last updated** | 2026-06-16 |
| **Depends on** | Phases 1–5 |

---

## 1. Summary

Harden the platform for production scale and peak performance. Accelerate relay and
gateway packet processing with **eBPF/XDP** (via `aya`) to reach line-rate
throughput, front the edge with **anycast** routing for lowest-latency entry,
build full **observability** (metrics, traces, alerting) that respects the no-logs
promise, and put the infrastructure under **IaC** with autoscaling and resilience.
This phase turns a working VPN into a dependable service.

---

## 2. Goals & Non-Goals

### Goals
- G1. eBPF/XDP fast path for relays/gateways — line-rate packet forwarding (`aya`).
- G2. Anycast edge so clients reach the nearest entry node automatically.
- G3. Horizontal autoscaling of coordinators and relays under load.
- G4. Observability: Prometheus metrics, OpenTelemetry traces, Grafana dashboards, alerting.
- G5. Infrastructure-as-code (Terraform + Ansible) and reproducible, automated deploys.
- G6. Resilience: health checks, graceful failover, capacity planning, DDoS mitigation.

### Non-Goals
- ❌ New end-user features (the product surface is set by Phases 1–5).
- ❌ Changing the protocol or client architecture.
- ❌ Logging user traffic — observability is infra/health metrics only.

---

## 3. Background & Rationale

Userspace forwarding caps out well below NIC line rate; eBPF/XDP processes packets
in the kernel before the network stack, unlocking 10–100 Gbps-class forwarding on
commodity hardware. Anycast lets one IP route to many regional nodes, minimizing
entry latency and aiding DDoS absorption. At scale, you cannot operate blind:
metrics and traces are essential — but they must be strictly infrastructure-level
to preserve the privacy guarantee that defines the product. IaC makes the whole
fleet reproducible and auditable.

---

## 4. Users & Use Case

- **Primary users:** SRE/operations team; end users benefit indirectly via speed & reliability.
- **Use case:** Traffic surges in a region; autoscaling spins up relays, anycast steers
  users to the nearest healthy node, eBPF/XDP keeps per-node throughput high, and
  dashboards/alerts let SRE see capacity and failures in real time — all without any
  visibility into user traffic content.

---

## 5. Functional Requirements

### FR1 — eBPF/XDP Acceleration
- XDP program (via `aya`) on relays/gateways for fast-path encrypted-packet forwarding.
- Userspace fallback for packets the XDP path doesn't handle.
- Benchmark vs. Phase 4 userspace relay; document throughput/CPU gains.

### FR2 — Anycast Edge
- Announce anycast prefixes (BGP) across regional points of presence.
- Health-aware withdrawal of unhealthy nodes from anycast.
- Clients resolve to nearest entry transparently; integrates with relay selection.

### FR3 — Autoscaling & Orchestration
- Coordinators scale horizontally (stateless where possible; shared PostgreSQL/cache).
- Relays autoscale on connection/bandwidth metrics.
- Rolling, zero-downtime deploys; drain connections gracefully on scale-in.

### FR4 — Observability (privacy-preserving)
- Prometheus metrics: throughput, connections, handshake rates, relay vs direct ratio,
  CPU/mem, error rates — **no per-user traffic content or destinations**.
- OpenTelemetry tracing across coordinator/relay request paths.
- Grafana dashboards + alerting (SLO-based) for latency, errors, capacity.
- Structured `tracing` logs scrubbed of any sensitive data.

### FR5 — Infrastructure-as-Code
- Terraform for cloud/edge provisioning; Ansible for node configuration.
- Reproducible relay/coordinator images; pinned, auditable builds.
- Secrets management; least-privilege node roles.

### FR6 — Resilience & Security Hardening
- Liveness/readiness health checks feeding anycast + LB.
- DDoS mitigation at the edge (rate limiting, SYN/UDP flood protection).
- Graceful failover; capacity/load testing to defined headroom targets.

---

## 6. Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR1 | Relay throughput (XDP) | ≥ 10 Gbps per node forwarding |
| NFR2 | Entry latency (anycast) | Nearest-PoP RTT; < 20 ms for 90% of users |
| NFR3 | Availability | 99.95% monthly for the service |
| NFR4 | Scale-out reaction | New capacity serving traffic < 90 s |
| NFR5 | Privacy | Zero user-traffic data in any metric/log/trace |
| NFR6 | Deploy safety | Zero-downtime rolling deploys; automated rollback |

---

## 7. Architecture

```
        Clients ──► Anycast IP (BGP) ──► nearest healthy PoP
                                               │
                  ┌────────────────────────────┼────────────────────────────┐
                  ▼                             ▼                            ▼
            ┌───────────┐               ┌───────────┐               ┌───────────┐
            │  Relay PoP │  …            │ Relay PoP │  …            │ Coordinator│
            │ eBPF/XDP   │               │ eBPF/XDP  │               │  (autoscaled)│
            └─────┬─────┘               └─────┬─────┘               └─────┬─────┘
                  └───────────► Metrics/Traces (Prometheus + OTel) ◄──────┘
                                      │
                                ┌─────▼─────┐
                                │  Grafana  │  dashboards + SLO alerting
                                └───────────┘
         All managed by Terraform + Ansible (IaC).  No traffic content collected.
```

### Components
- `crates/relay` — extended with `aya`/XDP fast path.
- `crates/coordinator` — autoscaling/observability hooks.
- `infra/` — Terraform + Ansible; dashboards; alerting rules.

### Key dependencies
`aya` (eBPF), Prometheus, OpenTelemetry, Grafana, Terraform, Ansible; Phase 1–5 crates.

---

## 8. Milestones

1. **M1** — Observability baseline: metrics, traces, dashboards, alerts (privacy-scrubbed).
2. **M2** — IaC: Terraform + Ansible provisioning of coordinators & relays.
3. **M3** — Autoscaling + zero-downtime rolling deploys with connection draining.
4. **M4** — eBPF/XDP relay fast path + throughput benchmark vs userspace.
5. **M5** — Anycast edge with health-aware route withdrawal.
6. **M6** — DDoS mitigation, failover drills, capacity/load test to NFR targets.

---

## 9. Acceptance Criteria

- ✅ XDP relay sustains NFR1 throughput; documented gain over Phase 4 userspace.
- ✅ Clients route to nearest healthy PoP via anycast (NFR2); unhealthy nodes withdraw.
- ✅ Load surge triggers autoscaling serving traffic within NFR4.
- ✅ Rolling deploy completes with zero dropped sessions; rollback verified.
- ✅ Dashboards/alerts cover SLOs; an injected fault fires the right alert.
- ✅ Audit confirms no user-traffic data exists in any metric, log, or trace (NFR5).

---

## 10. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| eBPF/XDP complexity & kernel/NIC variance | Delays, instability | Prototype on target kernels/NICs early; always keep userspace fallback |
| Anycast/BGP operational complexity | Routing incidents | Partner with anycast-capable provider; staged rollout per region |
| Observability leaks sensitive data | Privacy breach | Strict metric/label allowlist; audits; scrub at source |
| Autoscaling thrash | Cost/instability | Tuned thresholds + cooldowns; load-test scaling policies |
| Edge DDoS | Outage | Upstream scrubbing + edge rate limiting; capacity headroom |

---

## 11. Outcome

With Phase 6 complete, the VPN is a production-grade, privacy-preserving service:
fast (line-rate, anycast-fronted), resilient (autoscaled, self-healing), and
observable — without ever compromising the no-logs guarantee established in Phase 1.
This closes the 6-phase roadmap from MVP tunnel to next-gen VPN.
