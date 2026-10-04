# SEC-006 — No rate limiting / quotas on the coordinator

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M3 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR6 |
| **Area** | `ferrum-coordinator` |

## Problem

`register_device`, `watch_network_map`, and `RelayHeartbeat` have no visible
per-identity/per-source rate limits or connection quotas. A single client can
open unbounded watch streams or spam registrations — a resourcing/DoS gap that
commercial VPN control planes handle at the edge.

## Acceptance criteria

- [x] Per-identity and per-source rate limits on `register_device` and
      `RelayHeartbeat`. *(Token buckets in `limits.rs`. Per-source runs before
      authentication, per-identity (`oidc:`/`mtls:`) after. IPv6 sources keyed
      by /64.)*
- [x] A cap on concurrent `watch_network_map` streams per identity/source.
      *(Plus a global cap. A disconnect now frees its slot immediately.)*
- [x] Rejections use a clear `resource_exhausted` status.
- [x] Aggregate-only metrics for throttled/rejected counts (no per-user labels —
      NFR5); `tracing_privacy` integration test still passes.
      *(`ferrum_register_throttled_total`, `ferrum_relay_heartbeat_throttled_total`,
      `ferrum_watch_streams_rejected_total`, plus a `FerrumCoordinatorThrottlingSpike` alert.)*
- [x] Test: a registration flood and an excess-stream case are throttled.

## Implementation notes

- A token-bucket keyed by identity (authenticated) or source IP (open mode),
  behind the existing `Mutex`-guarded state or a dedicated limiter.
- The active-streams gauge already exists (`watch_started`); add an enforced cap
  alongside the metric.
- Keep it aggregate-only to preserve NFR5 (the review flagged the privacy
  posture as a selling point — don't regress it).
