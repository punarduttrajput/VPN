# Ferrum observability stack (Phase 6 FR4)

A reproducible local/dev observability stack for the Ferrum control plane:

| Service | Role | URL |
|---------|------|-----|
| **Prometheus** | Scrapes the coordinator + relay `/metrics`; evaluates SLO rules | http://localhost:9090 |
| **Alertmanager** | Routes/dedupes fired SLO alerts | http://localhost:9093 |
| **Grafana** | Dashboards over Prometheus + Jaeger (pre-provisioned) | http://localhost:3000 |
| **Jaeger** | Receives OTLP spans from `--otlp-endpoint` | http://localhost:16686 |

This is the **FR4 deliverable**: metrics + traces + dashboards, all
privacy-preserving. The only telemetry that reaches this stack is the aggregate,
label-free metrics and the `skip_all` spans the services already emit — **no
per-user traffic, keys, IPs, or destinations** (NFR5).

## Run it

```sh
docker compose -f deploy/observability/docker-compose.yml up -d
```

Grafana opens on http://localhost:3000 with anonymous read-only access; the
**Ferrum — Control Plane Overview** dashboard (folder *Ferrum*) is provisioned
automatically. Log in as `admin` / `admin` to edit.

## Feed it data

Run the coordinator and/or relay with their metrics (and optionally OTLP) endpoints:

```sh
# Coordinator: metrics on :9095, traces to Jaeger
cargo run -p ferrum-coordinator --features otlp -- \
  --listen 0.0.0.0:50051 \
  --metrics-listen 0.0.0.0:9095 \
  --otlp-endpoint http://localhost:4317 \
  --insecure-no-auth   # local only; use the --oidc-* flags in a real deployment

# Relay: metrics on :9096, traces to Jaeger
cargo run -p ferrum-cli --features otlp --bin ferrum -- relay \
  --listen 0.0.0.0:51821 \
  --metrics-listen 0.0.0.0:9096 \
  --otlp-endpoint http://localhost:4317
```

(The `otlp` feature is only needed for span export; `--metrics-listen` works on a
default build.)

By default Prometheus scrapes `host.docker.internal:9095` / `:9096` — i.e. the
coordinator/relay running **on the host**. This resolves to the host on Docker
Desktop and standard Linux (via the `host-gateway` mapping in the compose file).

### Containerized deployment

When the coordinator/relay run as containers, attach them to the
`ferrum-observability` network and point the scrape jobs at their service names
instead of `host.docker.internal` — e.g. in [prometheus/prometheus.yml](prometheus/prometheus.yml):

```yaml
    static_configs:
      - targets: ["coordinator:9095"]
```

## What's scraped

Coordinator (`ferrum_*`) and relay (`ferrum_relay_*`) expose aggregate counters
and gauges only — see the module docs in `crates/coordinator/src/metrics.rs` and
`crates/transport/src/relay.rs`. Key series:

- `ferrum_devices_registered`, `ferrum_watch_streams_active`
- `ferrum_register_total`, `ferrum_network_map_requests_total`,
  `ferrum_rotate_key_total`, `ferrum_publish_candidates_total`,
  `ferrum_unauthenticated_total`
- `ferrum_relay_clients_registered`, `ferrum_relay_frames_forwarded_total`,
  `ferrum_relay_bytes_forwarded_total`, `ferrum_relay_frames_dropped_total`

## SLO-based alerting

Prometheus loads SLO recording + alerting rules from
[prometheus/rules/](prometheus/rules/) and ships fired alerts to **Alertmanager**.

**SLOs** (measured from the existing aggregate metrics — NFR5):

| SLO | Target | Error budget | SLI |
|-----|--------|--------------|-----|
| Control-plane availability | 99.95% (NFR3) | 0.05% | `1 - avg(up)` per job |
| Relay forwarding success | 99% | 1% | `dropped / (forwarded + dropped)` |
| Coordinator latency | 99% of RPCs < 100 ms | 1% | `1 - bucket{le="0.1"} / count` |

All use **multi-window, multi-burn-rate** alerts (Google SRE Workbook): each
alert ANDs a long and a short window so it pages fast on a hard outage but won't
flap on a blip, and auto-resolves on recovery.

| Tier | Burn rate | Windows | Severity |
|------|-----------|---------|----------|
| Fast page | 14.4× | 1h & 5m | critical |
| Slow page | 6× | 6h & 30m | critical |
| Ticket | 1× | 3d & 6h | warning |

Plus operational alerts: `FerrumCoordinatorDown` / `FerrumRelayDown` /
`FerrumTargetMissing` (hard availability), `FerrumCoordinatorIPPoolNearExhaustion`
/ `FerrumCoordinatorWatchStreamsHigh` / `FerrumRelayClientsHigh` (capacity), and
`FerrumCoordinatorAuthRejectionSpike` (security).

Alertmanager ([alertmanager/alertmanager.yml](alertmanager/alertmanager.yml))
routes `severity: critical` to a `pager` receiver and `warning` to `default`.
Both receivers ship **without** an external integration so the stack runs with no
secrets — plug in Slack/PagerDuty/email/a webhook where the comments mark.

The **coordinator latency SLO** is measured from the
`ferrum_request_duration_seconds` histogram (a `RequestTimer` RAII guard records
every RPC handler's duration; aggregate-only, no per-user labels per NFR5): the
SLI is the share of RPCs slower than 100 ms (`1 - bucket{le="0.1"} / count`),
with the same three burn-rate tiers and `slo: coordinator-latency`.

### Test the rules

The alert rules have **promtool unit tests** that prove each alert fires on its
condition (and stays quiet when healthy) without waiting for real `for` windows —
also run in CI (the `observability` job):

```sh
docker run --rm --entrypoint promtool -v "$PWD/deploy/observability":/work \
  prom/prometheus:v2.54.1 test rules /work/prometheus/tests/slo_tests.yml
```

To see an alert fire live, start the coordinator with `--metrics-listen`, let
Prometheus scrape it (target `up`), then stop it: after ~2m `FerrumCoordinatorDown`
moves to *firing* (Prometheus → Status → Alerts) and appears in Alertmanager.

## Tear down

```sh
docker compose -f deploy/observability/docker-compose.yml down        # keep data
docker compose -f deploy/observability/docker-compose.yml down -v      # wipe volumes
```

## Notes

- **WSL2 + native Docker:** `host-gateway` resolves to the *WSL* host, not the
  Windows host. If the coordinator runs as a Windows binary, point Prometheus at
  the WSL2 VM gateway IP (`ip route | grep default`) via a local
  `docker-compose.override.yml` that remaps `extra_hosts`. This file is intended
  for the portable Docker-Desktop/Linux path.
- **Privacy:** metrics are aggregate-only and spans are `skip_all` (NFR5), so
  nothing scraped or traced here identifies a device or user. Keep it that way
  when adding metrics: see the [threat model](../../docs/security/threat-model.md) §3.4.
- Dashboards and alert rules are provisioned from files, so they're versioned in
  git and reproducible. Alerting (SLO rules) is a follow-up on top of this stack.
