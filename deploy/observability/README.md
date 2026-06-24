# Ferrum observability stack (Phase 6 FR4)

A reproducible local/dev observability stack for the Ferrum control plane:

| Service | Role | URL |
|---------|------|-----|
| **Prometheus** | Scrapes the coordinator + relay `/metrics` | http://localhost:9090 |
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
  --otlp-endpoint http://localhost:4317

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
- Dashboards and alert rules are provisioned from files, so they're versioned in
  git and reproducible. Alerting (SLO rules) is a follow-up on top of this stack.
