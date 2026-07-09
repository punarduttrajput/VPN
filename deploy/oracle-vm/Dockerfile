# Builds ferrum-coordinator (admin-api + sqlite features) and the ferrum CLI
# (used here to run `ferrum relay`) into one image. Build this ON the target
# host (e.g. `docker compose build` on the Oracle Ampere A1 VM itself) rather
# than cross-building elsewhere — plain `cargo build` targets whatever
# architecture it's run on, no cross-compilation toolchain needed either way.
#
# Only the library workspace (crates/) is needed here — apps/desktop is its
# own excluded workspace with heavy webview deps this image never touches.

FROM rust:1.85-bookworm AS builder
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Separate invocations: combining -p and --bin in one `cargo build` scopes
# --bin across *all* selected packages, so ferrum-coordinator's own binary
# would silently never get built (it has no bin literally named "ferrum").
# real-tun: the dns-node service runs `ferrum up-mesh` with a real TUN device
# (PRD leak-protection.md M4); the relay doesn't care either way.
RUN cargo build --release -p ferrum-coordinator --features admin-api,sqlite
RUN cargo build --release -p ferrum-cli --bin ferrum --features ferrum-tunnel/real-tun

FROM debian:bookworm-slim
# dnsmasq: the in-mesh resolver (PRD leak-protection.md M4) — the `resolver`
# service runs it from this same image, sharing the dns-node's network
# namespace so it answers DNS at the node's tunnel address.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates dnsmasq \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/ferrum-coordinator /usr/local/bin/ferrum-coordinator
COPY --from=builder /build/target/release/ferrum /usr/local/bin/ferrum

# Coordinator: 50051/tcp gRPC, 9090/tcp admin API+panel (proxied by Caddy, not
# published directly), 9095/tcp metrics (matches deploy/observability's
# expected scrape port). Relay: 51821/udp data, 9096/tcp metrics.
EXPOSE 50051 9090 9095 51821/udp 9096

RUN useradd -r -u 10001 ferrum
USER ferrum
