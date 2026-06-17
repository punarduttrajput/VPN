# Next-Gen VPN — Phase 1 (MVP Encrypted Tunnel)

A Rust, WireGuard-based point-to-point tunnel. This is Phase 1 of the
[6-phase roadmap](PRD/); see [STATUS.md](STATUS.md) for progress.

## Workspace

| Crate | Role |
|-------|------|
| [`vpn-core`](crates/core) | Keys, config, errors — `#![forbid(unsafe_code)]` foundation |
| [`vpn-transport`](crates/transport) | `Transport` trait + UDP and QUIC (`quic` feature) implementations (Phase 2) |
| [`vpn-tunnel`](crates/tunnel) | boringtun session, TUN device trait, transport-generic async event loop |
| [`vpn-cli`](crates/cli) | `vpn` binary: `keygen`, `up` |
| [`vpn-control-proto`](crates/control-proto) | gRPC coordinator service contract (Phase 3) |
| [`vpn-coordinator`](crates/coordinator) | Control-plane coordinator: device registry, IP allocation, network map, ACL policy (Phase 3) |
| [`vpn-client-core`](crates/client-core) | Client control integration: register with the coordinator, build a tunnel plan from the network map (Phase 3) |

### Optional features

- `quic` (on `vpn-cli`/`vpn-tunnel`/`vpn-transport`) — build the QUIC datagram transport (quinn + ring-backed rustls). Test it with `cargo test --workspace --features vpn-cli/quic`.
- `masque` — MASQUE CONNECT-UDP over HTTP/3 (RFC 9298): `MasqueTransport` client + `MasqueProxy` relay. Test with `cargo test --workspace --features vpn-cli/masque`.
- `real-tun` (on `vpn-tunnel`) — the real OS TUN device (Linux/macOS).

## Build & test

```sh
cargo build            # data plane + CLI (no OS driver needed)
cargo test             # crypto, config, handshake, loopback
cargo clippy --all-targets
```

> The crates.io-offline override `CARGO_NET_OFFLINE=false` may be needed on this
> machine (a global `~/.cargo/config.toml` sets `offline = true`).

### Real TUN device (Linux/macOS only)

The OS interface is gated behind the `real-tun` feature (Phase 1 scope):

```sh
cargo build --features vpn-tunnel/real-tun        # on Linux/macOS
sudo ./target/debug/vpn up --config config.toml   # needs privileges
```

On other hosts (e.g. Windows) the device path returns `UnsupportedPlatform`;
all crypto/transport logic still builds and is fully tested in-process.

## Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push / PR:

- **test** — `rustfmt --check`, `clippy -D warnings`, build, and `cargo test`
  on both `ubuntu-latest` and `windows-latest`.
- **verify-linux** — installs `iproute2` + `iperf3` and runs
  [`scripts/verify-linux.sh`](scripts/verify-linux.sh) (M3 / M5 / M6) on a Linux runner.

## Usage

```sh
vpn keygen                          # generate a keypair for each peer
vpn up --config config.example.toml # bring up the tunnel (Linux/macOS)
```

### Transport selection (Phase 2)

The `[transport]` block selects how the encrypted tunnel is carried:

```toml
[transport]
mode = "quic"        # "udp" (default) or "quic"
role = "client"      # quic only: one peer "server" (accepts), one "client"
server_name = "vpn"  # quic only: TLS SNI (peer identity is via WireGuard)
```

QUIC requires building with the feature: `cargo build --features vpn-cli/quic`.
See [config.quic.example.toml](config.quic.example.toml). Omitting `[transport]`
keeps plain UDP (Phase 1 behavior).

**Padding (obfuscation, FR5):** add `padding = true` (optionally `pad_to = 1280`)
to `[transport]` to normalize datagram sizes against fingerprinting. Both peers
must set the same values; works with either UDP or QUIC.
