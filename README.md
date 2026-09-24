# Ferrum — a Rust, WireGuard-based VPN

A Rust, WireGuard-based VPN: encrypted tunnel + pluggable transports
(UDP/QUIC/MASQUE) + a gRPC control plane + a multi-peer mesh data plane.
Built to a [6-phase roadmap](PRD/); Phases 1–3 are functionally complete and
the mesh covers much of Phase 4. See [STATUS.md](STATUS.md) for dated progress
and [CLAUDE.md](CLAUDE.md) for agent/developer context (build, conventions,
architecture, environment notes).

## Workspace

| Crate | Role |
|-------|------|
| [`ferrum-core`](crates/core) | Keys, config, errors — `#![forbid(unsafe_code)]` foundation |
| [`ferrum-transport`](crates/transport) | `Transport` trait + UDP and QUIC (`quic` feature) implementations (Phase 2) |
| [`ferrum-tunnel`](crates/tunnel) | boringtun session, TUN device trait, transport-generic async event loop |
| [`ferrum-cli`](crates/cli) | `ferrum` binary: `keygen`, `up` |
| [`ferrum-control-proto`](crates/control-proto) | gRPC coordinator service contract (Phase 3) |
| [`ferrum-coordinator`](crates/coordinator) | Control-plane coordinator: device registry, IP allocation, network map, ACL policy (Phase 3) |
| [`ferrum-client-core`](crates/client-core) | Client control integration: register with the coordinator, build a tunnel plan from the network map (Phase 3) |

### Optional features

- `quic` (on `ferrum-cli`/`ferrum-tunnel`/`ferrum-transport`) — build the QUIC datagram transport (quinn + ring-backed rustls). Test it with `cargo test --workspace --features ferrum-cli/quic`.
- `masque` — MASQUE CONNECT-UDP over HTTP/3 (RFC 9298): `MasqueTransport` client + `MasqueProxy` relay. Test with `cargo test --workspace --features ferrum-cli/masque`.
- `real-tun` (on `ferrum-tunnel`) — the real OS TUN device (Linux/macOS).
- `sqlite` (on `ferrum-coordinator`) — durable device persistence via bundled SQLite (`--store <path>`).
- `mtls` (on `ferrum-coordinator` / `ferrum-client-core`) — mutual TLS on the gRPC channel (`--tls-cert/--tls-key/--tls-ca`; `ControlClient::connect_mtls`).

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
cargo build --features ferrum-tunnel/real-tun        # on Linux/macOS
sudo ./target/debug/ferrum up --config config.toml   # needs privileges
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
ferrum keygen                          # generate a keypair for each peer
ferrum up --config config.example.toml # bring up the tunnel (Linux/macOS)
```

### Transport selection (Phase 2)

The `[transport]` block selects how the encrypted tunnel is carried:

```toml
[transport]
mode = "quic"        # "udp" (default) or "quic"
role = "client"      # quic only: one peer "server" (accepts), one "client"
server_name = "ferrum"  # quic only: TLS SNI (peer identity is via WireGuard)
```

QUIC requires building with the feature: `cargo build --features ferrum-cli/quic`.
See [config.quic.example.toml](config.quic.example.toml). Omitting `[transport]`
keeps plain UDP (Phase 1 behavior).

**Certificate pinning (SEC-004):** QUIC and MASQUE run inside TLS, and the
client checks the server's certificate against `cert_pins` in `[transport]`.
A pin is the SHA-256 of the certificate's **public key**, so it survives the
certificate being re-issued. A Ferrum node's key is derived from its WireGuard
private key, so its pin stays the same across restarts: print it on the server
with `ferrum tls-fingerprint --config <server config>` and put it in the
client's `cert_pins`. For a third-party MASQUE proxy, compute it with
`openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256`.

What a pin protects, and what it doesn't:

- **Your traffic's contents never depend on it.** Everything inside the tunnel
  is WireGuard-encrypted and only the real peer can read it, pinned or not.
- **With a pin**, someone on the network path (a hostile Wi-Fi, ISP or
  middlebox) can't pose as the QUIC server or MASQUE proxy. If they try, the
  connection fails instead of being quietly intercepted. They can still see that
  you're talking to that address, how much, and when, and they can still block
  it.
- **Without a pin**, that same attacker could sit in the middle of the outer
  QUIC/HTTP-3 layer. They could watch its timing and sizes more closely, probe
  it to confirm it's a VPN, or tamper with it. Ferrum still connects in this case
  (so existing setups keep working) but logs an "outer transport
  UNAUTHENTICATED" warning every time it connects.

In the coordinator-managed QUIC mesh (`up-mesh`, desktop) pinning is
automatic. Each node publishes its public-key pin when it registers, the
coordinator hands it to peers in the network map, and every dial to a peer is
pinned to it, with no configuration. A peer that registered without a pin (for
example an older client) is still dialed, with the warning.

Those pins are only as trustworthy as the connection to the coordinator that
delivers them. If that connection is plain `http://`, someone on the path
between a device and the coordinator could swap in their own pin (or, for that
matter, their own WireGuard key). Protect the control channel with mTLS
(`--tls-cert/--tls-key/--tls-ca`) or run it only over a network you trust.

**Padding (obfuscation, FR5):** add `padding = true` (optionally `pad_to = 1280`)
to `[transport]` to normalize datagram sizes against fingerprinting. Both peers
must set the same values; works with either UDP or QUIC.
