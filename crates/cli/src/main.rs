//! `ferrum` — the Phase 1 command-line client (PRD FR5).
//!
//! Subcommands:
//!   * `ferrum keygen`            — print a fresh private/public keypair (base64)
//!   * `ferrum up --config <path>` — bring up the tunnel and run until interrupted
//!
//! Logging is via `tracing`, controlled by `RUST_LOG`. Keys and packet payloads
//! are never logged (NFR3 / FR5).

use std::net::SocketAddr;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::info;

mod telemetry;

use ferrum_client_core::data_plane::run_mesh_session_supervised;
use ferrum_client_core::{ClientIdentity, ControlClient, FerrumClient, ReconnectPolicy};
use ferrum_core::config::{Cidr, Config, TransportMode};
use ferrum_core::keys::KeyPair;
use ferrum_transport::{JitteredTransport, UdpMeshTransport, UdpTransport};
use ferrum_tunnel::device::{self, TunConfig};
use ferrum_tunnel::session::Session;

#[derive(Parser)]
#[command(name = "ferrum", version, about = "Ferrum — Phase 1 MVP tunnel")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new Curve25519 keypair and print it (base64).
    Keygen,
    /// Run a DERP-style relay server: forward mesh packets between peers keyed by
    /// their WireGuard public key (Phase 4 fallback for peers with no direct path).
    Relay {
        /// Address to listen on, e.g. `0.0.0.0:51821`.
        #[arg(long, default_value = "0.0.0.0:51821")]
        listen: String,
        /// Optional address to serve privacy-preserving Prometheus metrics on
        /// (`GET /metrics`), e.g. `0.0.0.0:9096` (Phase 6 FR4).
        #[arg(long)]
        metrics_listen: Option<String>,
        /// Optional OTLP collector endpoint to export tracing spans to, e.g.
        /// `http://localhost:4317` (Phase 6 FR4; requires the `otlp` feature).
        #[arg(long)]
        otlp_endpoint: Option<String>,
        /// Network interface to attach the eBPF/XDP fast path to, e.g. `eth0`
        /// (PRD `phase-6-ebpf-xdp-relay.md`; requires the `xdp` feature, Linux
        /// only, and a compiled `relay-ebpf` object — see `--xdp-program`).
        /// Without this, the relay behaves exactly as before this feature
        /// existed: pure userspace forwarding.
        #[arg(long)]
        xdp_iface: Option<String>,
        /// Path to the compiled `relay-ebpf` object (see
        /// `relay-ebpf/README.md` for how to build it). Required alongside
        /// `--xdp-iface` to actually enable the fast path.
        #[arg(long)]
        xdp_program: Option<String>,
    },
    /// Bring up the tunnel from a config file and run until Ctrl-C.
    Up {
        /// Path to the TOML config file.
        #[arg(short, long)]
        config: String,
        /// Interface name to request for the TUN device.
        #[arg(long, default_value = "ferrum0")]
        iface: String,
        /// MTU for the TUN device.
        #[arg(long, default_value_t = 1420)]
        mtu: u16,
    },
    /// Join a coordinator-managed mesh: register, fetch the network map, and run
    /// a multi-peer data plane against every peer the coordinator returns.
    ///
    /// The `[peer]` block in the config is ignored in this mode — peers come from
    /// the coordinator. Only `private_key` and `listen_port` are used from it.
    UpMesh {
        /// Path to the TOML config file (supplies `private_key` + `listen_port`).
        #[arg(short, long)]
        config: String,
        /// Coordinator gRPC URL, e.g. `http://10.0.0.1:50051`.
        #[arg(long)]
        coordinator: String,
        /// This device's reachable endpoint (`ip:port`) advertised to peers.
        #[arg(long)]
        endpoint: String,
        /// STUN server (`ip:port`) for NAT-traversal candidate discovery. When
        /// set, the node gathers host + server-reflexive candidates and publishes
        /// them to the coordinator so peers can probe alternative paths (Phase 4).
        #[arg(long)]
        stun_server: Option<String>,
        /// Human-readable device name registered with the coordinator.
        #[arg(long, default_value = "ferrum-node")]
        name: String,
        /// Policy tag for this device (repeatable). Ignored when the coordinator
        /// runs with OIDC auth — tags then come from the verified token.
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Path to a file holding an OIDC bearer token (JWT) for the coordinator.
        /// Read from a file rather than a flag to keep it out of the process list.
        #[arg(long)]
        token_file: Option<String>,
        /// Interface name to request for the TUN device.
        #[arg(long, default_value = "ferrum0")]
        iface: String,
        /// MTU for the TUN device.
        #[arg(long, default_value_t = 1420)]
        mtu: u16,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // The relay is a Phase 6 FR4 observability target and may export spans over
    // OTLP, which must be initialized inside the tokio runtime (the OTLP/gRPC
    // exporter needs a tokio context); its tracing is set up in `relay()` itself.
    // Every other command just gets the stderr `fmt` subscriber here.
    let _telemetry =
        (!matches!(cli.command, Command::Relay { .. })).then(|| telemetry::init(None, "ferrum"));

    match cli.command {
        Command::Keygen => {
            keygen();
            Ok(())
        }
        Command::Relay {
            listen,
            metrics_listen,
            otlp_endpoint,
            xdp_iface,
            xdp_program,
        } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(relay(
                &listen,
                metrics_listen.as_deref(),
                otlp_endpoint.as_deref(),
                xdp_iface.as_deref(),
                xdp_program.as_deref(),
            )),
        Command::Up { config, iface, mtu } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(up(&config, &iface, mtu)),
        Command::UpMesh {
            config,
            coordinator,
            endpoint,
            stun_server,
            name,
            tags,
            token_file,
            iface,
            mtu,
        } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(up_mesh(
                &config,
                &coordinator,
                &endpoint,
                stun_server.as_deref(),
                &name,
                &tags,
                token_file.as_deref(),
                &iface,
                mtu,
            )),
    }
}

/// FR4: print a fresh keypair. Never logged — written to stdout for the operator.
fn keygen() {
    let kp = KeyPair::generate();
    println!("private_key = \"{}\"", kp.private_base64());
    println!("public_key  = \"{}\"", kp.public_base64());
}

/// Phase 4 M3: run the public-key-keyed relay until interrupted. The relay only
/// forwards opaque (already-encrypted) datagrams between registered peers, so it
/// needs no keys of its own. With `metrics_listen` set, also serve
/// privacy-preserving Prometheus metrics on `GET /metrics` (Phase 6 FR4).
/// `xdp_iface`/`xdp_program` opt into the eBPF fast path (PRD
/// `phase-6-ebpf-xdp-relay.md`) — see [`enable_xdp_fastpath`].
async fn relay(
    listen: &str,
    metrics_listen: Option<&str>,
    otlp_endpoint: Option<&str>,
    xdp_iface: Option<&str>,
    xdp_program: Option<&str>,
) -> Result<()> {
    // Tracing: stderr logs always; OTLP span export (Phase 6 FR4) when
    // --otlp-endpoint is given and the `otlp` feature is built. The guard flushes
    // the exporter on drop, so it must outlive the serve loop below.
    let _telemetry = telemetry::init(otlp_endpoint, "ferrum-relay");

    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("parsing --listen '{listen}'"))?;
    let server = ferrum_transport::RelayServer::bind(addr)
        .await
        .with_context(|| format!("binding relay on {addr}"))?;

    if let Some(metrics_addr) = metrics_listen {
        let metrics_addr: SocketAddr = metrics_addr
            .parse()
            .with_context(|| format!("parsing --metrics-listen '{metrics_addr}'"))?;
        let metrics = server.metrics();
        info!(%metrics_addr, "relay metrics enabled");
        tokio::spawn(serve_relay_metrics(metrics_addr, metrics));
    }

    enable_xdp_fastpath(&server, addr.port(), xdp_iface, xdp_program).await;

    info!(%addr, "relay listening (Ctrl-C to stop)");
    tokio::select! {
        result = server.serve() => result.context("relay server")?,
        _ = shutdown_signal() => info!("relay stopped"),
    }
    Ok(())
}

/// Attach the eBPF/XDP fast path (PRD `phase-6-ebpf-xdp-relay.md`) when both
/// `--xdp-iface` and `--xdp-program` are given, the `xdp` feature is built,
/// and the host is Linux. Never a hard failure either way (PRD FR5 goal G4:
/// additive, never required) — a missing flag, an unbuilt feature, or a
/// failed attach all just mean "the relay runs userspace-only," logged, not
/// returned as an error that would abort an otherwise-working relay.
#[cfg(all(target_os = "linux", feature = "xdp"))]
async fn enable_xdp_fastpath(
    server: &ferrum_transport::RelayServer,
    relay_port: u16,
    xdp_iface: Option<&str>,
    xdp_program: Option<&str>,
) {
    let (Some(iface), Some(program)) = (xdp_iface, xdp_program) else {
        if xdp_iface.is_some() || xdp_program.is_some() {
            tracing::warn!(
                "relay xdp: both --xdp-iface and --xdp-program are required to enable the fast path; running userspace-only"
            );
        }
        return;
    };
    match ferrum_transport::RelayXdpLoader::attach(
        std::path::Path::new(program),
        iface,
        relay_port,
        server.metrics(),
    )
    .await
    {
        Ok(loader) => {
            server.set_xdp_hook(loader);
            info!(%iface, %program, "relay xdp fast path enabled");
        }
        Err(e) => {
            tracing::warn!("relay xdp: failed to attach fast path ({e}); running userspace-only");
        }
    }
}

/// Non-Linux / `xdp`-feature-off builds: the flags are always accepted (see
/// the `Relay` subcommand) but only ever warn here — see
/// [`enable_xdp_fastpath`] above for what they do when the feature is built.
#[cfg(not(all(target_os = "linux", feature = "xdp")))]
async fn enable_xdp_fastpath(
    _server: &ferrum_transport::RelayServer,
    _relay_port: u16,
    xdp_iface: Option<&str>,
    xdp_program: Option<&str>,
) {
    if xdp_iface.is_some() || xdp_program.is_some() {
        tracing::warn!(
            "relay xdp: --xdp-iface/--xdp-program given, but this binary wasn't built with the `xdp` feature (or isn't running on Linux); running userspace-only"
        );
    }
}

/// Serve the relay's privacy-preserving metrics (PRD Phase 6 FR4) on a tiny
/// HTTP/1 endpoint at `GET /metrics` — enough for a Prometheus scraper,
/// hand-rolled over a `TcpListener` so the CLI gains no HTTP-server dependency.
async fn serve_relay_metrics(
    addr: SocketAddr,
    metrics: std::sync::Arc<ferrum_transport::RelayMetrics>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(%addr, error = %e, "failed to bind relay metrics endpoint");
            return;
        }
    };
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let response = if buf[..n].starts_with(b"GET /metrics") {
                let body = metrics.render();
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            };
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// FR1–FR3: load config, build the session + TUN device + UDP socket, run loop.
async fn up(config_path: &str, iface: &str, mtu: u16) -> Result<()> {
    let config = Config::load(config_path)
        .with_context(|| format!("loading config from '{config_path}'"))?;
    info!("config loaded and validated");

    let session = Session::from_base64(&config.private_key, &config.peer.public_key)
        .context("building wireguard session")?;

    // QUIC and MASQUE (HTTP/3 over QUIC) both need a reduced MTU; shrink the
    // inner MTU so encrypted packets fit inside a QUIC datagram.
    let effective_mtu = match config.transport.mode {
        TransportMode::Quic | TransportMode::Masque => mtu.min(QUIC_TUN_MTU),
        TransportMode::Udp => mtu,
    };

    let iface_cidr: Cidr = config.interface_address.parse()?;
    let tun_cfg = TunConfig {
        name: iface.to_string(),
        address: iface_cidr,
        mtu: effective_mtu,
    };

    let dev = device::open(&tun_cfg)
        .context("opening TUN device (needs elevated privileges on Linux/macOS)")?;
    info!(interface = %iface, mtu = effective_mtu, "TUN device up");

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", config.listen_port).parse()?;
    let peer = config.peer_endpoint()?;
    let shutdown = shutdown_signal();

    let pad_to = if config.transport.padding {
        let p = config.transport.pad_to.unwrap_or(DEFAULT_PAD_TO);
        info!(pad_to = p, "transport padding enabled (FR5)");
        Some(p)
    } else {
        None
    };

    let jitter_ms = config.transport.jitter_ms.map(u64::from);
    if let Some(ms) = jitter_ms {
        info!(max_ms = ms, "transport timing jitter enabled (FR5)");
    }

    info!("starting tunnel event loop (Ctrl-C to stop)");
    match config.transport.mode {
        TransportMode::Udp => {
            let transport = UdpTransport::bind(bind_addr, peer)
                .await
                .with_context(|| format!("binding UDP socket on {bind_addr}"))?;
            info!("transport: udp");
            drive(session, dev, transport, pad_to, jitter_ms, shutdown).await?;
        }
        TransportMode::Quic => {
            #[cfg(feature = "quic")]
            {
                use ferrum_core::config::TransportRole;
                use ferrum_transport::QuicTransport;
                let server_name = config
                    .transport
                    .server_name
                    .as_deref()
                    .unwrap_or("ferrum")
                    .to_string();
                match config.transport.role {
                    Some(TransportRole::Server) => {
                        info!("transport: quic (server), listening on {bind_addr}");
                        let ep = QuicTransport::server_endpoint(bind_addr)
                            .context("creating quic server endpoint")?;
                        let transport = QuicTransport::accept(ep)
                            .await
                            .context("accepting quic connection")?;
                        drive(session, dev, transport, pad_to, jitter_ms, shutdown).await?;
                    }
                    Some(TransportRole::Client) => {
                        info!("transport: quic (client), connecting to {peer}");
                        let transport = QuicTransport::connect(bind_addr, peer, &server_name)
                            .await
                            .context("connecting quic transport")?;
                        drive(session, dev, transport, pad_to, jitter_ms, shutdown).await?;
                    }
                    None => anyhow::bail!("transport.role (client|server) required for quic"),
                }
            }
            #[cfg(not(feature = "quic"))]
            {
                anyhow::bail!(
                    "config requests transport.mode = quic, but this binary was built \
                     without the `quic` feature (rebuild with --features ferrum-cli/quic)"
                );
            }
        }
        TransportMode::Masque => {
            #[cfg(feature = "masque")]
            {
                use ferrum_transport::MasqueTransport;
                let proxy_addr: SocketAddr = config
                    .transport
                    .masque_proxy
                    .as_deref()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "transport.masque_proxy is required when transport.mode = masque"
                        )
                    })?
                    .parse()
                    .context("parsing transport.masque_proxy")?;
                let authority = config
                    .transport
                    .server_name
                    .as_deref()
                    .unwrap_or("ferrum")
                    .to_string();
                info!("transport: masque, proxy={proxy_addr}");
                let transport = MasqueTransport::connect(bind_addr, proxy_addr, &authority, peer)
                    .await
                    .context("connecting to masque proxy")?;
                drive(session, dev, transport, pad_to, jitter_ms, shutdown).await?;
            }
            #[cfg(not(feature = "masque"))]
            {
                anyhow::bail!(
                    "config requests transport.mode = masque, but this binary was built \
                     without the `masque` feature (rebuild with --features ferrum-cli/masque)"
                );
            }
        }
    }
    info!("tunnel stopped");
    Ok(())
}

/// Phase 3 FR6 + Phase 5 FR5: join a coordinator-managed mesh and run a
/// **self-healing** multi-peer data plane until interrupted.
///
/// Registers once up front to learn the coordinator-assigned tunnel address (so
/// the TUN can be configured with it), gathers/publishes NAT-traversal candidates,
/// then hands a [`FerrumClient`] facade and device/transport *factories* to
/// [`run_mesh_session_supervised`], which registers, converges the mesh from
/// `WatchNetworkMap`, and **auto-reconnects with backoff** on any drop (coordinator
/// outage, transport failure) — re-opening the TUN and rebinding the socket each
/// attempt. An OIDC bearer token (`--token-file`), when given, authenticates every
/// coordinator RPC, including each reconnect.
#[allow(clippy::too_many_arguments)]
async fn up_mesh(
    config_path: &str,
    coordinator: &str,
    endpoint: &str,
    stun_server: Option<&str>,
    name: &str,
    tags: &[String],
    token_file: Option<&str>,
    iface: &str,
    mtu: u16,
) -> Result<()> {
    let config = Config::load(config_path)
        .with_context(|| format!("loading config from '{config_path}'"))?;
    let public_key = ferrum_core::keys::public_base64_from_private(&config.private_key)
        .context("deriving public key from config private_key")?;

    // Optional OIDC bearer token, read from a file so it stays out of the process
    // list. Applied to every coordinator RPC the data plane makes (and each
    // reconnect) via the facade.
    let token = match token_file {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading OIDC token from '{path}'"))?;
            info!("attaching OIDC bearer token to coordinator requests");
            Some(raw.trim().to_string())
        }
        None => None,
    };

    // Register once up front to learn our coordinator-assigned tunnel address — we
    // need it to configure the TUN before the data plane runs. The supervised
    // session re-registers idempotently each attempt; the allocation is stable.
    info!(coordinator, "registering with coordinator");
    let mut control = ControlClient::connect(coordinator.to_string())
        .await
        .with_context(|| format!("connecting to coordinator at {coordinator}"))?;
    if let Some(token) = &token {
        control = control.with_token(token.clone());
    }
    let address = control
        .register(&public_key, name, endpoint, tags)
        .await
        .context("registering with coordinator")?;
    info!(%address, "registered; coordinator assigned tunnel address");

    // Phase 4 M2: gather NAT-traversal candidates (host + STUN server-reflexive)
    // and publish them so peers can probe alternative paths. Gather *before*
    // binding the data-plane socket — STUN briefly binds the same listen port so
    // the discovered mapping matches what peers will reach.
    if let Some(stun) = stun_server {
        let stun_addr: SocketAddr = stun
            .parse()
            .with_context(|| format!("parsing --stun-server '{stun}'"))?;
        let candidates: Vec<String> =
            ferrum_transport::stun::gather_candidates(config.listen_port, Some(stun_addr))
                .await
                .iter()
                .map(|a| a.to_string())
                .collect();
        if candidates.is_empty() {
            tracing::warn!("no NAT-traversal candidates gathered (STUN unreachable?)");
        } else {
            info!(?candidates, "publishing NAT-traversal candidates");
            control
                .publish_candidates(&public_key, &candidates)
                .await
                .context("publishing candidates to coordinator")?;
        }
    }
    // The supervised session opens its own (token-carrying) control channels.
    drop(control);

    let iface_cidr: Cidr = address
        .parse()
        .with_context(|| format!("coordinator-assigned address '{address}'"))?;
    // QUIC and MASQUE (HTTP/3 over QUIC) both need a reduced MTU (mirrors `up`).
    let effective_mtu = match config.transport.mode {
        TransportMode::Quic | TransportMode::Masque => mtu.min(QUIC_TUN_MTU),
        TransportMode::Udp => mtu,
    };
    let tun_cfg = TunConfig {
        name: iface.to_string(),
        address: iface_cidr,
        mtu: effective_mtu,
    };
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", config.listen_port).parse()?;

    // The shared facade carries the token (so its control channels and every
    // reconnect authenticate). The relay is resolved inside the session: a local
    // `transport.relay` override else whatever the coordinator advertises.
    let client = FerrumClient::new();
    client.set_token(token);
    let identity = ClientIdentity {
        public_key: public_key.clone(),
        name: name.to_string(),
        endpoint: endpoint.to_string(),
        tags: tags.to_vec(),
    };
    let policy = ReconnectPolicy::default();
    let relay = config.transport.relay.clone();
    let priv_b64 = config.private_key.clone();

    // Factory that (re)opens the OS TUN for each session attempt — a session
    // consumes and closes its device, so a reconnect rebuilds it.
    let make_device = {
        let tun_cfg = tun_cfg.clone();
        move || {
            let tun_cfg = tun_cfg.clone();
            async move {
                device::open(&tun_cfg).map_err(|e| {
                    ferrum_client_core::Error::DataPlane(format!(
                        "opening TUN device (needs elevated privileges on Linux/macOS): {e:#}"
                    ))
                })
            }
        }
    };

    info!("starting mesh data plane (auto-reconnect; Ctrl-C to stop)");
    // Candidates were published above; the supervised session re-resolves the
    // relay and re-converges peers each attempt. Pick the transport by config mode.
    let result = match config.transport.mode {
        TransportMode::Udp => {
            info!("mesh transport: udp");
            let make_transport = move || async move {
                UdpMeshTransport::bind(bind_addr)
                    .await
                    .map_err(|e| ferrum_client_core::Error::DataPlane(e.to_string()))
            };
            run_mesh_session_supervised(
                &client,
                coordinator,
                &identity,
                &priv_b64,
                &[],
                make_device,
                make_transport,
                relay,
                &policy,
                shutdown_signal(),
            )
            .await
        }
        TransportMode::Quic => {
            #[cfg(feature = "quic")]
            {
                info!("mesh transport: quic");
                let make_transport = move || async move {
                    ferrum_transport::QuicMeshTransport::bind(bind_addr)
                        .await
                        .map_err(|e| ferrum_client_core::Error::DataPlane(e.to_string()))
                };
                run_mesh_session_supervised(
                    &client,
                    coordinator,
                    &identity,
                    &priv_b64,
                    &[],
                    make_device,
                    make_transport,
                    relay,
                    &policy,
                    shutdown_signal(),
                )
                .await
            }
            #[cfg(not(feature = "quic"))]
            {
                anyhow::bail!(
                    "config requests transport.mode = quic for the mesh, but this binary \
                     was built without the `quic` feature (rebuild with --features ferrum-cli/quic)"
                );
            }
        }
        TransportMode::Masque => {
            #[cfg(feature = "masque")]
            {
                let proxy_addr: SocketAddr = config
                    .transport
                    .masque_proxy
                    .as_deref()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "transport.masque_proxy is required when transport.mode = masque"
                        )
                    })?
                    .parse()
                    .context("parsing transport.masque_proxy")?;
                let authority = config
                    .transport
                    .server_name
                    .as_deref()
                    .unwrap_or("ferrum")
                    .to_string();
                info!(proxy = %proxy_addr, "mesh transport: masque");
                let make_transport = move || {
                    let authority = authority.clone();
                    async move {
                        Ok::<_, ferrum_client_core::Error>(
                            ferrum_transport::MasqueMeshTransport::new(proxy_addr, authority),
                        )
                    }
                };
                run_mesh_session_supervised(
                    &client,
                    coordinator,
                    &identity,
                    &priv_b64,
                    &[],
                    make_device,
                    make_transport,
                    relay,
                    &policy,
                    shutdown_signal(),
                )
                .await
            }
            #[cfg(not(feature = "masque"))]
            {
                anyhow::bail!(
                    "config requests transport.mode = masque for the mesh, but this binary \
                     was built without the `masque` feature (rebuild with --features ferrum-cli/masque)"
                );
            }
        }
    };
    result.context("supervised mesh data plane")?;
    info!("tunnel stopped");
    Ok(())
}

/// Default padded datagram size when `padding` is on but `pad_to` is unset.
const DEFAULT_PAD_TO: u16 = 1280;

/// Run the tunnel, optionally wrapping the transport in padding and/or jitter.
async fn drive<D, T>(
    session: Session,
    device: D,
    transport: T,
    pad_to: Option<u16>,
    jitter_ms: Option<u64>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()>
where
    D: ferrum_tunnel::device::TunDevice + Send + 'static,
    T: ferrum_transport::Transport + Send + Sync + 'static,
{
    // Layer order (outermost first): jitter → padding → inner transport.
    // Jitter goes outside padding so the randomly delayed packet is already
    // fully framed; swapping the order would still work but is less logical.
    match (pad_to, jitter_ms) {
        (Some(p), Some(ms)) => ferrum_tunnel::run(
            session,
            device,
            JitteredTransport::new(
                ferrum_transport::PaddedTransport::new(transport, p as usize),
                ms,
            ),
            shutdown,
        )
        .await
        .context("tunnel event loop")?,
        (Some(p), None) => ferrum_tunnel::run(
            session,
            device,
            ferrum_transport::PaddedTransport::new(transport, p as usize),
            shutdown,
        )
        .await
        .context("tunnel event loop")?,
        (None, Some(ms)) => ferrum_tunnel::run(
            session,
            device,
            JitteredTransport::new(transport, ms),
            shutdown,
        )
        .await
        .context("tunnel event loop")?,
        (None, None) => ferrum_tunnel::run(session, device, transport, shutdown)
            .await
            .context("tunnel event loop")?,
    }
    Ok(())
}

/// QUIC's conservative initial datagram size is ~1180 B; keep the inner MTU
/// below it (minus WireGuard's 32 B overhead) so packets are not dropped.
const QUIC_TUN_MTU: u16 = 1100;

/// FR1: a future that resolves on Ctrl-C (SIGINT) or SIGTERM.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("could not install SIGTERM handler: {e}");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
