//! `vpn` — the Phase 1 command-line client (PRD FR5).
//!
//! Subcommands:
//!   * `vpn keygen`            — print a fresh private/public keypair (base64)
//!   * `vpn up --config <path>` — bring up the tunnel and run until interrupted
//!
//! Logging is via `tracing`, controlled by `RUST_LOG`. Keys and packet payloads
//! are never logged (NFR3 / FR5).

use std::net::SocketAddr;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::info;
use tracing_subscriber::EnvFilter;

use vpn_client_core::{ControlClient, PeerSpec};
use vpn_core::config::{Cidr, Config, TransportMode};
use vpn_core::keys::KeyPair;
use vpn_transport::UdpTransport;
use vpn_tunnel::device::{self, TunConfig};
use vpn_tunnel::session::Session;
use vpn_tunnel::{run_mesh, MeshPeer};

#[derive(Parser)]
#[command(name = "vpn", version, about = "Next-gen VPN — Phase 1 MVP tunnel")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new Curve25519 keypair and print it (base64).
    Keygen,
    /// Bring up the tunnel from a config file and run until Ctrl-C.
    Up {
        /// Path to the TOML config file.
        #[arg(short, long)]
        config: String,
        /// Interface name to request for the TUN device.
        #[arg(long, default_value = "vpn0")]
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
        /// Human-readable device name registered with the coordinator.
        #[arg(long, default_value = "vpn-node")]
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
        #[arg(long, default_value = "vpn0")]
        iface: String,
        /// MTU for the TUN device.
        #[arg(long, default_value_t = 1420)]
        mtu: u16,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Keygen => {
            keygen();
            Ok(())
        }
        Command::Up { config, iface, mtu } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(up(&config, &iface, mtu)),
        Command::UpMesh {
            config,
            coordinator,
            endpoint,
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

/// FR1–FR3: load config, build the session + TUN device + UDP socket, run loop.
async fn up(config_path: &str, iface: &str, mtu: u16) -> Result<()> {
    let config = Config::load(config_path)
        .with_context(|| format!("loading config from '{config_path}'"))?;
    info!("config loaded and validated");

    let session = Session::from_base64(&config.private_key, &config.peer.public_key)
        .context("building wireguard session")?;

    // QUIC datagrams cap below a normal MTU; shrink the inner MTU so encrypted
    // packets (inner + 32 B WireGuard overhead) fit inside a QUIC datagram.
    let effective_mtu = match config.transport.mode {
        TransportMode::Quic => mtu.min(QUIC_TUN_MTU),
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

    info!("starting tunnel event loop (Ctrl-C to stop)");
    match config.transport.mode {
        TransportMode::Udp => {
            let transport = UdpTransport::bind(bind_addr, peer)
                .await
                .with_context(|| format!("binding UDP socket on {bind_addr}"))?;
            info!("transport: udp");
            drive(session, dev, transport, pad_to, shutdown).await?;
        }
        TransportMode::Quic => {
            #[cfg(feature = "quic")]
            {
                use vpn_core::config::TransportRole;
                use vpn_transport::QuicTransport;
                let server_name = config
                    .transport
                    .server_name
                    .as_deref()
                    .unwrap_or("vpn")
                    .to_string();
                match config.transport.role {
                    Some(TransportRole::Server) => {
                        info!("transport: quic (server), listening on {bind_addr}");
                        let ep = QuicTransport::server_endpoint(bind_addr)
                            .context("creating quic server endpoint")?;
                        let transport = QuicTransport::accept(ep)
                            .await
                            .context("accepting quic connection")?;
                        drive(session, dev, transport, pad_to, shutdown).await?;
                    }
                    Some(TransportRole::Client) => {
                        info!("transport: quic (client), connecting to {peer}");
                        let transport = QuicTransport::connect(bind_addr, peer, &server_name)
                            .await
                            .context("connecting quic transport")?;
                        drive(session, dev, transport, pad_to, shutdown).await?;
                    }
                    None => anyhow::bail!("transport.role (client|server) required for quic"),
                }
            }
            #[cfg(not(feature = "quic"))]
            {
                anyhow::bail!(
                    "config requests transport.mode = quic, but this binary was built \
                     without the `quic` feature (rebuild with --features vpn-cli/quic)"
                );
            }
        }
    }
    info!("tunnel stopped");
    Ok(())
}

/// Phase 3 FR6: register with the coordinator, turn the returned network map into
/// a multi-peer mesh, and run it until interrupted.
#[allow(clippy::too_many_arguments)]
async fn up_mesh(
    config_path: &str,
    coordinator: &str,
    endpoint: &str,
    name: &str,
    tags: &[String],
    token_file: Option<&str>,
    iface: &str,
    mtu: u16,
) -> Result<()> {
    let config = Config::load(config_path)
        .with_context(|| format!("loading config from '{config_path}'"))?;
    let public_key = vpn_core::keys::public_base64_from_private(&config.private_key)
        .context("deriving public key from config private_key")?;

    info!(coordinator, "registering with coordinator");
    let mut client = ControlClient::connect(coordinator.to_string())
        .await
        .with_context(|| format!("connecting to coordinator at {coordinator}"))?;
    if let Some(path) = token_file {
        let token = std::fs::read_to_string(path)
            .with_context(|| format!("reading OIDC token from '{path}'"))?;
        client = client.with_token(token.trim().to_string());
        info!("attaching OIDC bearer token to coordinator requests");
    }
    let address = client
        .register(&public_key, name, endpoint, tags)
        .await
        .context("registering with coordinator")?;
    info!(%address, "registered; coordinator assigned tunnel address");

    let iface_cidr: Cidr = address
        .parse()
        .with_context(|| format!("coordinator-assigned address '{address}'"))?;
    let tun_cfg = TunConfig {
        name: iface.to_string(),
        address: iface_cidr,
        mtu,
    };
    let dev = device::open(&tun_cfg)
        .context("opening TUN device (needs elevated privileges on Linux/macOS)")?;
    info!(interface = %iface, mtu, "TUN device up");

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", config.listen_port).parse()?;
    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("binding UDP socket on {bind_addr}"))?;

    // Subscribe to live network-map updates and feed converted peer sets into the
    // mesh, so membership converges no matter who registered first.
    let mut stream = client
        .watch(&public_key)
        .await
        .context("subscribing to network-map updates")?;
    let (tx, rx) = mpsc::channel::<Vec<MeshPeer>>(8);
    let priv_b64 = config.private_key.clone();
    let watcher = tokio::spawn(async move {
        loop {
            match stream.next().await {
                Ok(Some(specs)) => match build_mesh_peers(&priv_b64, &specs) {
                    Ok(peers) => {
                        if tx.send(peers).await.is_err() {
                            break; // data plane stopped
                        }
                    }
                    Err(e) => tracing::warn!("ignoring unusable network map: {e:#}"),
                },
                Ok(None) => break, // stream ended
                Err(e) => {
                    tracing::warn!("network-map stream error: {e}");
                    break;
                }
            }
        }
    });

    info!("starting mesh data plane (Ctrl-C to stop)");
    // Start with an empty mesh; the watch stream delivers the current peer set
    // immediately, then updates as the network changes.
    let result = run_mesh(dev, socket, Vec::new(), rx, shutdown_signal())
        .await
        .context("mesh data plane");
    watcher.abort();
    result?;
    info!("tunnel stopped");
    Ok(())
}

/// Turn the coordinator's peer list into mesh sessions keyed by our private key.
///
/// Each peer gets its own [`Session`] (with a distinct local index) over the one
/// shared UDP socket; outbound packets are routed to a peer by its `allowed_ips`.
fn build_mesh_peers(private_key_b64: &str, peers: &[PeerSpec]) -> Result<Vec<MeshPeer>> {
    let priv_bytes = vpn_core::keys::decode_key(private_key_b64).context("decoding private key")?;
    peers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let pub_bytes = vpn_core::keys::decode_key(&p.public_key)
                .with_context(|| format!("decoding peer public key '{}'", p.public_key))?;
            let endpoint: SocketAddr = p
                .endpoint
                .parse()
                .with_context(|| format!("parsing peer endpoint '{}'", p.endpoint))?;
            let allowed_ips = p
                .allowed_ips
                .iter()
                .map(|c| c.parse::<Cidr>())
                .collect::<std::result::Result<Vec<_>, _>>()
                .with_context(|| format!("parsing allowed_ips for peer '{}'", p.public_key))?;
            // Local session indices must be distinct per peer; +1 keeps them non-zero.
            let session = Session::from_bytes(priv_bytes, pub_bytes, (i as u32) + 1)
                .with_context(|| format!("building session for peer '{}'", p.public_key))?;
            Ok(MeshPeer {
                session,
                endpoint,
                allowed_ips,
            })
        })
        .collect()
}

/// Default padded datagram size when `padding` is on but `pad_to` is unset.
const DEFAULT_PAD_TO: u16 = 1280;

/// Run the tunnel, optionally wrapping the transport in size-padding (FR5).
async fn drive<D, T>(
    session: Session,
    device: D,
    transport: T,
    pad_to: Option<u16>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()>
where
    D: vpn_tunnel::device::TunDevice + Send + 'static,
    T: vpn_transport::Transport + Send + Sync + 'static,
{
    match pad_to {
        Some(p) => vpn_tunnel::run(
            session,
            device,
            vpn_transport::PaddedTransport::new(transport, p as usize),
            shutdown,
        )
        .await
        .context("tunnel event loop")?,
        None => vpn_tunnel::run(session, device, transport, shutdown)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(public_key: &str, endpoint: &str, allowed: &[&str]) -> PeerSpec {
        PeerSpec {
            public_key: public_key.to_string(),
            endpoint: endpoint.to_string(),
            allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn builds_one_mesh_peer_per_plan_peer() {
        let me = KeyPair::generate();
        let b = KeyPair::generate();
        let c = KeyPair::generate();

        let peers = build_mesh_peers(
            &me.private_base64(),
            &[
                peer(&b.public_base64(), "2.2.2.2:51820", &["10.8.0.3/32"]),
                peer(&c.public_base64(), "3.3.3.3:51820", &["10.8.0.4/32"]),
            ],
        )
        .unwrap();

        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].endpoint, "2.2.2.2:51820".parse().unwrap());
        assert_eq!(peers[0].allowed_ips, vec!["10.8.0.3/32".parse().unwrap()]);
        assert_eq!(peers[1].endpoint, "3.3.3.3:51820".parse().unwrap());
        assert_eq!(peers[1].allowed_ips, vec!["10.8.0.4/32".parse().unwrap()]);
    }

    #[test]
    fn empty_plan_yields_no_peers() {
        let me = KeyPair::generate();
        assert!(build_mesh_peers(&me.private_base64(), &[])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn rejects_malformed_peer_endpoint() {
        let me = KeyPair::generate();
        let b = KeyPair::generate();
        let err = build_mesh_peers(
            &me.private_base64(),
            &[peer(&b.public_base64(), "not-a-socket", &["10.8.0.3/32"])],
        );
        assert!(err.is_err());
    }

    #[test]
    fn rejects_malformed_allowed_ip() {
        let me = KeyPair::generate();
        let b = KeyPair::generate();
        let err = build_mesh_peers(
            &me.private_base64(),
            &[peer(&b.public_base64(), "2.2.2.2:51820", &["not-a-cidr"])],
        );
        assert!(err.is_err());
    }
}
