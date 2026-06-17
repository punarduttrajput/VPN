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
use tracing::info;
use tracing_subscriber::EnvFilter;

use vpn_core::config::{Cidr, Config, TransportMode};
use vpn_core::keys::KeyPair;
use vpn_transport::UdpTransport;
use vpn_tunnel::device::{self, TunConfig};
use vpn_tunnel::session::Session;

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

    info!("starting tunnel event loop (Ctrl-C to stop)");
    match config.transport.mode {
        TransportMode::Udp => {
            let transport = UdpTransport::bind(bind_addr, peer)
                .await
                .with_context(|| format!("binding UDP socket on {bind_addr}"))?;
            info!("transport: udp");
            vpn_tunnel::run(session, dev, transport, shutdown)
                .await
                .context("tunnel event loop")?;
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
                        vpn_tunnel::run(session, dev, transport, shutdown)
                            .await
                            .context("tunnel event loop")?;
                    }
                    Some(TransportRole::Client) => {
                        info!("transport: quic (client), connecting to {peer}");
                        let transport = QuicTransport::connect(bind_addr, peer, &server_name)
                            .await
                            .context("connecting quic transport")?;
                        vpn_tunnel::run(session, dev, transport, shutdown)
                            .await
                            .context("tunnel event loop")?;
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
