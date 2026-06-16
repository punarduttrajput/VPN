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

use vpn_core::config::{Cidr, Config};
use vpn_core::keys::KeyPair;
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

    let iface_cidr: Cidr = config.interface_address.parse()?;
    let tun_cfg = TunConfig {
        name: iface.to_string(),
        address: iface_cidr,
        mtu,
    };

    let dev = device::open(&tun_cfg)
        .context("opening TUN device (needs elevated privileges on Linux/macOS)")?;
    info!(interface = %iface, "TUN device up");

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", config.listen_port).parse()?;
    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("binding UDP socket on {bind_addr}"))?;
    let peer = config.peer_endpoint()?;

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    info!("starting tunnel event loop (Ctrl-C to stop)");
    vpn_tunnel::run(session, dev, socket, peer, shutdown)
        .await
        .context("tunnel event loop")?;
    info!("tunnel stopped");
    Ok(())
}
