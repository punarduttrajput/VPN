//! `vpn-coordinator` — runs the control-plane gRPC coordinator (PRD Phase 3 M1).
//!
//! Listens for device registration and network-map requests. In-memory registry
//! for now (persistence is a later increment). Bind address via `--listen`.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;
use vpn_control_proto::coordinator::coordinator_server::CoordinatorServer;
use vpn_coordinator::{CoordinatorService, Registry};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let listen: SocketAddr = std::env::args()
        .skip_while(|a| a != "--listen")
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:50051".to_string())
        .parse()?;

    // Tunnel address pool (10.8.0.0/24); host .1 reserved.
    let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
    let svc = CoordinatorService::new(registry);

    info!(%listen, "coordinator listening (in-memory registry)");
    Server::builder()
        .add_service(CoordinatorServer::new(svc))
        .serve(listen)
        .await?;
    Ok(())
}
