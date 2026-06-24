//! `ferrum-coordinator` — runs the control-plane gRPC coordinator (PRD Phase 3 M1).
//!
//! Listens for device registration and network-map requests. In-memory registry
//! for now (persistence is a later increment). Bind address via `--listen`.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use ferrum_control_proto::coordinator::coordinator_server::CoordinatorServer;
use ferrum_coordinator::{CoordinatorService, Policy, Registry};
use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn arg_value(flag: &str) -> Option<String> {
    std::env::args().skip_while(|a| a != flag).nth(1)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let listen: SocketAddr = arg_value("--listen")
        .unwrap_or_else(|| "0.0.0.0:50051".to_string())
        .parse()?;

    // Access policy: load from --policy <file> (TOML), else allow-all (full mesh).
    let policy = match arg_value("--policy") {
        Some(path) => {
            let text = std::fs::read_to_string(&path)?;
            let p = Policy::from_toml(&text)?;
            info!(policy = %path, allow_all = p.allow_all, rules = p.rules.len(), "loaded ACL policy");
            p
        }
        None => {
            info!("no --policy given; using allow-all (full mesh)");
            Policy::allow_all()
        }
    };

    // Tunnel address pool (10.8.0.0/24); host .1 reserved.
    let base = Ipv4Addr::new(10, 8, 0, 0);

    // Persistence: --store <path> uses SQLite (sqlite feature), else in-memory.
    #[cfg(feature = "sqlite")]
    let registry = match arg_value("--store") {
        Some(path) => {
            let store = ferrum_coordinator::SqliteStore::open(&path)?;
            let reg = Registry::with_store(base, 24, policy, Box::new(store))?;
            info!(store = %path, devices = reg.device_count(), "using SQLite persistence");
            reg
        }
        None => {
            info!("no --store given; using in-memory registry");
            Registry::with_policy(base, 24, policy)
        }
    };
    #[cfg(not(feature = "sqlite"))]
    let registry = Registry::with_policy(base, 24, policy);

    let registry = Arc::new(Mutex::new(registry));

    // OIDC auth: enable when --oidc-issuer/--oidc-audience/--oidc-jwks are all
    // provided. Tokens are then required on every RPC and device tags come from
    // the verified claim instead of the (self-declared) request.
    #[cfg(feature = "oidc")]
    let svc = match (
        arg_value("--oidc-issuer"),
        arg_value("--oidc-audience"),
        arg_value("--oidc-jwks"),
    ) {
        (Some(issuer), Some(audience), Some(jwks_path)) => {
            let jwks_doc = std::fs::read_to_string(&jwks_path)?;
            let jwks = ferrum_coordinator::Jwks::from_json(&jwks_doc)?;
            let verifier = Arc::new(ferrum_coordinator::OidcVerifier::new(
                &issuer, &audience, jwks,
            ));
            info!(%issuer, %audience, jwks = %jwks_path, "OIDC authentication enabled");
            CoordinatorService::with_auth(registry, verifier)
        }
        (None, None, None) => {
            info!("no --oidc-* flags; authentication disabled (tags are self-declared)");
            CoordinatorService::new(registry)
        }
        _ => return Err("OIDC requires --oidc-issuer, --oidc-audience, and --oidc-jwks".into()),
    };
    #[cfg(not(feature = "oidc"))]
    let svc = CoordinatorService::new(registry);

    // Advertise a network-wide relay fallback (PRD Phase 4): every device learns
    // it from the network map and uses it as the relay underlay unless locally
    // overridden. Validated as a socket address so a typo fails fast.
    let svc = match arg_value("--relay") {
        Some(relay) => {
            relay
                .parse::<SocketAddr>()
                .map_err(|e| format!("--relay '{relay}': {e}"))?;
            info!(%relay, "advertising relay fallback to devices");
            svc.with_relay(relay)
        }
        None => svc,
    };

    #[cfg_attr(not(feature = "mtls"), allow(unused_mut))]
    let mut builder = Server::builder();

    // mTLS: enable when --tls-cert/--tls-key/--tls-ca are all provided.
    #[cfg(feature = "mtls")]
    if let (Some(cert), Some(key), Some(ca)) = (
        arg_value("--tls-cert"),
        arg_value("--tls-key"),
        arg_value("--tls-ca"),
    ) {
        ferrum_coordinator::pki::install_crypto_provider();
        let identity = tonic::transport::Identity::from_pem(
            std::fs::read_to_string(&cert)?,
            std::fs::read_to_string(&key)?,
        );
        let ca_root = tonic::transport::Certificate::from_pem(std::fs::read_to_string(&ca)?);
        let tls = tonic::transport::ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(ca_root);
        builder = builder.tls_config(tls)?;
        info!("mutual TLS enabled (client certificates required)");
    }

    info!(%listen, "coordinator listening");
    builder
        .add_service(CoordinatorServer::new(svc))
        .serve(listen)
        .await?;
    Ok(())
}
