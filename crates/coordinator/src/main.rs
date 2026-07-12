//! `ferrum-coordinator` — runs the control-plane gRPC coordinator (PRD Phase 3 M1).
//!
//! Listens for device registration and network-map requests. In-memory registry
//! for now (persistence is a later increment). Bind address via `--listen`.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use ferrum_control_proto::coordinator::coordinator_server::CoordinatorServer;
use ferrum_coordinator::{CoordinatorService, Metrics, Policy, Registry};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tonic::transport::Server;
use tracing::{error, info};

fn arg_value(flag: &str) -> Option<String> {
    std::env::args().skip_while(|a| a != flag).nth(1)
}

/// Serve the privacy-preserving metrics (PRD Phase 6 FR4) on a tiny HTTP/1
/// endpoint at `GET /metrics` — enough for a Prometheus scraper, hand-rolled over
/// a `TcpListener` so the coordinator gains no HTTP-server dependency. Runs on its
/// own port (separate from the gRPC `--listen`). `device_count` is sampled from
/// the registry at scrape time.
///
/// The same listener answers `GET /healthz` (liveness) and `GET /readyz`
/// (readiness) probes for load balancers and orchestrators (PRD
/// `phase-6-anycast-autoscaling.md` FR1). The coordinator has no drain state
/// yet (that's the M2 relay-registry work), so readiness mirrors liveness;
/// both bodies are constant strings — nothing user-derived (NFR5).
async fn serve_metrics(addr: SocketAddr, metrics: Arc<Metrics>, registry: Arc<Mutex<Registry>>) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(%addr, error = %e, "failed to bind metrics endpoint");
            return;
        }
    };
    info!(%addr, "metrics endpoint listening on GET /metrics (+ /healthz, /readyz)");
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let metrics = metrics.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            // The request is tiny; one read captures the request line we need.
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let response = if buf[..n].starts_with(b"GET /metrics") {
                let device_count = registry
                    .lock()
                    .expect("registry mutex poisoned")
                    .device_count();
                let body = metrics.render(device_count);
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
            } else if buf[..n].starts_with(b"GET /healthz") {
                plain_response("200 OK", "ok")
            } else if buf[..n].starts_with(b"GET /readyz") {
                plain_response("200 OK", "ready")
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            };
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// A minimal `text/plain` HTTP/1 response for the health probes.
fn plain_response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Tracing: stderr logs always; OTLP span export (PRD Phase 6 FR4) when
    // --otlp-endpoint <url> is given and the `otlp` feature is built. The guard
    // flushes the exporter on drop, so it must outlive `serve`.
    let _telemetry = ferrum_coordinator::telemetry::init(
        arg_value("--otlp-endpoint").as_deref(),
        "ferrum-coordinator",
    );

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
    // Clone the registry handle for the metrics endpoint before the service
    // consumes it (the device-count gauge is sampled from the registry).
    let metrics_registry = registry.clone();
    // Same, for the admin API (device list/revoke, policy view/edit) — it
    // shares the live registry rather than reading the store independently.
    #[cfg(feature = "admin-api")]
    let admin_registry = registry.clone();

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

    // Grab the change-notification handle for the admin API before `svc` is
    // reassigned below — a getter, so this doesn't consume `svc`.
    #[cfg(feature = "admin-api")]
    let admin_changes = svc.changes();

    // Advertise a network-wide relay fallback (PRD Phase 4): every device learns
    // it from the network map and uses it as the relay underlay unless locally
    // overridden. Validated as a socket address so a typo fails fast. Without
    // the static override, relays announce themselves via the RelayHeartbeat
    // RPC (PRD phase-6-anycast-autoscaling.md FR3) and the sweeper withdraws
    // any that go silent, pushing a fresh map to watchers.
    let svc = match arg_value("--relay") {
        Some(relay) => {
            relay
                .parse::<SocketAddr>()
                .map_err(|e| format!("--relay '{relay}': {e}"))?;
            info!(%relay, "advertising static relay fallback to devices (relay registry disabled)");
            svc.with_relay(relay)
        }
        None => {
            info!("no --relay override; advertising self-announced relays (RelayHeartbeat)");
            svc.spawn_relay_sweeper(std::time::Duration::from_secs(5));
            svc
        }
    };

    // Advertise DNS resolvers (PRD leak-protection.md): every device points its
    // system DNS at them through the tunnel while connected, unless locally
    // overridden. Bare IPs (comma-separated), validated so a typo fails fast.
    let svc = match arg_value("--dns") {
        Some(dns) => {
            let servers: Vec<String> = dns.split(',').map(|s| s.trim().to_string()).collect();
            for server in &servers {
                server
                    .parse::<std::net::IpAddr>()
                    .map_err(|e| format!("--dns '{server}' is not an IP address: {e}"))?;
            }
            info!(?servers, "advertising DNS resolvers to devices");
            svc.with_dns_servers(servers)
        }
        None => svc,
    };

    // Metrics endpoint (PRD Phase 6 FR4): enable with --metrics-listen <ip:port>.
    // Runs on its own port; serves GET /metrics in the Prometheus text format.
    if let Some(addr) = arg_value("--metrics-listen") {
        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| format!("--metrics-listen '{addr}': {e}"))?;
        let metrics = svc.metrics();
        info!(%addr, "metrics enabled");
        tokio::spawn(serve_metrics(addr, metrics, metrics_registry));
    } else {
        // Avoid an unused-variable warning when the endpoint isn't enabled.
        let _ = metrics_registry;
        info!("no --metrics-listen; metrics endpoint disabled");
    }

    // Admin API + panel (device list/revoke, live ACL policy view/edit):
    // enable with --admin-listen <ip:port>. Has no auth mode of its own — it
    // requires --oidc-issuer/--oidc-audience/--oidc-jwks to already be set, and
    // refuses to start otherwise (fail-closed: never served unauthenticated).
    // Builds its own `OidcVerifier` from the same JWKS file rather than
    // threading the gRPC path's verifier through, keeping this block isolated
    // from the OIDC branch above.
    #[cfg(feature = "admin-api")]
    if let Some(addr) = arg_value("--admin-listen") {
        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| format!("--admin-listen '{addr}': {e}"))?;
        let (issuer, audience, jwks_path) = match (
            arg_value("--oidc-issuer"),
            arg_value("--oidc-audience"),
            arg_value("--oidc-jwks"),
        ) {
            (Some(i), Some(a), Some(j)) => (i, a, j),
            _ => {
                return Err(
                    "--admin-listen requires --oidc-issuer, --oidc-audience, and --oidc-jwks \
                     (the admin API has no other auth mode)"
                        .into(),
                )
            }
        };
        let jwks_doc = std::fs::read_to_string(&jwks_path)?;
        let jwks = ferrum_coordinator::Jwks::from_json(&jwks_doc)?;
        let verifier = Arc::new(ferrum_coordinator::OidcVerifier::new(
            &issuer, &audience, jwks,
        ));
        let router = ferrum_coordinator::admin::router(admin_registry, admin_changes, verifier);
        info!(%addr, "admin API + panel listening");
        tokio::spawn(async move {
            if let Err(e) = ferrum_coordinator::admin::serve(addr, router).await {
                error!(%addr, error = %e, "admin API server failed");
            }
        });
    }

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
