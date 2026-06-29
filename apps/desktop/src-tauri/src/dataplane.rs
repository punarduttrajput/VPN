//! Shared data-plane bring-up (Phase 5).
//!
//! One place that turns a validated [`ConnectConfig`] into a running, supervised
//! mesh data plane on a given [`FerrumClient`]. Both callers use it:
//!
//! * the **privileged Windows service** ([`crate::service`]) runs it on its own
//!   client and forwards the client's event stream back to the GUI over the pipe;
//! * the **Unix in-process path** ([`crate::run`]'s `connect`) runs it directly on
//!   the GUI's client (Linux/macOS keep the existing elevated-GUI model).
//!
//! It performs everything platform-independent about bring-up — parse the
//! transport selection, derive the advertised public key, pre-register to learn
//! the coordinator-assigned tunnel address, gather + publish NAT-traversal
//! candidates (if a STUN server is set), build the [`TunConfig`], pre-flight the
//! TUN once for a clean early error, then drive
//! [`run_mesh_session_supervised`] (always-on auto-reconnect) over the chosen
//! transport until `shutdown` resolves.
//!
//! The kill-switch *policy* (arming) and *enforcement* (the OS firewall) live with
//! the caller: this only sets `client.set_kill_switch(cfg.kill_switch)` so the
//! core emits `TrafficBlocked`; the caller's event loop enforces it (the service
//! drives WFP; the Unix shell drives `nft`). That keeps enforcement in whichever
//! process is privileged.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};

use ferrum_client_core::data_plane::run_mesh_session_supervised;
use ferrum_client_core::{ClientIdentity, ConnectionState, FerrumClient, ReconnectPolicy};
use ferrum_core::config::Cidr;
use ferrum_transport::{MasqueMeshTransport, MeshTransport, QuicMeshTransport, UdpMeshTransport};
use ferrum_tunnel::device::{self, TunConfig};

use crate::ipc::ConnectConfig;

/// TUN interface name requested from the OS (best effort; the OS may rename).
pub const TUN_IFACE: &str = "ferrum0";
/// Inner TUN MTU for the UDP transport (leaves headroom under a 1500 B path for
/// WireGuard + UDP/IP overhead).
const TUN_MTU: u16 = 1420;
/// Smaller inner TUN MTU for QUIC/MASQUE — the extra QUIC + TLS (and, for MASQUE,
/// HTTP/3 CONNECT-UDP) framing eats into the path budget (mirrors the CLI).
const QUIC_TUN_MTU: u16 = 1100;
/// Default TLS / HTTP-3 `:authority` for QUIC/MASQUE when the form leaves it blank.
const DEFAULT_SERVER_NAME: &str = "ferrum";

/// Mesh wire transport chosen in the connect form.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TransportMode {
    Udp,
    Quic,
    Masque,
}

/// Render a [`ConnectionState`] as the short string the GUI displays. Shared so
/// the in-process path and the service report identical names.
pub fn state_name(s: ConnectionState) -> String {
    match s {
        ConnectionState::Disconnected => "Disconnected",
        ConnectionState::Connecting => "Connecting",
        ConnectionState::Connected => "Connected",
        ConnectionState::Reconnecting => "Reconnecting",
        ConnectionState::Failed => "Failed",
    }
    .to_string()
}

fn parse_mode(mode: &str) -> Result<TransportMode, String> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "udp" => Ok(TransportMode::Udp),
        "quic" => Ok(TransportMode::Quic),
        "masque" => Ok(TransportMode::Masque),
        other => Err(format!(
            "unknown transport mode '{other}' (expected udp, quic, or masque)"
        )),
    }
}

/// Best-effort resolve a coordinator URL (`http://host:port`) to its IP
/// address(es), for the kill-switch allow-list (so the control plane can reconnect
/// while other traffic is blocked). Empty on a parse/resolve failure → strict block.
pub fn resolve_coordinator_ips(coordinator: &str) -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;
    let authority = coordinator
        .rsplit("://")
        .next()
        .unwrap_or(coordinator)
        .split('/')
        .next()
        .unwrap_or("");
    authority
        .to_socket_addrs()
        .map(|addrs| addrs.map(|a| a.ip()).collect())
        .unwrap_or_default()
}

/// Validate + bring up the data plane on `client`, running until `shutdown`.
///
/// Returns `Err(msg)` for a configuration/registration/TUN error that happens
/// *before* the supervisor takes over (so the caller can surface a clean failure),
/// or for a supervised data-plane error that exhausts its retry budget. Returns
/// `Ok(())` on a clean shutdown.
pub async fn bring_up<F>(
    client: &FerrumClient,
    cfg: &ConnectConfig,
    shutdown: F,
) -> Result<(), String>
where
    F: Future<Output = ()> + Send,
{
    // Resolve the transport selection up front so a bad mode / missing-or-malformed
    // MASQUE proxy fails *now* with a clean error rather than inside the supervisor.
    let mode = parse_mode(&cfg.transport_mode)?;
    let server_name = cfg
        .server_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_SERVER_NAME)
        .to_string();
    let masque_proxy: Option<SocketAddr> = match mode {
        TransportMode::Masque => Some(
            cfg.masque_proxy
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "MASQUE transport requires a proxy address".to_string())?
                .parse()
                .map_err(|e| format!("invalid MASQUE proxy address: {e}"))?,
        ),
        TransportMode::Udp | TransportMode::Quic => None,
    };

    // NAT-traversal settings (Phase 4), validated up front for a clean error.
    let relay: Option<String> = match cfg
        .relay
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(r) => {
            r.parse::<SocketAddr>()
                .map_err(|e| format!("invalid relay address '{r}': {e}"))?;
            Some(r.to_string())
        }
        None => None,
    };
    let stun_server: Option<SocketAddr> = match cfg
        .stun_server
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => Some(
            s.parse()
                .map_err(|e| format!("invalid STUN server address '{s}': {e}"))?,
        ),
        None => None,
    };

    // Derive the advertised public key from the private key.
    let public_key = ferrum_core::keys::public_base64_from_private(&cfg.private_key)
        .map_err(|e| format!("deriving public key from private key: {e}"))?;

    // Arm the kill-switch policy + carry any bearer token *before* connecting so the
    // core emits the right `TrafficBlocked` signal and authenticates its RPCs.
    client.set_token(cfg.token.clone());
    client.set_kill_switch(cfg.kill_switch);

    // Pre-register (out of band) only to learn the assigned tunnel address — the
    // TUN needs it before the runner (which re-registers idempotently) takes over.
    let mut control = ferrum_client_core::ControlClient::connect(cfg.coordinator.clone())
        .await
        .map_err(|e| format!("connecting to coordinator: {e}"))?;
    if let Some(token) = cfg.token.clone() {
        control = control.with_token(token);
    }
    let address = control
        .register(&public_key, &cfg.name, &cfg.endpoint, &cfg.tags)
        .await
        .map_err(|e| format!("registering with coordinator: {e}"))?;

    let cidr: Cidr = address
        .parse()
        .map_err(|e| format!("assigned tunnel address '{address}': {e}"))?;
    let mtu = match mode {
        TransportMode::Udp => TUN_MTU,
        TransportMode::Quic | TransportMode::Masque => QUIC_TUN_MTU,
    };
    let tun_cfg = TunConfig {
        name: TUN_IFACE.to_string(),
        address: cidr,
        mtu,
    };
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", cfg.listen_port)
        .parse()
        .map_err(|e| format!("invalid listen port {}: {e}", cfg.listen_port))?;

    // Phase 4 M2: with a STUN server set, gather host + server-reflexive candidates
    // on the data-plane port *before* the supervisor binds it (STUN briefly binds
    // the same port so the mapping matches). A flaky STUN server never blocks bring-up.
    let candidates: Vec<String> = match stun_server {
        Some(stun) => {
            let gathered: Vec<String> =
                ferrum_transport::stun::gather_candidates(cfg.listen_port, Some(stun))
                    .await
                    .iter()
                    .map(|a| a.to_string())
                    .collect();
            if gathered.is_empty() {
                log::warn!("no NAT-traversal candidates gathered (STUN unreachable?)");
            }
            gathered
        }
        None => Vec::new(),
    };

    // Pre-flight the TUN once so an unsupported platform / missing privileges fails
    // *now* with a clean error, rather than the supervisor retrying forever. Drop it
    // immediately; the supervisor's factory reopens a fresh device per attempt.
    device::open(&tun_cfg).map_err(|e| format!("opening TUN device (needs elevation): {e}"))?;

    let id = ClientIdentity {
        public_key,
        name: cfg.name.clone(),
        endpoint: cfg.endpoint.clone(),
        tags: cfg.tags.clone(),
    };
    let private_key = cfg.private_key.clone();
    let coordinator = cfg.coordinator.clone();

    // Rerun the whole mesh session with backoff on any drop. The transport factory
    // is rebuilt per attempt (a session consumes it); the TUN factory lives in
    // `supervise_session`. Only one match arm runs, so each may move `shutdown`.
    match mode {
        TransportMode::Udp => {
            let make_transport = move || async move {
                UdpMeshTransport::bind(bind_addr)
                    .await
                    .map_err(|e| ferrum_client_core::Error::DataPlane(e.to_string()))
            };
            supervise_session(
                client,
                coordinator,
                id,
                private_key,
                tun_cfg,
                make_transport,
                candidates,
                relay,
                shutdown,
            )
            .await
        }
        TransportMode::Quic => {
            let make_transport = move || async move {
                QuicMeshTransport::bind(bind_addr)
                    .await
                    .map_err(|e| ferrum_client_core::Error::DataPlane(e.to_string()))
            };
            supervise_session(
                client,
                coordinator,
                id,
                private_key,
                tun_cfg,
                make_transport,
                candidates,
                relay,
                shutdown,
            )
            .await
        }
        TransportMode::Masque => {
            let proxy = masque_proxy.expect("masque proxy resolved above");
            let make_transport = move || {
                let authority = server_name.clone();
                async move {
                    Ok::<_, ferrum_client_core::Error>(MasqueMeshTransport::new(proxy, authority))
                }
            };
            supervise_session(
                client,
                coordinator,
                id,
                private_key,
                tun_cfg,
                make_transport,
                candidates,
                relay,
                shutdown,
            )
            .await
        }
    }
    .map_err(|e| format!("data plane: {e}"))
}

/// Run the supervised (always-on) mesh session over a chosen transport. Generic
/// over the concrete `MeshTransport` (the runner monomorphizes per type); the TUN
/// factory is built from `tun_cfg` (a session consumes and closes its device, so
/// each reconnect reopens it). `shutdown` winds the whole supervisor down.
// Nine independent inputs (identity, keys, TUN config, the transport factory,
// NAT-traversal candidates + relay, and shutdown). Grouping them into a struct
// would only move the noise, so allow the lint — mirroring the data-plane runner.
#[allow(clippy::too_many_arguments)]
async fn supervise_session<M, MkM, FutM, F>(
    client: &FerrumClient,
    coordinator: String,
    id: ClientIdentity,
    private_key: String,
    tun_cfg: TunConfig,
    make_transport: MkM,
    candidates: Vec<String>,
    relay: Option<String>,
    shutdown: F,
) -> Result<(), ferrum_client_core::Error>
where
    M: MeshTransport + Send + 'static,
    MkM: FnMut() -> FutM + Send,
    FutM: std::future::Future<Output = Result<M, ferrum_client_core::Error>> + Send,
    F: Future<Output = ()> + Send,
{
    let make_device = move || {
        let cfg = tun_cfg.clone();
        async move {
            device::open(&cfg).map_err(|e| {
                ferrum_client_core::Error::DataPlane(format!("opening TUN device: {e}"))
            })
        }
    };
    run_mesh_session_supervised(
        client,
        &coordinator,
        &id,
        &private_key,
        &candidates,
        make_device,
        make_transport,
        relay,
        &ReconnectPolicy::default(),
        shutdown,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_is_case_insensitive_and_rejects_unknown() {
        assert!(matches!(parse_mode("UDP"), Ok(TransportMode::Udp)));
        assert!(matches!(parse_mode("  quic "), Ok(TransportMode::Quic)));
        assert!(matches!(parse_mode("Masque"), Ok(TransportMode::Masque)));
        assert!(parse_mode("wireguard").is_err());
    }

    #[test]
    fn resolve_coordinator_ips_extracts_host() {
        let ips = resolve_coordinator_ips("http://127.0.0.1:50051");
        assert_eq!(ips, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
        // A bare authority (no scheme) also resolves.
        let ips = resolve_coordinator_ips("127.0.0.1:50051");
        assert_eq!(ips, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
        // Unresolvable → empty (strict block).
        assert!(resolve_coordinator_ips("http://").is_empty());
    }
}
