//! Shared data-plane bring-up (Phase 5).
//!
//! One place that turns a validated [`ConnectConfig`] into a running, supervised
//! mesh data plane on a given [`FerrumClient`]. Both callers use it:
//!
//! * the **privileged Windows service** ([`crate::service`]) runs it on its own
//!   client and forwards the client's event stream back to the GUI over the pipe;
//! * the **Unix in-process path** ([`crate::run`]'s `connect`) runs it directly on
//!   the GUI's client (macOS keeps the existing elevated-GUI model; Linux does too,
//!   but [`open_tun`] tries the `ferrum-helper` Unix-socket daemon first — Phase 5).
//!
//! It performs everything platform-independent about bring-up — parse the
//! transport selection, derive the advertised public key, pre-register to learn
//! the coordinator-assigned tunnel address, gather + publish NAT-traversal
//! candidates (if a STUN server is set), build the [`TunConfig`], pre-flight the
//! TUN once via [`open_tun`] for a clean early error, then drive
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

/// Wraps whichever concrete `TunDevice` [`open_tun`] picked (the helper-backed
/// device or a direct open) behind one type. Manual delegation rather than
/// `Box<dyn TunDevice>`: `TunDevice`'s async methods are return-position
/// `impl Future`, which isn't `dyn`-compatible.
#[cfg(unix)]
enum EitherTun<A, B> {
    ViaHelper(A),
    Direct(B),
}

#[cfg(unix)]
impl<A, B> device::TunDevice for EitherTun<A, B>
where
    A: device::TunDevice,
    B: device::TunDevice,
{
    async fn read_packet(&mut self, buf: &mut [u8]) -> ferrum_tunnel::Result<usize> {
        match self {
            EitherTun::ViaHelper(d) => d.read_packet(buf).await,
            EitherTun::Direct(d) => d.read_packet(buf).await,
        }
    }

    async fn write_packet(&mut self, packet: &[u8]) -> ferrum_tunnel::Result<()> {
        match self {
            EitherTun::ViaHelper(d) => d.write_packet(packet).await,
            EitherTun::Direct(d) => d.write_packet(packet).await,
        }
    }
}

/// Open the TUN device, preferring the privileged helper daemon (Phase 5 —
/// Linux) — so this process doesn't need to be elevated itself — and falling
/// back to opening it in-process (which does need elevation) if the daemon
/// isn't reachable. On Windows this runs *inside* the already-privileged
/// `ferrum-helper` service ([`crate::service`]), so it always opens directly;
/// same for macOS, which has no daemon yet.
#[cfg(unix)]
fn open_tun(
    cfg: &TunConfig,
) -> Result<EitherTun<impl device::TunDevice, impl device::TunDevice>, String> {
    match device::open_via_helper(crate::HELPER_SOCK_PATH, cfg) {
        Ok(dev) => Ok(EitherTun::ViaHelper(dev)),
        Err(helper_err) => match device::open(cfg) {
            Ok(dev) => Ok(EitherTun::Direct(dev)),
            Err(direct_err) => Err(format!(
                "opening TUN device: helper unavailable ({helper_err}); direct open also \
                 failed ({direct_err}) — install/start ferrum-helper (see \
                 apps/desktop/README.md) or run this app elevated"
            )),
        },
    }
}

/// Non-Unix: no daemon indirection needed — Windows runs this inside the
/// already-privileged `ferrum-helper` service.
#[cfg(not(unix))]
fn open_tun(cfg: &TunConfig) -> Result<impl device::TunDevice, String> {
    device::open(cfg).map_err(|e| format!("opening TUN device (needs elevated privileges): {e}"))
}

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

/// Parse a list of string IPs, skipping (and logging) malformed entries rather
/// than failing bring-up — leak protection degrades visibly, never fatally.
fn parse_ips_lossy(list: &[String]) -> Vec<IpAddr> {
    list.iter()
        .filter_map(|s| match s.trim().parse() {
            Ok(ip) => Some(ip),
            Err(e) => {
                log::warn!("ignoring invalid DNS server '{s}': {e}");
                None
            }
        })
        .collect()
}

/// Resolve the DNS servers to enforce this session (PRD leak-protection.md):
/// the config's local override when non-empty, else the coordinator-advertised
/// list — the same order as relay selection. Empty means the session runs
/// DNS-unprotected (the caller surfaces that). Best-effort: a control-plane
/// hiccup here degrades to "unprotected", it never blocks bring-up.
pub async fn resolve_dns(cfg: &ConnectConfig) -> Vec<IpAddr> {
    let local = parse_ips_lossy(&cfg.dns_servers);
    if !local.is_empty() {
        return local;
    }
    let Ok(public_key) = ferrum_core::keys::public_base64_from_private(&cfg.private_key) else {
        return Vec::new(); // bring_up will surface the key error itself
    };
    let mut control =
        match ferrum_client_core::ControlClient::connect(cfg.coordinator.clone()).await {
            Ok(c) => c,
            Err(e) => {
                log::warn!("fetching advertised DNS: connecting to coordinator failed: {e}");
                return Vec::new();
            }
        };
    if let Some(token) = cfg.token.clone() {
        control = control.with_token(token);
    }
    match control.advertised_dns(&public_key).await {
        Ok(Some(list)) => parse_ips_lossy(&list),
        Ok(None) => Vec::new(),
        Err(e) => {
            log::warn!("fetching advertised DNS failed: {e}");
            Vec::new()
        }
    }
}

/// Whether this session should block off-tunnel IPv6 (PRD leak-protection.md).
/// `auto` (the default) blocks: the coordinator allocates IPv4 tunnel
/// addresses today, so v6 always rides outside the tunnel unless blocked.
pub fn ipv6_block(cfg: &ConnectConfig) -> bool {
    match cfg.ipv6_policy.trim().to_ascii_lowercase().as_str() {
        "" | "auto" | "block" => true,
        "tunnel" | "off" => false,
        other => {
            log::warn!("unknown ipv6 policy '{other}'; defaulting to auto (block)");
            true
        }
    }
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
    // Outer-transport authentication (SEC-004): the MASQUE proxy's cert pins,
    // and this node's stable QUIC identity (derived from its WireGuard key).
    let cert_pins = ferrum_transport::tls::parse_fingerprints(&cfg.cert_pins)
        .map_err(|e| format!("invalid certificate pin: {e}"))?;
    let tls_identity = ferrum_core::keys::decode_key(&cfg.private_key)
        .map_err(|e| format!("invalid private key: {e}"))
        .and_then(|k| {
            ferrum_transport::TlsIdentity::from_wireguard_key(&k)
                .map_err(|e| format!("deriving TLS identity: {e}"))
        })?;

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
    // SEC-004: over the QUIC mesh, peers dial this node as a TLS server, so
    // publish the pin of the cert it presents (peers then pin it).
    client.set_tls_fingerprint(matches!(mode, TransportMode::Quic).then(|| {
        ferrum_transport::tls::fingerprint_hex(&tls_identity.fingerprint())
    }));

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

    // Pre-flight the TUN once so an unsupported platform / missing privileges (and
    // no reachable helper) fails *now* with a clean error, rather than the
    // supervisor retrying forever. Drop it immediately; the supervisor's factory
    // reopens a fresh device per attempt.
    open_tun(&tun_cfg)?;

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
            let make_transport = move || {
                let id = tls_identity.clone();
                async move {
                    QuicMeshTransport::bind(bind_addr, &id)
                        .await
                        .map_err(|e| ferrum_client_core::Error::DataPlane(e.to_string()))
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
        TransportMode::Masque => {
            let proxy = masque_proxy.expect("masque proxy resolved above");
            let make_transport = move || {
                let authority = server_name.clone();
                let pins = cert_pins.clone();
                async move {
                    Ok::<_, ferrum_client_core::Error>(MasqueMeshTransport::new(
                        proxy, authority, pins,
                    ))
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
        async move { open_tun(&cfg).map_err(ferrum_client_core::Error::DataPlane) }
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
    fn ipv6_block_follows_policy_and_defaults_to_block() {
        let mut cfg = ConnectConfig {
            coordinator: "http://10.0.0.1:50051".into(),
            private_key: String::new(),
            name: String::new(),
            endpoint: String::new(),
            tags: vec![],
            listen_port: 51820,
            transport_mode: "udp".into(),
            masque_proxy: None,
            server_name: None,
            cert_pins: Vec::new(),
            stun_server: None,
            relay: None,
            token: None,
            kill_switch: false,
            dns_servers: vec![],
            ipv6_policy: String::new(),
        };
        // Empty/auto/block all block (coordinator-assigned addresses are v4).
        assert!(ipv6_block(&cfg));
        cfg.ipv6_policy = "Block".into();
        assert!(ipv6_block(&cfg));
        cfg.ipv6_policy = "off".into();
        assert!(!ipv6_block(&cfg));
        cfg.ipv6_policy = "tunnel".into();
        assert!(!ipv6_block(&cfg));
        // Unknown values fail safe (block), with a logged warning.
        cfg.ipv6_policy = "banana".into();
        assert!(ipv6_block(&cfg));
    }

    #[test]
    fn parse_ips_lossy_skips_bad_entries() {
        let ips = parse_ips_lossy(&[
            "10.99.0.53".to_string(),
            "not-an-ip".to_string(),
            " fd00::53 ".to_string(),
        ]);
        assert_eq!(ips.len(), 2);
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
