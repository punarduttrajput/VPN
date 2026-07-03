//! Ferrum desktop shell (Tauri, Phase 5 FR4).
//!
//! A thin GUI over the shared client core: the commands here drive
//! [`ferrum_client_core::FerrumClient`] (connect / disconnect / status / peers) and a
//! background task forwards its event stream to the webview as `client-event`.
//!
//! `connect` brings up the **OS data plane**: it registers with the coordinator
//! to learn the assigned tunnel address, opens a real TUN with it, binds a UDP
//! mesh transport, and runs [`ferrum_client_core::data_plane::run_mesh_session`] in
//! a background task — so the GUI actually moves packets. `disconnect` signals
//! that task to wind down. Opening the TUN and enforcing the kill-switch both
//! need elevated privileges; on Linux this process tries the privileged helper
//! daemon (Phase 5 — see [`open_tun`], `packaging/systemd/ferrum-helper.service`,
//! and `apps/desktop/README.md`) first, so the GUI itself can stay unprivileged.
//! Without the helper (or on Windows/macOS, or without privileges at all), it
//! falls back to doing the privileged operation in-process, surfacing a clean
//! error if that also fails.

mod identity;
mod killswitch;

use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, RunEvent, State};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::oneshot;

use ferrum_client_core::data_plane::run_mesh_session_supervised;
use ferrum_client_core::{
    ClientEvent, ClientIdentity, ConnectionState, FerrumClient, ReconnectPolicy,
};
use ferrum_core::config::Cidr;
use ferrum_transport::{MasqueMeshTransport, MeshTransport, QuicMeshTransport, UdpMeshTransport};
use ferrum_tunnel::device::{self, TunConfig};

use killswitch::KillSwitch;

/// TUN interface name requested from the OS (best effort; the OS may rename).
const TUN_IFACE: &str = "ferrum0";
/// Inner TUN MTU for the UDP transport (leaves headroom under a 1500 B path for
/// WireGuard + UDP/IP overhead).
const TUN_MTU: u16 = 1420;
/// Smaller inner TUN MTU for the QUIC/MASQUE transports — the extra QUIC + TLS
/// (and, for MASQUE, HTTP/3 CONNECT-UDP) framing eats into the path budget, so
/// the inner MTU is reduced to keep encapsulated datagrams under a 1500 B path
/// (mirrors the CLI's `QUIC_TUN_MTU`).
const QUIC_TUN_MTU: u16 = 1100;
/// Default TLS / HTTP-3 `:authority` name for the QUIC/MASQUE transports when the
/// connect form leaves the server-name field blank (mirrors the CLI default).
const DEFAULT_SERVER_NAME: &str = "ferrum";
/// Unix socket path of the privileged helper daemon (Phase 5), tried before
/// falling back to an in-process TUN open. See
/// `packaging/systemd/ferrum-helper.service` and `apps/desktop/README.md`.
#[cfg(unix)]
pub(crate) const HELPER_SOCK_PATH: &str = "/run/ferrum/helper.sock";

/// Wraps whichever concrete `TunDevice` [`open_tun`] picked (the
/// helper-backed device or a direct in-process open) behind one type. Manual
/// delegation rather than `Box<dyn TunDevice>`: `TunDevice`'s async methods
/// are return-position `impl Future`, which isn't `dyn`-compatible.
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

/// Open the TUN device, preferring the privileged helper daemon (Phase 5) —
/// so this process doesn't need to be elevated itself — and falling back to
/// opening it in-process (which does need elevation) if the helper isn't
/// reachable. On non-Unix (no helper yet) this just opens it in-process.
#[cfg(unix)]
fn open_tun(
    cfg: &TunConfig,
) -> Result<EitherTun<impl device::TunDevice, impl device::TunDevice>, String> {
    match device::open_via_helper(HELPER_SOCK_PATH, cfg) {
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

/// Non-Unix fallback: no helper daemon yet, so this just opens the TUN
/// in-process (needs elevation).
#[cfg(not(unix))]
fn open_tun(cfg: &TunConfig) -> Result<impl device::TunDevice, String> {
    device::open(cfg).map_err(|e| format!("opening TUN device (needs elevated privileges): {e}"))
}

/// A handle to the running data-plane task, kept so `disconnect` can stop it.
struct DataPlaneHandle {
    /// Fires to wind the mesh runner down (it then returns to `Disconnected`).
    shutdown: oneshot::Sender<()>,
}

/// Shared application state: the one client the whole UI drives, plus the
/// currently running data-plane task (if any).
struct AppState {
    client: FerrumClient,
    data_plane: Mutex<Option<DataPlaneHandle>>,
    /// Enforces the kill-switch firewall rules in response to `TrafficBlocked`
    /// events from the core (FR5).
    kill_switch: Mutex<KillSwitch>,
    /// Coordinator address(es) resolved at `connect`, allow-listed by the
    /// kill-switch so the control plane can still reconnect while traffic is
    /// otherwise blocked. Empty until the first connect.
    coordinator_ips: Mutex<Vec<IpAddr>>,
}

/// A peer as presented to the webview.
#[derive(Serialize)]
struct PeerDto {
    public_key: String,
    endpoint: String,
    allowed_ips: Vec<String>,
    path: String,
}

/// Identity fields received from the webview's connect form.
///
/// The form carries the WireGuard **private** key (needed to build the per-peer
/// mesh sessions); the public key advertised to the coordinator is derived from
/// it. The private key never leaves this process.
#[derive(Deserialize)]
struct IdentityArg {
    private_key: String,
    name: String,
    endpoint: String,
    tags: Vec<String>,
}

/// Mesh wire transport chosen in the connect form. Selects which `MeshTransport`
/// the data plane binds — UDP (plain), QUIC (encrypted/camouflaged), or MASQUE
/// (QUIC tunnelled through an HTTP/3 CONNECT-UDP proxy). Mirrors the CLI's
/// `[transport] mode`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TransportMode {
    Udp,
    Quic,
    Masque,
}

/// Transport selection received from the webview's connect form. `mode` is the
/// wire transport; `masque_proxy` (`ip:port`) is required for MASQUE; `server_name`
/// is the TLS / HTTP-3 `:authority` for QUIC/MASQUE (defaults to `ferrum`).
///
/// `stun_server` and `relay` are NAT-traversal settings that apply across all
/// modes (Phase 4): with a `stun_server` the client gathers host + server-reflexive
/// candidates and publishes them so peers can punch a direct path; `relay` is a
/// local `ip:port` override of the coordinator-advertised relay fallback (empty →
/// use whatever the coordinator advertises, or direct-only if none).
#[derive(Deserialize)]
struct TransportArg {
    /// `"udp"` | `"quic"` | `"masque"` (case-insensitive).
    mode: String,
    #[serde(default)]
    masque_proxy: Option<String>,
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    stun_server: Option<String>,
    #[serde(default)]
    relay: Option<String>,
}

impl TransportArg {
    /// Parse the form's `mode` string into a [`TransportMode`].
    fn parse_mode(&self) -> Result<TransportMode, String> {
        match self.mode.trim().to_ascii_lowercase().as_str() {
            "udp" => Ok(TransportMode::Udp),
            "quic" => Ok(TransportMode::Quic),
            "masque" => Ok(TransportMode::Masque),
            other => Err(format!(
                "unknown transport mode '{other}' (expected udp, quic, or masque)"
            )),
        }
    }
}

/// An event pushed to the webview on the `client-event` channel.
#[derive(Clone, Serialize)]
struct UiEvent {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peers: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked: Option<bool>,
}

fn state_name(s: ConnectionState) -> String {
    match s {
        ConnectionState::Disconnected => "Disconnected",
        ConnectionState::Connecting => "Connecting",
        ConnectionState::Connected => "Connected",
        ConnectionState::Reconnecting => "Reconnecting",
        ConnectionState::Failed => "Failed",
    }
    .to_string()
}

/// Build an `error`-kind UI event (used to surface a data-plane failure that
/// happens after `connect` has returned, while the runner task is detached).
fn error_event(message: String) -> UiEvent {
    UiEvent {
        kind: "error",
        state: None,
        peers: None,
        message: Some(message),
        blocked: None,
    }
}

fn to_ui_event(ev: ClientEvent) -> UiEvent {
    match ev {
        ClientEvent::StateChanged(s) => UiEvent {
            kind: "state",
            state: Some(state_name(s)),
            peers: None,
            message: None,
            blocked: None,
        },
        ClientEvent::PeersUpdated(n) => UiEvent {
            kind: "peers",
            state: None,
            peers: Some(n),
            message: None,
            blocked: None,
        },
        ClientEvent::Error(m) => UiEvent {
            kind: "error",
            state: None,
            peers: None,
            message: Some(m),
            blocked: None,
        },
        // The kill-switch's "block non-tunnel traffic" signal flipped (FR5). The
        // backend enforces it via the firewall; the UI reflects the state.
        ClientEvent::TrafficBlocked(b) => UiEvent {
            kind: "kill-switch",
            state: None,
            peers: None,
            message: None,
            blocked: Some(b),
        },
    }
}

/// Best-effort resolve a coordinator URL (`http://host:port`) to its IP
/// address(es), used to allow-list it in the kill-switch so the control plane can
/// reconnect while other traffic is blocked. Returns empty on a parse/resolve
/// failure (the kill-switch then blocks strictly — the safe default).
fn resolve_coordinator_ips(coordinator: &str) -> Vec<IpAddr> {
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

/// Run the supervised (always-on) mesh session over a chosen transport.
///
/// The transport is selected by the caller as a `make_transport` factory so this
/// stays generic over `UdpMeshTransport` / `QuicMeshTransport` /
/// `MasqueMeshTransport` (the data-plane runner monomorphizes per concrete type).
/// The TUN factory is built here from `tun_cfg` — a session consumes and closes
/// its device, so each reconnect attempt reopens it. `stop_rx` winds the whole
/// supervisor down (the facade returns to `Disconnected`).
// Nine independent inputs (identity, keys, TUN config, the transport factory,
// NAT-traversal candidates + relay, and the shutdown channel). Grouping them into
// a struct would only move the noise across the boundary, so allow the lint —
// mirroring `data_plane::run_mesh_session_supervised`.
#[allow(clippy::too_many_arguments)]
async fn supervise_session<M, MkM, FutM>(
    client: FerrumClient,
    coordinator: String,
    id: ClientIdentity,
    private_key: String,
    tun_cfg: TunConfig,
    make_transport: MkM,
    candidates: Vec<String>,
    relay: Option<String>,
    stop_rx: oneshot::Receiver<()>,
) -> Result<(), ferrum_client_core::Error>
where
    M: MeshTransport + Send + 'static,
    MkM: FnMut() -> FutM + Send,
    FutM: std::future::Future<Output = Result<M, ferrum_client_core::Error>> + Send,
{
    let make_device = move || {
        let cfg = tun_cfg.clone();
        async move { open_tun(&cfg).map_err(ferrum_client_core::Error::DataPlane) }
    };
    // `candidates` (gathered from the STUN field, if any) are published on each
    // connect so peers can probe a direct path; `relay` is the local override of
    // the coordinator-advertised relay fallback (`None` → use the advertised one,
    // or direct-only if none). Both come from the connect form (Phase 4).
    run_mesh_session_supervised(
        &client,
        &coordinator,
        &id,
        &private_key,
        &candidates,
        make_device,
        make_transport,
        relay,
        &ReconnectPolicy::default(),
        async move {
            let _ = stop_rx.await;
        },
    )
    .await
}

/// Bring up the data plane: register, open a TUN, and run the mesh session.
///
/// Registers first (out of band) only to learn the coordinator-assigned tunnel
/// address — the TUN needs it before the mesh runner takes over. The runner
/// re-registers idempotently as it drives the facade `Connecting → Connected`,
/// then moves packets over the TUN until `disconnect` signals shutdown.
#[tauri::command]
async fn connect(
    app: AppHandle,
    state: State<'_, AppState>,
    coordinator: String,
    identity: IdentityArg,
    listen_port: u16,
    transport: TransportArg,
) -> Result<(), String> {
    if state.data_plane.lock().unwrap().is_some() {
        return Err("already connected".into());
    }

    // Resolve the transport selection up front so a bad mode / missing-or-malformed
    // MASQUE proxy fails *now* with a clean UI error rather than inside the
    // detached supervisor task. The TLS / HTTP-3 `:authority` defaults to `ferrum`.
    let mode = transport.parse_mode()?;
    let server_name = transport
        .server_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_SERVER_NAME)
        .to_string();
    let masque_proxy: Option<SocketAddr> = match mode {
        TransportMode::Masque => Some(
            transport
                .masque_proxy
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "MASQUE transport requires a proxy address".to_string())?
                .parse()
                .map_err(|e| format!("invalid MASQUE proxy address: {e}"))?,
        ),
        TransportMode::Udp | TransportMode::Quic => None,
    };

    // NAT-traversal settings (Phase 4), validated up front for a clean UI error.
    // `relay` is a local override of the coordinator-advertised relay; `stun_server`
    // turns on candidate gathering. Both apply regardless of transport mode.
    let relay: Option<String> = match transport
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
    let stun_server: Option<SocketAddr> = match transport
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
    let public_key = ferrum_core::keys::public_base64_from_private(&identity.private_key)
        .map_err(|e| format!("deriving public key from private key: {e}"))?;

    // Pre-register to learn the assigned tunnel CIDR (needed to configure the
    // TUN before the runner — which re-registers idempotently — takes over).
    let mut control = ferrum_client_core::ControlClient::connect(coordinator.clone())
        .await
        .map_err(|e| format!("connecting to coordinator: {e}"))?;
    let address = control
        .register(
            &public_key,
            &identity.name,
            &identity.endpoint,
            &identity.tags,
        )
        .await
        .map_err(|e| format!("registering with coordinator: {e}"))?;

    // The assigned tunnel address configures the TUN before the runner takes over.
    let cidr: Cidr = address
        .parse()
        .map_err(|e| format!("assigned tunnel address '{address}': {e}"))?;
    // QUIC/MASQUE add framing overhead, so the inner TUN MTU is reduced for them.
    let mtu = match mode {
        TransportMode::Udp => TUN_MTU,
        TransportMode::Quic | TransportMode::Masque => QUIC_TUN_MTU,
    };
    let tun_cfg = TunConfig {
        name: TUN_IFACE.to_string(),
        address: cidr,
        mtu,
    };
    let bind_addr: SocketAddr = format!("0.0.0.0:{listen_port}")
        .parse()
        .map_err(|e| format!("invalid listen port {listen_port}: {e}"))?;

    // Phase 4 M2: with a STUN server set, gather host + server-reflexive
    // candidates on the data-plane port *before* the supervisor binds it (STUN
    // briefly binds the same port so the mapping matches what peers reach). The
    // supervised session publishes them on each connect so peers can probe a
    // direct path. A flaky/unreachable STUN server never blocks bring-up.
    let candidates: Vec<String> = match stun_server {
        Some(stun) => {
            let gathered: Vec<String> =
                ferrum_transport::stun::gather_candidates(listen_port, Some(stun))
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

    // Pre-flight the TUN once so an unsupported platform / missing privileges
    // (and no reachable helper) fails *now* with a clean UI error, rather than
    // the always-on supervisor retrying a never-succeeding open forever. Drop
    // it immediately; the supervisor's factory reopens a fresh device per
    // attempt (a TUN fd is single-use). On Linux with the helper installed —
    // or with direct privileges — this is a brief re-open.
    open_tun(&tun_cfg)?;

    // Resolve the coordinator so the kill-switch can allow-list it (reconnect
    // while blocked); empty on failure → strict block.
    *state.coordinator_ips.lock().unwrap() = resolve_coordinator_ips(&coordinator);

    // Register the shutdown channel before spawning so a fast-failing runner
    // can't clear a not-yet-stored handle (the task clears it on exit).
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    *state.data_plane.lock().unwrap() = Some(DataPlaneHandle { shutdown: stop_tx });

    let client = state.client.clone();
    let id = ClientIdentity {
        public_key,
        name: identity.name,
        endpoint: identity.endpoint,
        tags: identity.tags,
    };
    let private_key = identity.private_key;
    let task_app = app.clone();
    tauri::async_runtime::spawn(async move {
        // Always-on: rerun the whole mesh session (control sync + OS data plane)
        // with backoff on any drop. The transport factory (rebuilt per attempt, as
        // a session consumes it) is chosen by the selected mode — UDP binds a
        // socket, QUIC binds a quinn endpoint, MASQUE opens CONNECT-UDP sessions
        // through the proxy. The TUN factory lives in `supervise_session`.
        let result = match mode {
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
                    stop_rx,
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
                    stop_rx,
                )
                .await
            }
            TransportMode::Masque => {
                // Validated non-`None` above for MASQUE.
                let proxy = masque_proxy.expect("masque proxy resolved above");
                let make_transport = move || {
                    let authority = server_name.clone();
                    async move {
                        Ok::<_, ferrum_client_core::Error>(MasqueMeshTransport::new(
                            proxy, authority,
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
                    stop_rx,
                )
                .await
            }
        };
        if let Err(e) = result {
            log::error!("data plane stopped with error: {e}");
            let _ = task_app.emit("client-event", error_event(format!("data plane: {e}")));
        }
        // Clear the handle so a later `connect` can start cleanly.
        let _ = task_app
            .state::<AppState>()
            .data_plane
            .lock()
            .unwrap()
            .take();
    });

    Ok(())
}

/// Stop the data plane (if running); the client returns to `Disconnected`.
#[tauri::command]
fn disconnect(state: State<'_, AppState>) {
    if let Some(handle) = state.data_plane.lock().unwrap().take() {
        // Signal the runner to wind down; it drives the facade back to
        // `Disconnected` and clears nothing else (the handle is already taken).
        let _ = handle.shutdown.send(());
    } else {
        // No data plane running — reset the facade view directly.
        state.client.disconnect();
    }
}

/// Arm or disarm the kill-switch (FR5). When armed, the core emits
/// `TrafficBlocked` as the tunnel goes up/down and the backend enforces the
/// firewall rules; this only sets the policy.
#[tauri::command]
fn set_kill_switch(state: State<'_, AppState>, enabled: bool) {
    state.client.set_kill_switch(enabled);
}

/// Whether the kill-switch is armed (for the initial UI paint).
#[tauri::command]
fn kill_switch_enabled(state: State<'_, AppState>) -> bool {
    state.client.kill_switch_enabled()
}

/// Generate a fresh WireGuard keypair for first-run identity setup (GUI PRD
/// FR1). Returns `(private_key, public_key)`, both base64; the caller shows
/// the public key (safe to display) and saves the private key via
/// `save_identity` once the user confirms the rest of the profile.
#[tauri::command]
fn generate_identity() -> (String, String) {
    identity::generate_keypair()
}

/// Persist the identity/profile to OS-backed secure storage (GUI PRD FR1),
/// overwriting any previously saved one.
#[tauri::command]
fn save_identity(profile: identity::Identity) -> Result<(), String> {
    identity::save(&profile)
}

/// Load the saved identity/profile, if any (`None` on first run — not an error).
#[tauri::command]
fn load_identity() -> Result<Option<identity::Identity>, String> {
    identity::load()
}

/// Remove the saved identity ("reset identity" in the UI). Idempotent.
#[tauri::command]
fn clear_identity() -> Result<(), String> {
    identity::clear()
}

/// The current connection state (for the initial UI paint).
#[tauri::command]
fn get_status(state: State<'_, AppState>) -> String {
    state_name(state.client.status())
}

/// The current peer list.
#[tauri::command]
fn get_peers(state: State<'_, AppState>) -> Vec<PeerDto> {
    state
        .client
        .peers()
        .into_iter()
        .map(|p| PeerDto {
            public_key: p.public_key,
            endpoint: p.endpoint,
            allowed_ips: p.allowed_ips,
            path: format!("{:?}", p.path),
        })
        .collect()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::default()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .manage(AppState {
            client: FerrumClient::new(),
            data_plane: Mutex::new(None),
            kill_switch: Mutex::new(KillSwitch::default()),
            coordinator_ips: Mutex::new(Vec::new()),
        })
        .setup(|app| {
            // Forward core events to the webview, and enforce the kill-switch's
            // block/release signal in the OS firewall as it flips (FR5).
            let client = app.state::<AppState>().client.clone();
            let mut events = client.subscribe();
            let handle: AppHandle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    match events.recv().await {
                        Ok(ev) => {
                            if let ClientEvent::TrafficBlocked(blocked) = &ev {
                                let st = handle.state::<AppState>();
                                if *blocked {
                                    let ips = st.coordinator_ips.lock().unwrap().clone();
                                    st.kill_switch.lock().unwrap().engage(TUN_IFACE, &ips);
                                } else {
                                    st.kill_switch.lock().unwrap().disengage();
                                }
                            }
                            let _ = handle.emit("client-event", to_ui_event(ev));
                        }
                        // A lagging UI just misses intermediate events.
                        Err(RecvError::Lagged(_)) => continue,
                        Err(RecvError::Closed) => break,
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            connect,
            disconnect,
            get_status,
            get_peers,
            set_kill_switch,
            kill_switch_enabled,
            generate_identity,
            save_identity,
            load_identity,
            clear_identity
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app_handle, event| {
        // On exit, tear down any kill-switch firewall rules so the network isn't
        // left blocked (managed-state `Drop` isn't guaranteed on exit).
        if let RunEvent::Exit = event {
            app_handle
                .state::<AppState>()
                .kill_switch
                .lock()
                .unwrap()
                .disengage();
        }
    });
}
