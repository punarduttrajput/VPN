//! Ferrum desktop shell (Tauri, Phase 5 FR4/FR5).
//!
//! A thin GUI over the shared client core. The connect/disconnect/kill-switch
//! commands drive the data plane and a background task forwards events to the
//! webview as `client-event`.
//!
//! **Privilege model differs by OS (Phase 5 privileged-helper):**
//!
//! * **Windows** — the data plane (wintun adapter) and the kill-switch (WFP) both
//!   need elevation, so they run in a separate privileged **service**
//!   (`ferrum-helper.exe`, see [`service`]). This GUI stays unprivileged and is a
//!   [named-pipe](ipc) control client ([`helper_client`]): `connect` ships a
//!   [`ipc::ConnectConfig`] to the service, which brings the tunnel up and streams
//!   events back.
//! * **Linux** — the GUI brings the data plane up **in-process** via
//!   [`dataplane::bring_up`], same call shape as Windows/macOS, but
//!   [`dataplane::open_tun`] tries a privileged **`ferrum-helper` Unix-socket
//!   daemon** first (Phase 5 — `packaging/systemd/ferrum-helper.service`,
//!   `apps/desktop/README.md`), so the GUI itself can stay unprivileged there
//!   too; the kill-switch's `nft` calls do the same (see `killswitch::ask_helper`).
//!   Without the daemon (or without privileges at all), both fall back to doing
//!   the privileged operation in-process, surfacing a clean error if that also fails.
//! * **macOS** — the GUI brings the data plane up **in-process** (the existing
//!   elevated-GUI model); kill-switch enforcement (`pf`) is a follow-up.
//!
//! Both privilege models share [`dataplane`] for the actual bring-up and
//! [`ipc::ConnectConfig`] as the parameter bundle.

pub mod dataplane;
mod identity;
pub mod ipc;
mod killswitch;
mod leakguard;

#[cfg(windows)]
mod helper_client;
#[cfg(windows)]
pub mod pipe_security;
#[cfg(windows)]
pub mod service;

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, RunEvent, State};

use ferrum_client_core::{ConnectionState, FerrumClient};

use dataplane::state_name;
use ipc::ConnectConfig;

#[cfg(not(windows))]
use std::net::IpAddr;
#[cfg(not(windows))]
use tokio::sync::oneshot;

#[cfg(not(windows))]
use ferrum_client_core::ClientEvent;
#[cfg(not(windows))]
use killswitch::KillSwitch;
#[cfg(not(windows))]
use leakguard::LeakGuard;

/// A running data-plane session, kept so `disconnect` can wind it down. The
/// representation differs by privilege model: an in-process shutdown channel on
/// Unix, a helper-service control connection on Windows.
enum Session {
    /// Unix: the in-process [`dataplane::bring_up`] task; the channel signals it
    /// to wind down.
    #[cfg(not(windows))]
    InProcess(oneshot::Sender<()>),
    /// Windows: the named-pipe control connection to the helper service.
    #[cfg(windows)]
    Helper(helper_client::HelperSession),
}

/// Unix socket path of the privileged helper daemon (Phase 5 — Linux), tried by
/// [`dataplane::open_tun`] and `killswitch::ask_helper` before falling back to
/// an in-process TUN open / direct `nft` call. See
/// `packaging/systemd/ferrum-helper.service` and `apps/desktop/README.md`.
#[cfg(unix)]
pub(crate) const HELPER_SOCK_PATH: &str = "/run/ferrum/helper.sock";

/// Shared application state.
struct AppState {
    /// The connection facade. On Unix it owns the in-process data plane; on
    /// Windows it is the GUI's record of the armed kill-switch state / bearer token
    /// (the *service* owns the real connection), and the connection state shown in
    /// the UI is tracked in [`Self::status`] from the event stream.
    client: FerrumClient,
    /// The running session (if any).
    session: Mutex<Option<Session>>,
    /// Latest connection-state string, updated from the event stream — the source
    /// of truth for `get_status` (works whether events come from the in-process
    /// core or the helper service).
    status: Mutex<String>,
    /// Kill-switch firewall enforcer (Unix `nft`). On Windows enforcement lives in
    /// the helper service (WFP), so this field is Unix-only.
    #[cfg(not(windows))]
    kill_switch: Mutex<KillSwitch>,
    /// Coordinator address(es) resolved at connect, allow-listed by the Unix
    /// kill-switch so the control plane can reconnect while traffic is blocked.
    #[cfg(not(windows))]
    coordinator_ips: Mutex<Vec<IpAddr>>,
    /// Leak-protection enforcer (PRD leak-protection.md M2): system DNS + the
    /// leak-guard firewall, engaged as the session reaches `Connected` and
    /// disengaged on disconnect/exit. Windows enforcement lives in the helper
    /// service (M3), so this is Unix-only like the kill-switch.
    #[cfg(not(windows))]
    leak_guard: Mutex<LeakGuard>,
    /// The DNS servers + IPv6-block decision resolved at connect (local
    /// override else coordinator-advertised), consumed by the event loop when
    /// `Connected` fires. `None` until a connect resolves them.
    #[cfg(not(windows))]
    leak_params: Mutex<Option<(Vec<IpAddr>, bool)>>,
}

/// A peer as presented to the webview.
#[derive(Serialize)]
struct PeerDto {
    public_key: String,
    endpoint: String,
    allowed_ips: Vec<String>,
    path: String,
}

/// Identity fields from the connect form. The WireGuard **private** key (used to
/// build per-peer sessions) is carried here; the advertised public key is derived
/// from it and the private key never leaves this host's processes.
#[derive(Deserialize)]
struct IdentityArg {
    private_key: String,
    name: String,
    endpoint: String,
    tags: Vec<String>,
    /// OIDC bearer token, required on every gRPC call when the coordinator is
    /// built with `--oidc-issuer` (see `FerrumClient::set_token`).
    #[serde(default)]
    token: Option<String>,
}

/// Transport selection from the connect form. Mirrors the CLI's `[transport]`.
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
    /// Comma-separated DNS resolver IPs — a local override of the
    /// coordinator-advertised list (PRD leak-protection.md M5).
    #[serde(default)]
    dns_servers: Option<String>,
    /// IPv6 leak policy: `""`/`"auto"` | `"block"` | `"tunnel"` | `"off"`.
    #[serde(default)]
    ipv6_policy: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_protected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv6_blocked: Option<bool>,
}

/// A `UiEvent` with every optional field unset; constructors fill their own.
const EMPTY_UI_EVENT: UiEvent = UiEvent {
    kind: "",
    state: None,
    peers: None,
    message: None,
    blocked: None,
    dns_protected: None,
    ipv6_blocked: None,
};

impl UiEvent {
    fn state(s: String) -> Self {
        UiEvent {
            kind: "state",
            state: Some(s),
            ..EMPTY_UI_EVENT
        }
    }
    fn peers(n: u32) -> Self {
        UiEvent {
            kind: "peers",
            peers: Some(n),
            ..EMPTY_UI_EVENT
        }
    }
    fn error(message: String) -> Self {
        UiEvent {
            kind: "error",
            message: Some(message),
            ..EMPTY_UI_EVENT
        }
    }
    fn kill_switch(blocked: bool) -> Self {
        UiEvent {
            kind: "kill-switch",
            blocked: Some(blocked),
            ..EMPTY_UI_EVENT
        }
    }
    /// What this session's leak protection resolved to (PRD leak-protection.md
    /// M5) — drives the "DNS protected / IPv6 blocked" chips, including the
    /// honest warning state when nothing protects DNS.
    fn leak_protection(dns_protected: bool, ipv6_blocked: bool) -> Self {
        UiEvent {
            kind: "leak-protection",
            dns_protected: Some(dns_protected),
            ipv6_blocked: Some(ipv6_blocked),
            ..EMPTY_UI_EVENT
        }
    }
}

#[cfg(not(windows))]
fn to_ui_event(ev: ClientEvent) -> UiEvent {
    match ev {
        ClientEvent::StateChanged(s) => UiEvent::state(state_name(s)),
        ClientEvent::PeersUpdated(n) => UiEvent::peers(n),
        ClientEvent::Error(m) => UiEvent::error(m),
        ClientEvent::TrafficBlocked(b) => UiEvent::kill_switch(b),
    }
}

#[cfg(windows)]
fn ui_event_from_ipc(ev: ipc::Event) -> UiEvent {
    match ev {
        ipc::Event::State(s) => UiEvent::state(s),
        ipc::Event::Peers(n) => UiEvent::peers(n),
        ipc::Event::Error(m) => UiEvent::error(m),
        ipc::Event::TrafficBlocked(b) => UiEvent::kill_switch(b),
    }
}

/// Cache the latest connection-state string from a UI event so `get_status` can
/// report it regardless of where events originate.
fn cache_state(state: &AppState, ev: &UiEvent) {
    if let Some(s) = &ev.state {
        *state.status.lock().unwrap() = s.clone();
    }
}

/// Forward a helper-service event to the webview (Windows). Caches the connection
/// state and, when the service reports `Disconnected` (session ended), clears the
/// stored session so a later `connect` starts cleanly.
#[cfg(windows)]
pub(crate) fn emit_helper_event(app: &AppHandle, ev: ipc::Event) {
    let ui = ui_event_from_ipc(ev);
    let st = app.state::<AppState>();
    cache_state(&st, &ui);
    if ui.state.as_deref() == Some("Disconnected") {
        let _ = st.session.lock().unwrap().take();
    }
    let _ = app.emit("client-event", ui);
}

/// Build the data-plane parameter bundle from the connect-form args.
fn build_config(
    coordinator: String,
    identity: IdentityArg,
    listen_port: u16,
    transport: TransportArg,
    kill_switch: bool,
) -> ConnectConfig {
    ConnectConfig {
        coordinator,
        private_key: identity.private_key,
        name: identity.name,
        endpoint: identity.endpoint,
        tags: identity.tags,
        listen_port,
        transport_mode: transport.mode,
        masque_proxy: transport.masque_proxy,
        server_name: transport.server_name,
        cert_pins: Vec::new(), // no GUI field yet (SEC-004): unpinned, with a warning
        stun_server: transport.stun_server,
        relay: transport.relay,
        token: identity.token,
        kill_switch,
        // Leak protection (PRD leak-protection.md M5): the Advanced form's
        // comma-separated override; empty means coordinator-advertised.
        dns_servers: transport
            .dns_servers
            .as_deref()
            .map(|s| {
                s.split(',')
                    .map(|part| part.trim().to_string())
                    .filter(|part| !part.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        ipv6_policy: transport.ipv6_policy.unwrap_or_default(),
    }
}

/// Bring up the data plane. On Windows this hands a [`ConnectConfig`] to the
/// privileged helper service over the pipe; on Unix it runs
/// [`dataplane::bring_up`] in-process. In both cases the connection state and any
/// failure surface asynchronously as `client-event`s.
#[tauri::command]
async fn connect(
    app: AppHandle,
    state: State<'_, AppState>,
    coordinator: String,
    identity: IdentityArg,
    listen_port: u16,
    transport: TransportArg,
) -> Result<(), String> {
    if state.session.lock().unwrap().is_some() {
        return Err("already connected".into());
    }
    let kill_switch = state.client.kill_switch_enabled();
    let cfg = build_config(coordinator, identity, listen_port, transport, kill_switch);

    #[cfg(windows)]
    {
        // The GUI is unprivileged: ask the helper service to bring the tunnel up.
        // Mirror the service's leak-protection resolution for display only — the
        // chips show what the session will enforce (the service resolves and
        // enforces independently).
        let display_cfg = cfg.clone();
        let display_app = app.clone();
        tauri::async_runtime::spawn(async move {
            let dns = dataplane::resolve_dns(&display_cfg).await;
            let block_v6 = dataplane::ipv6_block(&display_cfg);
            let _ = display_app.emit(
                "client-event",
                UiEvent::leak_protection(!dns.is_empty(), block_v6),
            );
        });
        let session = helper_client::connect(app.clone(), cfg).await?;
        *state.session.lock().unwrap() = Some(Session::Helper(session));
        *state.status.lock().unwrap() = "Connecting".into();
        Ok(())
    }
    #[cfg(not(windows))]
    {
        connect_in_process(app, state, cfg)
    }
}

/// Unix: run the data plane in-process and forward its outcome as events. Resolves
/// the coordinator for the kill-switch allow-list, registers a shutdown channel,
/// then spawns the supervised bring-up on a clone of the facade.
#[cfg(not(windows))]
fn connect_in_process(
    app: AppHandle,
    state: State<'_, AppState>,
    cfg: ConnectConfig,
) -> Result<(), String> {
    *state.coordinator_ips.lock().unwrap() = dataplane::resolve_coordinator_ips(&cfg.coordinator);

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    *state.session.lock().unwrap() = Some(Session::InProcess(stop_tx));
    *state.status.lock().unwrap() = "Connecting".into();

    let client = state.client.clone();
    tauri::async_runtime::spawn(async move {
        // Resolve this session's leak protection (local override else
        // coordinator-advertised DNS; v6 policy) *before* bring-up starts, so
        // the parameters are in place when the event loop sees `Connected`.
        let dns = dataplane::resolve_dns(&cfg).await;
        let block_v6 = dataplane::ipv6_block(&cfg);
        if dns.is_empty() {
            log::warn!("no DNS servers configured or advertised; DNS is unprotected this session");
        }
        let _ = app.emit(
            "client-event",
            UiEvent::leak_protection(!dns.is_empty(), block_v6),
        );
        *app.state::<AppState>().leak_params.lock().unwrap() = Some((dns, block_v6));

        let result = dataplane::bring_up(&client, &cfg, async move {
            let _ = stop_rx.await;
        })
        .await;
        if let Err(e) = result {
            log::error!("data plane stopped with error: {e}");
            let _ = app.emit("client-event", UiEvent::error(e));
        }
        // Clear the handle so a later connect starts cleanly.
        let _ = app.state::<AppState>().session.lock().unwrap().take();
    });
    Ok(())
}

/// Stop the data plane (if running); the connection returns to `Disconnected`.
#[tauri::command]
fn disconnect(state: State<'_, AppState>) {
    let session = state.session.lock().unwrap().take();
    match session {
        #[cfg(not(windows))]
        Some(Session::InProcess(shutdown)) => {
            let _ = shutdown.send(());
        }
        #[cfg(windows)]
        Some(Session::Helper(helper)) => {
            helper.send(ipc::Request::Disconnect);
        }
        None => {
            // Nothing running — reset the facade view directly.
            state.client.disconnect();
            *state.status.lock().unwrap() = "Disconnected".into();
        }
    }
}

/// Arm or disarm the kill-switch (FR5). Records the armed state on the facade (so
/// it is carried into the next `connect`) and, on Windows with a live session,
/// forwards the change to the helper service that enforces it.
#[tauri::command]
fn set_kill_switch(state: State<'_, AppState>, enabled: bool) {
    state.client.set_kill_switch(enabled);
    #[cfg(windows)]
    if let Some(Session::Helper(helper)) = &*state.session.lock().unwrap() {
        helper.send(ipc::Request::SetKillSwitch(enabled));
    }
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
    state.status.lock().unwrap().clone()
}

/// The current peer list. On Windows the live peer detail lives in the helper
/// service; the GUI tracks the peer *count* via events (a `peers` UI event), so
/// this returns the in-process facade's list (empty under the service model) — full
/// peer-list forwarding over the pipe is a follow-up.
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

fn new_app_state() -> AppState {
    AppState {
        client: FerrumClient::new(),
        session: Mutex::new(None),
        status: Mutex::new(state_name(ConnectionState::Disconnected)),
        #[cfg(not(windows))]
        kill_switch: Mutex::new(KillSwitch::default()),
        #[cfg(not(windows))]
        coordinator_ips: Mutex::new(Vec::new()),
        #[cfg(not(windows))]
        leak_guard: Mutex::new(LeakGuard::default()),
        #[cfg(not(windows))]
        leak_params: Mutex::new(None),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::default()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .manage(new_app_state())
        .setup(|app| {
            setup_event_forwarding(app);
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
        // On exit, tear down any Unix kill-switch rules so the network isn't left
        // blocked. On Windows the helper service owns the firewall and tears it
        // down when the GUI's pipe closes (process exit), so nothing to do here.
        if let RunEvent::Exit = event {
            let _ = app_handle;
            #[cfg(not(windows))]
            {
                let state = app_handle.state::<AppState>();
                state.kill_switch.lock().unwrap().disengage();
                // Restore DNS + drop the leak-guard table too, so an app exit
                // never strands the system on the tunnel resolver.
                state.leak_guard.lock().unwrap().disengage();
            }
        }
    });
}

/// On Unix, forward the in-process core's event stream to the webview, caching
/// state and enforcing the `nft` kill-switch as `TrafficBlocked` flips. On Windows
/// the GUI's facade is idle (the helper service is the event source — see
/// [`helper_client`]), so there's nothing to forward here.
#[cfg(not(windows))]
fn setup_event_forwarding(app: &tauri::App) {
    use tokio::sync::broadcast::error::RecvError;

    let client = app.state::<AppState>().client.clone();
    let mut events = client.subscribe();
    let handle: AppHandle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        loop {
            match events.recv().await {
                Ok(ev) => {
                    match &ev {
                        ClientEvent::TrafficBlocked(blocked) => {
                            let st = handle.state::<AppState>();
                            if *blocked {
                                let ips = st.coordinator_ips.lock().unwrap().clone();
                                st.kill_switch
                                    .lock()
                                    .unwrap()
                                    .engage(dataplane::TUN_IFACE, &ips);
                            } else {
                                st.kill_switch.lock().unwrap().disengage();
                            }
                        }
                        // Leak protection engages only once the tunnel is up
                        // (never at boot / before a captive portal — NFR2) and
                        // re-engages idempotently on every reconnect.
                        ClientEvent::StateChanged(ConnectionState::Connected) => {
                            let st = handle.state::<AppState>();
                            let params = st.leak_params.lock().unwrap().clone();
                            if let Some((dns, block_v6)) = params {
                                st.leak_guard.lock().unwrap().engage(
                                    dataplane::TUN_IFACE,
                                    &dns,
                                    block_v6,
                                );
                            }
                        }
                        ClientEvent::StateChanged(ConnectionState::Disconnected) => {
                            handle
                                .state::<AppState>()
                                .leak_guard
                                .lock()
                                .unwrap()
                                .disengage();
                        }
                        _ => {}
                    }
                    let ui = to_ui_event(ev);
                    cache_state(&handle.state::<AppState>(), &ui);
                    let _ = handle.emit("client-event", ui);
                }
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            }
        }
    });
}

#[cfg(windows)]
fn setup_event_forwarding(_app: &tauri::App) {
    // Windows: events arrive from the helper service via `emit_helper_event`.
}
