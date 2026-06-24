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
//! that task to wind down. The real TUN needs elevated privileges on a
//! Linux/macOS host; on Windows (or without privileges) `connect` surfaces a
//! clean error and the UI stays disconnected.

use std::net::SocketAddr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::oneshot;

use ferrum_client_core::data_plane::run_mesh_session;
use ferrum_client_core::{ClientEvent, ClientIdentity, ConnectionState, FerrumClient};
use ferrum_core::config::Cidr;
use ferrum_transport::UdpMeshTransport;
use ferrum_tunnel::device::{self, TunConfig};

/// TUN interface name requested from the OS (best effort; the OS may rename).
const TUN_IFACE: &str = "ferrum0";
/// Inner TUN MTU for the UDP transport (leaves headroom under a 1500 B path for
/// WireGuard + UDP/IP overhead).
const TUN_MTU: u16 = 1420;

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
    }
}

fn to_ui_event(ev: ClientEvent) -> UiEvent {
    match ev {
        ClientEvent::StateChanged(s) => UiEvent {
            kind: "state",
            state: Some(state_name(s)),
            peers: None,
            message: None,
        },
        ClientEvent::PeersUpdated(n) => UiEvent {
            kind: "peers",
            state: None,
            peers: Some(n),
            message: None,
        },
        ClientEvent::Error(m) => UiEvent {
            kind: "error",
            state: None,
            peers: None,
            message: Some(m),
        },
    }
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
) -> Result<(), String> {
    if state.data_plane.lock().unwrap().is_some() {
        return Err("already connected".into());
    }

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

    // Open the real OS TUN with the assigned address.
    let cidr: Cidr = address
        .parse()
        .map_err(|e| format!("assigned tunnel address '{address}': {e}"))?;
    let tun_cfg = TunConfig {
        name: TUN_IFACE.to_string(),
        address: cidr,
        mtu: TUN_MTU,
    };
    let dev = device::open(&tun_cfg)
        .map_err(|e| format!("opening TUN device (needs privileges on Linux/macOS): {e}"))?;

    // Bind the UDP mesh transport for the data plane.
    let bind_addr: SocketAddr = format!("0.0.0.0:{listen_port}")
        .parse()
        .map_err(|e| format!("invalid listen port {listen_port}: {e}"))?;
    let transport = UdpMeshTransport::bind(bind_addr)
        .await
        .map_err(|e| format!("binding UDP socket on {bind_addr}: {e}"))?;

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
        // No NAT-traversal candidates and no relay fallback yet: the GUI has no
        // STUN-server or relay field, so nothing is gathered/published and the
        // mesh runs direct-only (follow-up: STUN + relay inputs that feed
        // `gather_candidates` / a `RelayMeshTransport` here, like the CLI's
        // `--stun-server` and `transport.relay`).
        let result = run_mesh_session(
            &client,
            &coordinator,
            &id,
            &private_key,
            &[],
            dev,
            transport,
            None,
            async move {
                let _ = stop_rx.await;
            },
        )
        .await;
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
    tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::default()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .manage(AppState {
            client: FerrumClient::new(),
            data_plane: Mutex::new(None),
        })
        .setup(|app| {
            // Forward core events (state / peers / errors) to the webview.
            let client = app.state::<AppState>().client.clone();
            let mut events = client.subscribe();
            let handle: AppHandle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    match events.recv().await {
                        Ok(ev) => {
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
            connect, disconnect, get_status, get_peers
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
