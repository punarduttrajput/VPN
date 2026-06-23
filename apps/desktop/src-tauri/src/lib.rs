//! Next-Gen VPN desktop shell (Tauri, Phase 5 FR4).
//!
//! A thin GUI over the shared client core: the commands here drive
//! [`vpn_client_core::VpnClient`] (register / disconnect / status / peers) and a
//! background task forwards its event stream to the webview as `client-event`.
//!
//! Scope: this scaffold exercises the platform-independent **control-plane** loop
//! the UI is built on. Bringing up the OS data plane (open a TUN, then
//! `vpn_client_core::data_plane::run_mesh_session`) is the next increment — it
//! needs elevated privileges and a Linux/macOS host, so it is intentionally not
//! wired into the GUI yet.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::broadcast::error::RecvError;

use vpn_client_core::{ClientEvent, ClientIdentity, ConnectionState, VpnClient};

/// Shared application state: the one client the whole UI drives.
struct AppState {
    client: VpnClient,
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
#[derive(Deserialize)]
struct IdentityArg {
    public_key: String,
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

/// Register with the coordinator and load the peer set (drives the state machine).
#[tauri::command]
async fn connect(
    state: State<'_, AppState>,
    coordinator: String,
    identity: IdentityArg,
) -> Result<(), String> {
    let id = ClientIdentity {
        public_key: identity.public_key,
        name: identity.name,
        endpoint: identity.endpoint,
        tags: identity.tags,
    };
    state
        .client
        .connect(coordinator, &id)
        .await
        .map_err(|e| e.to_string())
}

/// Tear down the session view; the client returns to `Disconnected`.
#[tauri::command]
fn disconnect(state: State<'_, AppState>) {
    state.client.disconnect();
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
            client: VpnClient::new(),
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
