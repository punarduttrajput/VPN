//! GUI-side client for the privileged helper service (Phase 5 — Windows).
//!
//! On Windows the unprivileged GUI does not bring up the data plane itself;
//! [`connect`] opens the helper service's [named pipe](crate::ipc) and asks it to.
//! A writer task serializes outgoing [`Request`]s (the opening `Connect`, plus any
//! later `SetKillSwitch`/`Disconnect`), and a reader task forwards the service's
//! [`Event`] stream to the webview (via [`crate::emit_helper_event`]) until the
//! connection ends — at which point it reports `Disconnected`, so a service crash
//! or stop is reflected in the UI.

#![cfg(windows)]

use tauri::AppHandle;
use tokio::io::split;
use tokio::net::windows::named_pipe::ClientOptions;
use tokio::sync::mpsc;

use crate::ipc::{self, ConnectConfig, Event, Request, ServerMessage};

/// A live control connection to the helper service. Dropping it does not by itself
/// disconnect — send [`Request::Disconnect`] (or close the GUI) to wind the tunnel
/// down. Held in the app state so the connect/disconnect/kill-switch commands can
/// reach the service.
pub struct HelperSession {
    cmd_tx: mpsc::Sender<Request>,
}

impl HelperSession {
    /// Queue a control request to the service (best-effort: a full or closed queue
    /// is dropped, which only happens once the session is already winding down).
    pub fn send(&self, req: Request) {
        let _ = self.cmd_tx.try_send(req);
    }
}

/// Connect to the helper service and start the data plane with `cfg`.
///
/// Fails with a clear message if the service isn't installed/running (the pipe
/// won't open). On success the returned [`HelperSession`] drives further control
/// messages; events flow to the webview from the spawned reader task.
pub async fn connect(app: AppHandle, cfg: ConnectConfig) -> Result<HelperSession, String> {
    let pipe = ClientOptions::new().open(ipc::PIPE_NAME).map_err(|e| {
        format!("connecting to the ferrum-helper service (is it installed and running?): {e}")
    })?;
    let (mut reader, mut writer) = split(pipe);

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Request>(16);
    // Queue the opening Connect before spawning so it's the first frame on the wire.
    cmd_tx
        .try_send(Request::Connect(Box::new(cfg)))
        .map_err(|e| format!("queuing connect request: {e}"))?;

    // Writer task: serialize outgoing requests; a Disconnect (or a write error)
    // ends it.
    tauri::async_runtime::spawn(async move {
        while let Some(req) = cmd_rx.recv().await {
            let is_disconnect = matches!(req, Request::Disconnect);
            if ipc::write_frame(&mut writer, &req).await.is_err() {
                break;
            }
            if is_disconnect {
                break;
            }
        }
    });

    // Reader task: forward the service's events to the webview.
    let app_reader = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            match ipc::read_frame::<_, ServerMessage>(&mut reader).await {
                Ok(Some(ServerMessage::Event(ev))) => crate::emit_helper_event(&app_reader, ev),
                Ok(Some(ServerMessage::Error(e))) => {
                    crate::emit_helper_event(&app_reader, Event::Error(e))
                }
                Ok(Some(ServerMessage::Status { state, .. })) => {
                    crate::emit_helper_event(&app_reader, Event::State(state))
                }
                Ok(Some(ServerMessage::Ack)) => {}
                // EOF or a read error: the session is over.
                Ok(None) => break,
                Err(e) => {
                    log::warn!("helper event stream error: {e}");
                    break;
                }
            }
        }
        // Reflect the closed connection so the UI returns to Disconnected.
        crate::emit_helper_event(&app_reader, Event::State("Disconnected".into()));
    });

    Ok(HelperSession { cmd_tx })
}
