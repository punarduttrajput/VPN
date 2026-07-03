//! Privileged helper service core (Phase 5 — Windows, FR5).
//!
//! On Windows the data plane needs elevation (the wintun adapter) and the
//! kill-switch needs WFP (also elevated). Rather than run the whole GUI as
//! Administrator, those privileged parts live here, in a long-lived **Windows
//! service** (`ferrum-helper.exe`, installed to run as LocalSystem). The
//! unprivileged GUI is a [named-pipe](crate::ipc) control client.
//!
//! [`serve`] is the accept loop: it owns the pipe, accepts one GUI connection at a
//! time (a host has one tunnel), and for a [`Request::Connect`] runs the data
//! plane on a service-owned [`FerrumClient`] via [`crate::dataplane::bring_up`],
//! enforcing the kill-switch in WFP as the core's `TrafficBlocked` signal flips
//! and streaming every event back over the pipe. Closing the pipe — or the GUI
//! dying — surfaces as EOF and tears the tunnel (and kill-switch) down, so a dead
//! GUI never strands an open tunnel. A service stop (from the SCM) ends the accept
//! loop and any active session the same way.
//!
//! This module is Windows-only; the binary that hosts it ([`mod@crate`]'s
//! `ferrum-helper` bin) wires it to the Service Control Manager.

#![cfg(windows)]

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{mpsc, watch};

use ferrum_client_core::{ClientEvent, FerrumClient};

use crate::dataplane::{self, state_name, TUN_IFACE};
use crate::ipc::{self, ConnectConfig, Event, Request, ServerMessage, PIPE_NAME};
use crate::killswitch::KillSwitch;

/// Map a core [`ClientEvent`] to the pipe-side [`Event`] the GUI consumes.
fn map_event(ev: ClientEvent) -> Event {
    match ev {
        ClientEvent::StateChanged(s) => Event::State(state_name(s)),
        ClientEvent::PeersUpdated(n) => Event::Peers(n),
        ClientEvent::Error(m) => Event::Error(m),
        ClientEvent::TrafficBlocked(b) => Event::TrafficBlocked(b),
    }
}

/// Accept and serve GUI connections on the helper pipe until `global_stop` flips
/// true (the service is stopping).
pub async fn serve(global_stop: watch::Receiver<bool>) -> std::io::Result<()> {
    serve_on(PIPE_NAME, global_stop).await
}

/// The accept loop, parameterized by pipe name (so tests can drive a private
/// pipe). One session at a time: a host runs a single tunnel, and a second GUI
/// connection waits until the first session ends.
async fn serve_on(pipe_name: &str, mut global_stop: watch::Receiver<bool>) -> std::io::Result<()> {
    // The first instance claims the pipe name; subsequent instances reuse it.
    let mut first = true;
    loop {
        if *global_stop.borrow() {
            return Ok(());
        }
        let server = ServerOptions::new()
            .first_pipe_instance(first)
            .create(pipe_name)?;
        first = false;

        tokio::select! {
            _ = global_stop.changed() => {
                if *global_stop.borrow() {
                    return Ok(());
                }
            }
            res = server.connect() => {
                res?;
                if let Err(e) = handle_connection(server, global_stop.clone()).await {
                    log::warn!("helper session ended with error: {e}");
                }
            }
        }
    }
}

/// Handle one connected GUI: read the opening request and, for a `Connect`, run a
/// session; answer a `Ping` (liveness) directly; otherwise reject.
async fn handle_connection(
    server: NamedPipeServer,
    global_stop: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(server);
    match ipc::read_frame::<_, Request>(&mut reader).await? {
        Some(Request::Connect(cfg)) => run_session(*cfg, reader, writer, global_stop).await,
        Some(Request::Ping) => ipc::write_frame(&mut writer, &ServerMessage::Ack).await,
        Some(_) => {
            ipc::write_frame(
                &mut writer,
                &ServerMessage::Error("expected a Connect or Ping as the first message".into()),
            )
            .await
        }
        // Client connected then hung up without a request — nothing to do.
        None => Ok(()),
    }
}

/// Run a full data-plane session for one GUI connection.
///
/// Spawns three cooperating tasks around [`dataplane::bring_up`]: a **writer** that
/// serializes all outbound frames (so the event and request paths never interleave
/// on the wire), an **event forwarder** that mirrors the core's stream to the pipe
/// and enforces the kill-switch in WFP on `TrafficBlocked`, and a **request
/// reader** that applies mid-session control messages and signals shutdown on
/// `Disconnect`/EOF. The session ends — and the tunnel + kill-switch are torn down
/// — when the GUI disconnects or the service stops.
async fn run_session(
    cfg: ConnectConfig,
    mut reader: ReadHalf<NamedPipeServer>,
    writer: WriteHalf<NamedPipeServer>,
    global_stop: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let client = FerrumClient::new();
    // Coordinator address(es), allow-listed by the kill-switch so the control plane
    // can still reconnect while other traffic is blocked.
    let coordinator_ips: Vec<IpAddr> = dataplane::resolve_coordinator_ips(&cfg.coordinator);
    // The service owns kill-switch *enforcement* (WFP needs elevation, which it has).
    let kill_switch = Arc::new(Mutex::new(KillSwitch::default()));

    // Outbound frames flow through one mpsc so the writer task is the sole writer.
    let (out_tx, mut out_rx) = mpsc::channel::<ServerMessage>(64);
    // Session shutdown, flipped by the request reader (Disconnect/EOF) or a writer
    // failure; `bring_up` also stops on the service-wide `global_stop`.
    let (sstop_tx, sstop_rx) = watch::channel(false);

    // Subscribe *before* bring-up so the initial Connecting→Connected transitions
    // aren't missed.
    let mut events = client.subscribe();

    // Writer task: drain the mpsc to the pipe. A write failure (GUI gone) flips
    // session shutdown so the data plane winds down.
    let sstop_writer = sstop_tx.clone();
    let writer_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(msg) = out_rx.recv().await {
            if ipc::write_frame(&mut writer, &msg).await.is_err() {
                let _ = sstop_writer.send(true);
                break;
            }
        }
    });

    // Event forwarder: mirror the core's events to the GUI and enforce the
    // kill-switch as its block/release signal flips.
    let event_tx = out_tx.clone();
    let ks_events = kill_switch.clone();
    let coord_ips = coordinator_ips.clone();
    let event_task = tokio::spawn(async move {
        use tokio::sync::broadcast::error::RecvError;
        loop {
            match events.recv().await {
                Ok(ev) => {
                    if let ClientEvent::TrafficBlocked(blocked) = &ev {
                        let mut ks = ks_events.lock().unwrap();
                        if *blocked {
                            ks.engage(TUN_IFACE, &coord_ips);
                        } else {
                            ks.disengage();
                        }
                    }
                    if event_tx
                        .send(ServerMessage::Event(map_event(ev)))
                        .await
                        .is_err()
                    {
                        break; // writer gone
                    }
                }
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            }
        }
    });

    // Request reader: mid-session control + shutdown detection.
    let req_tx = out_tx.clone();
    let req_client = client.clone();
    let sstop_reader = sstop_tx.clone();
    let request_task = tokio::spawn(async move {
        loop {
            match ipc::read_frame::<_, Request>(&mut reader).await {
                Ok(Some(Request::SetKillSwitch(enabled))) => req_client.set_kill_switch(enabled),
                Ok(Some(Request::GetStatus)) => {
                    let status = ServerMessage::Status {
                        state: state_name(req_client.status()),
                        peers: req_client.peers().len() as u32,
                    };
                    if req_tx.send(status).await.is_err() {
                        break;
                    }
                }
                // Disconnect or a clean EOF (GUI closed the pipe) ends the session.
                Ok(Some(Request::Disconnect)) | Ok(None) => {
                    let _ = sstop_reader.send(true);
                    break;
                }
                // A second Connect / a stray Ping mid-session is ignored.
                Ok(Some(Request::Connect(_))) | Ok(Some(Request::Ping)) => {}
                Err(e) => {
                    log::warn!("helper request stream error: {e}");
                    let _ = sstop_reader.send(true);
                    break;
                }
            }
        }
    });

    // Acknowledge the Connect, then run the data plane until shutdown.
    let _ = out_tx.send(ServerMessage::Ack).await;
    let shutdown = wait_stop(sstop_rx, global_stop);
    let result = dataplane::bring_up(&client, &cfg, shutdown).await;
    if let Err(e) = result {
        let _ = out_tx.send(ServerMessage::Event(Event::Error(e))).await;
    }

    // Teardown: ensure the firewall block is lifted and the tasks stop.
    sstop_tx.send(true).ok();
    kill_switch.lock().unwrap().disengage();
    event_task.abort();
    request_task.abort();
    // Drop the last sender so the writer task drains and exits, then join it.
    drop(out_tx);
    let _ = writer_task.await;
    Ok(())
}

/// Resolve once either watch flips true (session shutdown or service stop).
async fn wait_stop(mut session: watch::Receiver<bool>, mut global: watch::Receiver<bool>) {
    loop {
        if *session.borrow() || *global.borrow() {
            return;
        }
        tokio::select! {
            _ = session.changed() => {}
            _ = global.changed() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::windows::named_pipe::ClientOptions;

    /// End-to-end over a *real* Windows named pipe (no elevation, no coordinator):
    /// the server accepts a connection, the client sends a `Ping`, and the server
    /// answers `Ack`. Exercises `serve_on` → `handle_connection` and the framing
    /// codec on the actual pipe transport the GUI and service use.
    #[tokio::test]
    async fn ping_over_a_real_pipe_is_acked() {
        // A test-private pipe name so it never collides with a running service.
        let name = r"\\.\pipe\ferrum-helper-test-ping";
        let (stop_tx, stop_rx) = watch::channel(false);
        let server = tokio::spawn(serve_on(name, stop_rx));

        // The server creates the pipe instance inside the spawned task, so retry the
        // client open until it exists.
        let mut pipe = loop {
            match ClientOptions::new().open(name) {
                Ok(p) => break p,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        };
        let (mut reader, mut writer) = tokio::io::split(&mut pipe);

        ipc::write_frame(&mut writer, &Request::Ping).await.unwrap();
        let resp: ServerMessage = ipc::read_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(resp, ServerMessage::Ack);

        // Stop the server and let the accept loop wind down.
        stop_tx.send(true).unwrap();
        drop(pipe);
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    }

    /// A non-Connect/Ping opening message is rejected with an error frame rather
    /// than silently dropped, and the connection isn't left hanging.
    #[tokio::test]
    async fn unexpected_first_message_is_rejected() {
        let name = r"\\.\pipe\ferrum-helper-test-reject";
        let (stop_tx, stop_rx) = watch::channel(false);
        let server = tokio::spawn(serve_on(name, stop_rx));

        let mut pipe = loop {
            match ClientOptions::new().open(name) {
                Ok(p) => break p,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        };
        let (mut reader, mut writer) = tokio::io::split(&mut pipe);

        ipc::write_frame(&mut writer, &Request::Disconnect)
            .await
            .unwrap();
        let resp: ServerMessage = ipc::read_frame(&mut reader).await.unwrap().unwrap();
        assert!(matches!(resp, ServerMessage::Error(_)));

        stop_tx.send(true).unwrap();
        drop(pipe);
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    }
}
