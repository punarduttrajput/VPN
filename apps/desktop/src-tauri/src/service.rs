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
//! The pipe is the service's privilege boundary (SEC-005): it's created with an
//! explicit DACL and remote clients rejected, and every client's token is checked
//! before it's served — see [`crate::pipe_security`].
//!
//! This module is Windows-only; the binary that hosts it ([`mod@crate`]'s
//! `ferrum-helper` bin) wires it to the Service Control Manager.

#![cfg(windows)]

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::{mpsc, watch};

use ferrum_client_core::{ClientEvent, ConnectionState, FerrumClient};

use crate::dataplane::{self, state_name, TUN_IFACE};
use crate::ipc::{self, ConnectConfig, Event, Request, ServerMessage, PIPE_NAME};
use crate::killswitch::KillSwitch;
use crate::leakguard::LeakGuard;
use crate::pipe_security::{self, PipeAccess};

/// Map a core [`ClientEvent`] to the pipe-side [`Event`] the GUI consumes.
fn map_event(ev: ClientEvent) -> Event {
    match ev {
        ClientEvent::StateChanged(s) => Event::State(state_name(s)),
        ClientEvent::PeersUpdated(n) => Event::Peers(n),
        ClientEvent::Error(m) => Event::Error(m),
        ClientEvent::TrafficBlocked(b) => Event::TrafficBlocked(b),
    }
}

/// How long a connected client has to send its opening request before the
/// service hangs up (connections are served one at a time, so an idle one would
/// otherwise block everyone else).
const FIRST_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Accept and serve GUI connections on the helper pipe until `global_stop` flips
/// true (the service is stopping).
pub async fn serve(global_stop: watch::Receiver<bool>) -> std::io::Result<()> {
    serve_on(PIPE_NAME, &PipeAccess::default(), global_stop).await
}

/// The accept loop, parameterized by pipe name and access policy (so tests can
/// drive a private pipe). One session at a time: a host runs a single tunnel, and
/// a second GUI connection waits until the first session ends.
///
/// Every instance is created with the explicit DACL in `access` (never the default
/// descriptor), and every connected client is identity-checked
/// ([`pipe_security::verify_client`]) before a single byte of it is read.
async fn serve_on(
    pipe_name: &str,
    access: &PipeAccess,
    mut global_stop: watch::Receiver<bool>,
) -> std::io::Result<()> {
    // The first instance claims the pipe name (fails if someone already squats
    // it). The next instance is always created *before* the connected one is
    // handled and dropped, so the name is never released between sessions for
    // another process to claim.
    let mut server = pipe_security::create_pipe(pipe_name, true, &access.sddl)?;
    loop {
        if *global_stop.borrow() {
            return Ok(());
        }

        tokio::select! {
            _ = global_stop.changed() => {
                if *global_stop.borrow() {
                    return Ok(());
                }
            }
            res = server.connect() => {
                res?;
                let connected = std::mem::replace(
                    &mut server,
                    pipe_security::create_pipe(pipe_name, false, &access.sddl)?,
                );
                match pipe_security::verify_client(&connected, &access.policy) {
                    Ok(client) => {
                        log::debug!("helper client pid {} admitted", client.pid);
                        if let Err(e) = handle_connection(connected, global_stop.clone()).await {
                            log::warn!("helper session ended with error: {e}");
                        }
                    }
                    Err(reason) => {
                        log::warn!("refused helper pipe client: {reason}");
                        let (_, mut writer) = tokio::io::split(connected);
                        let _ = ipc::write_frame(
                            &mut writer,
                            &ServerMessage::Error("not authorized".into()),
                        )
                        .await;
                    }
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
    let first = tokio::time::timeout(
        FIRST_REQUEST_TIMEOUT,
        ipc::read_frame::<_, Request>(&mut reader),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "no opening request from helper client",
        )
    })??;
    match first {
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
    // Leak protection (PRD leak-protection.md M3): resolved before bring-up so
    // the event forwarder can engage as the session reaches `Connected`.
    let leak_guard = Arc::new(Mutex::new(LeakGuard::default()));
    let leak_dns: Vec<IpAddr> = dataplane::resolve_dns(&cfg).await;
    let leak_block_v6 = dataplane::ipv6_block(&cfg);
    if leak_dns.is_empty() {
        log::warn!("no DNS servers configured or advertised; DNS is unprotected this session");
    }

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

    // Event forwarder: mirror the core's events to the GUI, enforce the
    // kill-switch as its block/release signal flips, and engage/disengage the
    // leak guard as the session comes up / goes down.
    let event_tx = out_tx.clone();
    let ks_events = kill_switch.clone();
    let coord_ips = coordinator_ips.clone();
    let lg_events = leak_guard.clone();
    let lg_dns = leak_dns.clone();
    let event_task = tokio::spawn(async move {
        use tokio::sync::broadcast::error::RecvError;
        loop {
            match events.recv().await {
                Ok(ev) => {
                    match &ev {
                        ClientEvent::TrafficBlocked(blocked) => {
                            let mut ks = ks_events.lock().unwrap();
                            if *blocked {
                                ks.engage(TUN_IFACE, &coord_ips);
                            } else {
                                ks.disengage();
                            }
                        }
                        // Only once the tunnel is up (never at boot / before a
                        // captive portal — NFR2); a repeat `Connected` after a
                        // reconnect is a no-op inside the guard.
                        ClientEvent::StateChanged(ConnectionState::Connected) => {
                            lg_events
                                .lock()
                                .unwrap()
                                .engage(TUN_IFACE, &lg_dns, leak_block_v6);
                        }
                        ClientEvent::StateChanged(ConnectionState::Disconnected) => {
                            lg_events.lock().unwrap().disengage();
                        }
                        _ => {}
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

    // Teardown: ensure the firewall block is lifted, DNS restored, and the
    // tasks stop — a dead GUI (pipe EOF) or a service stop never strands either.
    sstop_tx.send(true).ok();
    kill_switch.lock().unwrap().disengage();
    leak_guard.lock().unwrap().disengage();
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
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
    use windows::Win32::Security::{WinAuthenticatedUserSid, WinInteractiveSid, WinLocalSystemSid};

    use crate::pipe_security::{self, ClientPolicy};

    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_ACCESS_DENIED: i32 = 5;

    /// A DACL + policy that admit any authenticated user, so these tests pass
    /// whatever logon type runs them (the production policy wants an interactive
    /// logon — see `production_access_admits_an_interactive_user`).
    fn test_access() -> PipeAccess {
        PipeAccess {
            sddl: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x12019b;;;AU)".into(),
            policy: ClientPolicy {
                allow: vec![WinAuthenticatedUserSid],
                deny: vec![],
            },
        }
    }

    /// Start `serve_on` for a test-private pipe name (so it never collides with a
    /// running service).
    fn spawn_server(
        name: &'static str,
        access: PipeAccess,
    ) -> (
        watch::Sender<bool>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    ) {
        let (stop_tx, stop_rx) = watch::channel(false);
        let server = tokio::spawn(async move { serve_on(name, &access, stop_rx).await });
        (stop_tx, server)
    }

    /// The server creates the pipe inside its spawned task, so retry the client
    /// open until the name exists; any other outcome is returned.
    async fn open_client(name: &str) -> std::io::Result<NamedPipeClient> {
        loop {
            match ClientOptions::new().open(name) {
                Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {
                    tokio::time::sleep(Duration::from_millis(10)).await
                }
                other => return other,
            }
        }
    }

    async fn ping(pipe: &mut NamedPipeClient) -> ServerMessage {
        let (mut reader, mut writer) = tokio::io::split(pipe);
        ipc::write_frame(&mut writer, &Request::Ping).await.unwrap();
        ipc::read_frame(&mut reader).await.unwrap().unwrap()
    }

    async fn shut_down(
        stop_tx: watch::Sender<bool>,
        server: tokio::task::JoinHandle<std::io::Result<()>>,
    ) {
        stop_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
    }

    /// End-to-end over a *real* Windows named pipe (no elevation, no coordinator):
    /// the server accepts a connection, verifies the client's token, the client
    /// sends a `Ping`, and the server answers `Ack`. Exercises `serve_on` →
    /// `verify_client` → `handle_connection` and the framing codec on the actual
    /// pipe transport the GUI and service use.
    #[tokio::test]
    async fn ping_over_a_real_pipe_is_acked() {
        let name = r"\\.\pipe\ferrum-helper-test-ping";
        let (stop_tx, server) = spawn_server(name, test_access());
        let mut pipe = open_client(name).await.unwrap();
        assert_eq!(ping(&mut pipe).await, ServerMessage::Ack);
        drop(pipe);
        shut_down(stop_tx, server).await;
    }

    /// A non-Connect/Ping opening message is rejected with an error frame rather
    /// than silently dropped, and the connection isn't left hanging.
    #[tokio::test]
    async fn unexpected_first_message_is_rejected() {
        let name = r"\\.\pipe\ferrum-helper-test-reject";
        let (stop_tx, server) = spawn_server(name, test_access());
        let mut pipe = open_client(name).await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(&mut pipe);

        ipc::write_frame(&mut writer, &Request::Disconnect)
            .await
            .unwrap();
        let resp: ServerMessage = ipc::read_frame(&mut reader).await.unwrap().unwrap();
        assert!(matches!(resp, ServerMessage::Error(_)));

        drop(pipe);
        shut_down(stop_tx, server).await;
    }

    /// The production DACL + policy admit the (interactive) user running the tests
    /// — and a client opening with tokio's default `ClientOptions` (GENERIC_READ |
    /// GENERIC_WRITE, identification-level QoS), exactly as the GUI does, gets
    /// through a DACL that withholds `FILE_CREATE_PIPE_INSTANCE`.
    #[tokio::test]
    async fn production_access_admits_an_interactive_user() {
        if !pipe_security::current_process_is_member(WinInteractiveSid) {
            eprintln!("skipping: the test process isn't an interactive logon");
            return;
        }
        let name = r"\\.\pipe\ferrum-helper-test-production";
        let (stop_tx, server) = spawn_server(name, PipeAccess::default());
        let mut pipe = open_client(name).await.unwrap();
        assert_eq!(ping(&mut pipe).await, ServerMessage::Ack);
        drop(pipe);
        shut_down(stop_tx, server).await;
    }

    /// Layer 1: a caller the pipe DACL doesn't grant can't even open the pipe.
    #[tokio::test]
    async fn dacl_denies_a_caller_it_does_not_grant() {
        if pipe_security::current_process_is_member(WinLocalSystemSid) {
            eprintln!("skipping: running as SYSTEM, which the DACL admits");
            return;
        }
        let name = r"\\.\pipe\ferrum-helper-test-dacl-deny";
        let access = PipeAccess {
            sddl: "D:P(A;;GA;;;SY)".into(),
            policy: ClientPolicy::default(),
        };
        let (stop_tx, server) = spawn_server(name, access);
        let err = open_client(name).await.unwrap_err();
        assert_eq!(err.raw_os_error(), Some(ERROR_ACCESS_DENIED), "{err}");
        shut_down(stop_tx, server).await;
    }

    /// Layer 2: a caller the DACL lets in but the token check doesn't admit is
    /// told "not authorized" and hung up on — without its request being served —
    /// and the service keeps accepting (and holding the pipe name) afterwards.
    #[tokio::test]
    async fn client_outside_the_policy_is_refused_after_connect() {
        if pipe_security::current_process_is_member(WinLocalSystemSid) {
            eprintln!("skipping: running as SYSTEM, which the policy admits");
            return;
        }
        let name = r"\\.\pipe\ferrum-helper-test-policy-deny";
        let access = PipeAccess {
            policy: ClientPolicy {
                allow: vec![WinLocalSystemSid],
                deny: vec![],
            },
            ..test_access()
        };
        let (stop_tx, server) = spawn_server(name, access);
        for _ in 0..2 {
            let mut pipe = open_client(name).await.unwrap();
            assert_eq!(
                ping(&mut pipe).await,
                ServerMessage::Error("not authorized".into())
            );
            let (mut reader, _) = tokio::io::split(&mut pipe);
            assert!(ipc::read_frame::<_, ServerMessage>(&mut reader)
                .await
                .map(|m| m.is_none())
                .unwrap_or(true));
        }
        shut_down(stop_tx, server).await;
    }

    /// A deny SID wins over an allow SID.
    #[tokio::test]
    async fn deny_sid_overrides_allow() {
        let name = r"\\.\pipe\ferrum-helper-test-deny-wins";
        let access = PipeAccess {
            policy: ClientPolicy {
                allow: vec![WinAuthenticatedUserSid],
                deny: vec![WinAuthenticatedUserSid],
            },
            ..test_access()
        };
        let (stop_tx, server) = spawn_server(name, access);
        let mut pipe = open_client(name).await.unwrap();
        assert_eq!(
            ping(&mut pipe).await,
            ServerMessage::Error("not authorized".into())
        );
        drop(pipe);
        shut_down(stop_tx, server).await;
    }

    /// Squatting: the pipe name is never released between sessions, so another
    /// process can't claim it (with its own DACL) and wait for the next GUI.
    #[tokio::test]
    async fn pipe_name_stays_claimed_between_sessions() {
        let name = r"\\.\pipe\ferrum-helper-test-claimed";
        let (stop_tx, server) = spawn_server(name, test_access());
        let mut pipe = open_client(name).await.unwrap();
        assert_eq!(ping(&mut pipe).await, ServerMessage::Ack);
        drop(pipe);
        // The session is over; a would-be squatter still can't take the name.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let squat = pipe_security::create_pipe(name, true, "D:P(A;;GA;;;WD)");
        assert!(
            squat.is_err(),
            "pipe name was free to squat after a session"
        );
        // ...and the next real client is still served.
        let mut pipe = open_client(name).await.unwrap();
        assert_eq!(ping(&mut pipe).await, ServerMessage::Ack);
        drop(pipe);
        shut_down(stop_tx, server).await;
    }
}
