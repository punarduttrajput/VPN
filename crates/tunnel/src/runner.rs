//! The async data-plane event loop (PRD FR3 / M5).
//!
//! Throughput note (NFR1): rather than one task processing a single packet at a
//! time (recv → decrypt → await TUN write → repeat, with only one packet ever in
//! flight), the data plane is **pipelined** into concurrent tasks connected by
//! channels so network I/O, crypto, and TUN I/O overlap across CPU cores:
//!
//! ```text
//!   net reader ─inbound_net─┐                         ┌─outbound_net─ net writer
//!                           ├─▶ crypto (owns Session) ─┤
//!   device(read)─inbound_tun┘                         └─outbound_tun─ device(write)
//! ```
//!
//! Crypto stays single-task (WireGuard's per-session nonce ordering is serial),
//! but it no longer blocks on I/O syscalls — those happen in sibling tasks.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};
use vpn_transport::{Transport, BATCH_SIZE};

use crate::device::TunDevice;
use crate::session::{Action, Session, MAX_PACKET};
use crate::Result;

/// Handle returned by [`run`] (reserved for future control).
pub struct RunHandle;

/// Bounded channel depth between pipeline stages (packets).
const CHANNEL_CAP: usize = 1024;

/// Run the pipelined tunnel data plane until `shutdown` resolves.
///
/// * `session`   — the WireGuard session (constructed from config keys)
/// * `device`    — the TUN device (real on Unix, mock in tests)
/// * `transport` — the network transport to the peer (UDP, QUIC, …)
/// * `shutdown`  — completes to request graceful shutdown (FR1 teardown)
pub async fn run<D, T, S>(session: Session, device: D, transport: T, shutdown: S) -> Result<()>
where
    D: TunDevice + Send + 'static,
    T: Transport + Send + Sync + 'static,
    S: Future<Output = ()>,
{
    let transport = Arc::new(transport);

    // Encrypted datagrams peer→us; plaintext packets OS→us.
    let (inbound_net_tx, inbound_net_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAP);
    let (inbound_tun_tx, inbound_tun_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAP);
    // Encrypted datagrams us→peer; plaintext packets us→OS.
    let (outbound_net_tx, outbound_net_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAP);
    let (outbound_tun_tx, outbound_tun_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAP);

    let mut tasks: JoinSet<()> = JoinSet::new();

    // Tasks are resilient: a single transient I/O or packet error is logged and
    // skipped, never tearing down the tunnel (e.g. a UDP ECONNREFUSED from an
    // ICMP unreachable during the startup race must not kill the data plane).

    // --- net reader: transport.recv → inbound_net -------------------------
    // After the blocking recv, drain any further immediately-available datagrams
    // via try_recv so a burst of inbound packets is forwarded to the crypto task
    // in one scheduler timeslice rather than one wake-up per packet.
    {
        let transport = transport.clone();
        tasks.spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET];
            loop {
                match transport.recv(&mut buf).await {
                    Ok(n) => {
                        if inbound_net_tx.send(buf[..n].to_vec()).await.is_err() {
                            break; // crypto task gone
                        }
                        // Drain any additional packets already in the socket buffer.
                        let mut extra = vec![0u8; MAX_PACKET];
                        while let Ok(Some(m)) = transport.try_recv(&mut extra) {
                            if inbound_net_tx.send(extra[..m].to_vec()).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("transport recv error (ignored): {e}");
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }
            }
        });
    }

    // --- net writer: outbound_net → transport.send_batch ------------------
    // Drain the channel into a burst (up to BATCH_SIZE) so we hand multiple
    // datagrams to the transport in a single call — on Linux this becomes a
    // single sendmmsg syscall, cutting per-packet overhead (NFR1).
    {
        let transport = transport.clone();
        let mut rx = outbound_net_rx;
        tasks.spawn(async move {
            let mut batch: Vec<Vec<u8>> = Vec::with_capacity(BATCH_SIZE);
            loop {
                // Wait for at least one packet.
                let Some(first) = rx.recv().await else { break };
                batch.push(first);
                // Drain any additional packets that are already queued.
                while batch.len() < BATCH_SIZE {
                    match rx.try_recv() {
                        Ok(pkt) => batch.push(pkt),
                        Err(_) => break,
                    }
                }
                if let Err(e) = transport.send_batch(&batch).await {
                    debug!("transport send_batch error (ignored): {e}");
                }
                batch.clear();
            }
        });
    }

    // --- device task: TUN read → inbound_tun; outbound_tun → TUN write -----
    {
        let mut device = device;
        let mut out_tun_rx = outbound_tun_rx;
        tasks.spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET];
            loop {
                tokio::select! {
                    read = device.read_packet(&mut buf) => {
                        match read {
                            Ok(n) => {
                                if inbound_tun_tx.send(buf[..n].to_vec()).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => { warn!("TUN read error: {e}"); break; }
                        }
                    }
                    maybe = out_tun_rx.recv() => {
                        match maybe {
                            Some(pkt) => {
                                if let Err(e) = device.write_packet(&pkt).await {
                                    debug!("TUN write error (ignored): {e}");
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        });
    }

    // --- crypto task: owns the Session, drives handshake/encap/decap/timers
    {
        let mut session = session;
        let mut in_net = inbound_net_rx;
        let mut in_tun = inbound_tun_rx;
        let out_net = outbound_net_tx;
        let out_tun = outbound_tun_tx;
        tasks.spawn(async move {
            let mut out = vec![0u8; MAX_PACKET];

            // Kick off the handshake immediately (NFR4: ready quickly).
            match session.start_handshake(&mut out) {
                Ok(Action::SendToPeer(pkt)) => {
                    let _ = out_net.send(pkt.to_vec()).await;
                    debug!("sent initial handshake");
                }
                Ok(_) => {}
                Err(e) => warn!("handshake start error: {e}"),
            }

            let mut timer = tokio::time::interval(Duration::from_millis(250));
            loop {
                tokio::select! {
                    // Inbound encrypted datagram → decrypt → TUN (or a control reply).
                    maybe = in_net.recv() => {
                        let Some(datagram) = maybe else { break };
                        match session.decapsulate(&datagram, &mut out) {
                            Ok(Action::WriteToTun(pkt, _ip)) => { let _ = out_tun.send(pkt.to_vec()).await; }
                            Ok(Action::SendToPeer(pkt)) => { let _ = out_net.send(pkt.to_vec()).await; }
                            Ok(Action::Done) => {}
                            Err(e) => debug!("decapsulate error (dropped packet): {e}"),
                        }
                    }
                    // Outbound plaintext packet → encrypt → peer.
                    maybe = in_tun.recv() => {
                        let Some(packet) = maybe else { break };
                        match session.encapsulate(&packet, &mut out) {
                            Ok(Action::SendToPeer(pkt)) => { let _ = out_net.send(pkt.to_vec()).await; }
                            Ok(_) => {}
                            Err(e) => debug!("encapsulate error (dropped packet): {e}"),
                        }
                    }
                    // Service WireGuard timers (re-handshake / keepalive) — NFR5.
                    _ = timer.tick() => {
                        match session.update_timers(&mut out) {
                            Ok(Action::SendToPeer(pkt)) => { let _ = out_net.send(pkt.to_vec()).await; }
                            Ok(_) => {}
                            Err(e) => debug!("timer update error: {e}"),
                        }
                    }
                }
            }
        });
    }

    info!("tunnel running (pipelined data plane)");

    // Run until shutdown is requested (FR1). Individual stages are resilient, so
    // the tunnel does not tear down on transient per-packet errors.
    tokio::pin!(shutdown);
    shutdown.await;
    info!("shutdown requested; tearing down tunnel");

    // Aborting drops the device (interface teardown) and closes all sockets.
    tasks.shutdown().await;
    Ok(())
}
