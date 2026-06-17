//! The async event loop that wires a [`Session`] to a TUN device and a
//! [`Transport`] (PRD FR3 / M5; Phase 2 makes the transport pluggable).
//!
//! Three concurrent sources are multiplexed with `tokio::select!`:
//!   * outbound packets from the TUN device   -> encapsulate -> transport send
//!   * inbound datagrams from the transport    -> decapsulate -> TUN write
//!   * a periodic timer tick                   -> service handshake / keepalive
//!
//! The session is owned by this single task (no `Mutex`), so each packet costs
//! no lock and no per-packet allocation — the output buffer is reused.

use std::time::Duration;

use tracing::{debug, info, warn};
use vpn_transport::Transport;

use crate::device::TunDevice;
use crate::session::{Action, Session, MAX_PACKET};
use crate::Result;

/// Handle returned by [`run`] (reserved for future control; Phase 1 runs to signal).
pub struct RunHandle;

/// Run the tunnel event loop until `shutdown` resolves.
///
/// * `session`   — the WireGuard session (already constructed from config keys)
/// * `device`    — the TUN device (real on Unix, mock in tests)
/// * `transport` — the network transport to the peer (UDP, QUIC, …)
/// * `shutdown`  — a future that completes to request graceful shutdown (FR1 teardown)
pub async fn run<D, T, S>(
    mut session: Session,
    mut device: D,
    transport: T,
    shutdown: S,
) -> Result<()>
where
    D: TunDevice,
    T: Transport,
    S: std::future::Future<Output = ()>,
{
    // Kick off the handshake immediately so the tunnel is ready quickly (NFR4).
    {
        let mut buf = vec![0u8; MAX_PACKET];
        if let Action::SendToPeer(out) = session.start_handshake(&mut buf)? {
            transport.send(out).await?;
            debug!("sent initial handshake");
        }
    }

    let mut tun_buf = vec![0u8; MAX_PACKET];
    let mut net_buf = vec![0u8; MAX_PACKET];
    // Reused across iterations to avoid a heap allocation per packet (throughput).
    let mut out_buf = vec![0u8; MAX_PACKET];
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    tokio::pin!(shutdown);

    info!("tunnel running");

    loop {
        tokio::select! {
            // Graceful shutdown (Ctrl-C / SIGTERM upstream).
            _ = &mut shutdown => {
                info!("shutdown requested; tearing down tunnel");
                return Ok(());
            }

            // Outbound: OS -> TUN -> encrypt -> transport.
            read = device.read_packet(&mut tun_buf) => {
                let n = read?;
                match session.encapsulate(&tun_buf[..n], &mut out_buf)? {
                    Action::SendToPeer(pkt) => { transport.send(pkt).await?; }
                    Action::Done => {}
                    Action::WriteToTun(..) => { /* not expected on encap */ }
                }
            }

            // Inbound: transport -> decrypt -> TUN.
            recv = transport.recv(&mut net_buf) => {
                let n = recv?;
                match session.decapsulate(&net_buf[..n], &mut out_buf)? {
                    Action::WriteToTun(pkt, _ip) => { device.write_packet(pkt).await?; }
                    // boringtun may ask to flush queued handshake/keepalive packets.
                    Action::SendToPeer(pkt) => { transport.send(pkt).await?; }
                    Action::Done => {}
                }
            }

            // Periodic: service WireGuard timers (re-handshake, keepalive) — NFR5.
            _ = timer.tick() => {
                match session.update_timers(&mut out_buf) {
                    Ok(Action::SendToPeer(pkt)) => { transport.send(pkt).await?; }
                    Ok(_) => {}
                    Err(e) => warn!("timer update error: {e}"),
                }
            }
        }
    }
}
