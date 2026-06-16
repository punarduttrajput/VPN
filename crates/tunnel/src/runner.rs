//! The async event loop that wires a [`Session`] to a TUN device and a UDP
//! socket (PRD FR3 / M5).
//!
//! Three concurrent sources are multiplexed with `tokio::select!`:
//!   * outbound packets from the TUN device  -> encapsulate -> UDP send
//!   * inbound datagrams from the UDP socket  -> decapsulate -> TUN write
//!   * a periodic timer tick                  -> service handshake / keepalive

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::device::TunDevice;
use crate::session::{Action, Session, MAX_PACKET};
use crate::Result;

/// Handle returned by [`run`] (reserved for future control; Phase 1 runs to signal).
pub struct RunHandle;

/// Run the tunnel event loop until `shutdown` resolves.
///
/// * `session`  — the WireGuard session (already constructed from config keys)
/// * `device`   — the TUN device (real on Unix, mock in tests)
/// * `socket`   — bound UDP socket
/// * `peer`     — the peer's UDP endpoint to send to
/// * `shutdown` — a future that completes to request graceful shutdown (FR1 teardown)
pub async fn run<D, S>(
    session: Session,
    mut device: D,
    socket: UdpSocket,
    peer: SocketAddr,
    shutdown: S,
) -> Result<()>
where
    D: TunDevice,
    S: std::future::Future<Output = ()>,
{
    let session = Arc::new(Mutex::new(session));
    let socket = Arc::new(socket);

    // Kick off the handshake immediately so the tunnel is ready quickly (NFR4).
    {
        let mut s = session.lock().await;
        let mut buf = vec![0u8; MAX_PACKET];
        if let Action::SendToPeer(out) = s.start_handshake(&mut buf)? {
            socket.send_to(out, peer).await?;
            debug!("sent initial handshake");
        }
    }

    let mut tun_buf = vec![0u8; MAX_PACKET];
    let mut udp_buf = vec![0u8; MAX_PACKET];
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    tokio::pin!(shutdown);

    info!("tunnel running; peer endpoint {peer}");

    loop {
        tokio::select! {
            // Graceful shutdown (Ctrl-C / SIGTERM upstream).
            _ = &mut shutdown => {
                info!("shutdown requested; tearing down tunnel");
                return Ok(());
            }

            // Outbound: OS -> TUN -> encrypt -> UDP.
            read = device.read_packet(&mut tun_buf) => {
                let n = read?;
                let mut out = vec![0u8; MAX_PACKET];
                let mut s = session.lock().await;
                match s.encapsulate(&tun_buf[..n], &mut out)? {
                    Action::SendToPeer(pkt) => { socket.send_to(pkt, peer).await?; }
                    Action::Done => {}
                    Action::WriteToTun(..) => { /* not expected on encap */ }
                }
            }

            // Inbound: UDP -> decrypt -> TUN.
            recv = socket.recv_from(&mut udp_buf) => {
                let (n, _from) = recv?;
                let mut out = vec![0u8; MAX_PACKET];
                let mut s = session.lock().await;
                match s.decapsulate(&udp_buf[..n], &mut out)? {
                    Action::WriteToTun(pkt, _ip) => {
                        let pkt = pkt.to_vec();
                        drop(s);
                        device.write_packet(&pkt).await?;
                    }
                    // boringtun may ask to flush queued handshake/keepalive packets.
                    Action::SendToPeer(pkt) => { socket.send_to(pkt, peer).await?; }
                    Action::Done => {}
                }
            }

            // Periodic: service WireGuard timers (re-handshake, keepalive) — NFR5.
            _ = timer.tick() => {
                let mut out = vec![0u8; MAX_PACKET];
                let mut s = session.lock().await;
                match s.update_timers(&mut out) {
                    Ok(Action::SendToPeer(pkt)) => { socket.send_to(pkt, peer).await?; }
                    Ok(_) => {}
                    Err(e) => warn!("timer update error: {e}"),
                }
            }
        }
    }
}
