//! Multi-peer mesh data plane (PRD Phase 4 / ties Phase 3's network map to the
//! data plane).
//!
//! Phase 1's [`run`](crate::run) is point-to-point. `run_mesh` holds several
//! [`Session`]s — one per peer — over a single UDP socket, routing:
//!   * **outbound** TUN packets by destination IP against each peer's `allowed_ips`,
//!   * **inbound** datagrams to the peer they came from (by source address).
//!
//! This is the shape a [`TunnelPlan`](../../vpn_client_core) becomes: each plan
//! peer (public key, endpoint, allowed IPs) maps to one [`MeshPeer`].
//!
//! Scope: UDP transport only (the point-to-point [`Transport`](vpn_transport)
//! trait does not model multi-peer demux); QUIC/MASQUE mesh and a pipelined mesh
//! data path are later increments. Routing is verified in-process here; a
//! real-TUN mesh run is a Linux/Codespaces follow-up.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{debug, info, warn};
use vpn_core::config::Cidr;

use crate::device::TunDevice;
use crate::session::{Action, Session, MAX_PACKET};
use crate::Result;

/// One peer in the mesh: its WireGuard session, reachable endpoint, and the
/// destination CIDRs routed to it.
pub struct MeshPeer {
    /// WireGuard session for this peer.
    pub session: Session,
    /// The peer's reachable UDP endpoint.
    pub endpoint: SocketAddr,
    /// Destination CIDRs routed to this peer (crypto-routing).
    pub allowed_ips: Vec<Cidr>,
}

/// Destination IP of an outbound IP packet (v4 or v6), if parseable.
fn dest_ip(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::from([
            packet[16], packet[17], packet[18], packet[19],
        ])),
        6 if packet.len() >= 40 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&packet[24..40]);
            Some(IpAddr::from(a))
        }
        _ => None,
    }
}

/// Index of the peer whose `allowed_ips` contains `ip`.
fn peer_for_dest(peers: &[MeshPeer], ip: IpAddr) -> Option<usize> {
    peers
        .iter()
        .position(|p| p.allowed_ips.iter().any(|c| c.contains(ip)))
}

/// Run the mesh data plane until `shutdown` resolves.
pub async fn run_mesh<D, S>(
    mut device: D,
    socket: UdpSocket,
    mut peers: Vec<MeshPeer>,
    shutdown: S,
) -> Result<()>
where
    D: TunDevice,
    S: std::future::Future<Output = ()>,
{
    let mut out = vec![0u8; MAX_PACKET];

    // Kick off a handshake to every peer.
    for peer in &mut peers {
        if let Action::SendToPeer(pkt) = peer.session.start_handshake(&mut out)? {
            socket.send_to(pkt, peer.endpoint).await?;
        }
    }

    let mut tun_buf = vec![0u8; MAX_PACKET];
    let mut net_buf = vec![0u8; MAX_PACKET];
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    tokio::pin!(shutdown);

    info!(peers = peers.len(), "mesh data plane running");

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown requested; tearing down mesh");
                return Ok(());
            }

            // Outbound: TUN -> route by dest IP -> encrypt -> peer.
            read = device.read_packet(&mut tun_buf) => {
                let n = read?;
                match dest_ip(&tun_buf[..n]).and_then(|ip| peer_for_dest(&peers, ip)) {
                    Some(idx) => {
                        let peer = &mut peers[idx];
                        if let Action::SendToPeer(pkt) = peer.session.encapsulate(&tun_buf[..n], &mut out)? {
                            socket.send_to(pkt, peer.endpoint).await?;
                        }
                    }
                    None => debug!("no peer route for outbound packet; dropping"),
                }
            }

            // Inbound: datagram -> demux by source -> decrypt -> TUN.
            recv = socket.recv_from(&mut net_buf) => {
                let (n, src) = recv?;
                match peers.iter().position(|p| p.endpoint == src) {
                    Some(idx) => {
                        match peers[idx].session.decapsulate(&net_buf[..n], &mut out)? {
                            Action::WriteToTun(pkt, _ip) => device.write_packet(pkt).await?,
                            Action::SendToPeer(pkt) => { socket.send_to(pkt, src).await?; }
                            Action::Done => {}
                        }
                    }
                    None => debug!(%src, "datagram from unknown source; dropping"),
                }
            }

            // Timers: service each peer's handshake/keepalive.
            _ = timer.tick() => {
                for peer in &mut peers {
                    match peer.session.update_timers(&mut out) {
                        Ok(Action::SendToPeer(pkt)) => { socket.send_to(pkt, peer.endpoint).await?; }
                        Ok(_) => {}
                        Err(e) => warn!("timer update error: {e}"),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_destination() {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[16..20].copy_from_slice(&[10, 8, 0, 7]);
        assert_eq!(dest_ip(&p), Some("10.8.0.7".parse().unwrap()));
    }

    #[test]
    fn routes_to_peer_by_allowed_ips() {
        // Two peers with /32 routes; pick by destination.
        let a = vpn_core::keys::KeyPair::generate();
        let b = vpn_core::keys::KeyPair::generate();
        let me = vpn_core::keys::KeyPair::generate();
        let peers = vec![
            MeshPeer {
                session: Session::from_bytes(me.private.to_bytes(), a.public.to_bytes(), 1)
                    .unwrap(),
                endpoint: "127.0.0.1:1".parse().unwrap(),
                allowed_ips: vec!["10.8.0.2/32".parse().unwrap()],
            },
            MeshPeer {
                session: Session::from_bytes(me.private.to_bytes(), b.public.to_bytes(), 2)
                    .unwrap(),
                endpoint: "127.0.0.1:2".parse().unwrap(),
                allowed_ips: vec!["10.8.0.3/32".parse().unwrap()],
            },
        ];
        assert_eq!(peer_for_dest(&peers, "10.8.0.2".parse().unwrap()), Some(0));
        assert_eq!(peer_for_dest(&peers, "10.8.0.3".parse().unwrap()), Some(1));
        assert_eq!(peer_for_dest(&peers, "10.8.0.9".parse().unwrap()), None);
    }
}
