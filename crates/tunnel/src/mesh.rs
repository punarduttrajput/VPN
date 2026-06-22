//! Multi-peer mesh data plane (PRD Phase 4 / ties Phase 3's network map to the
//! data plane).
//!
//! Phase 1's [`run`](crate::run) is point-to-point. `run_mesh` holds several
//! [`Session`]s — one per peer — over a [`MeshTransport`], routing:
//!   * **outbound** TUN packets by destination IP against each peer's `allowed_ips`,
//!   * **inbound** datagrams by *crypto-demux* — the peer whose WireGuard session
//!     decrypts the packet — so routing is independent of the source address and
//!     survives relays (MASQUE) and NAT rewriting.
//!
//! This is the shape a [`TunnelPlan`](../../vpn_client_core) becomes: each plan
//! peer (public key, endpoint, allowed IPs) maps to one [`MeshPeer`].
//!
//! The wire protocol is abstracted behind [`MeshTransport`]: a shared UDP socket
//! ([`UdpMeshTransport`](vpn_transport::UdpMeshTransport)), QUIC
//! ([`QuicMeshTransport`](vpn_transport::QuicMeshTransport), the `quic` feature),
//! or MASQUE/HTTP3 ([`MasqueMeshTransport`](vpn_transport::MasqueMeshTransport),
//! the `masque` feature). A pipelined mesh data path is a later increment.
//! Routing is verified in-process here (UDP, QUIC, and a MASQUE node reaching a
//! UDP peer); a real-TUN mesh run is a Linux/Codespaces path
//! (`verify-linux.sh TEST_MESH=1`, `MESH_QUIC=1` for QUIC).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use vpn_core::config::Cidr;
use vpn_transport::MeshTransport;

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

/// Kick off a fresh handshake to every peer in `peers`.
async fn handshake_all<M: MeshTransport>(
    transport: &M,
    peers: &mut [MeshPeer],
    out: &mut [u8],
) -> Result<()> {
    for peer in peers {
        if let Action::SendToPeer(pkt) = peer.session.start_handshake(out)? {
            transport.send_to(peer.endpoint, pkt).await?;
        }
    }
    Ok(())
}

/// Run the mesh data plane until `shutdown` resolves.
///
/// The mesh is carried over any [`MeshTransport`] — a shared UDP socket today,
/// a QUIC endpoint multiplexing connections later — so this loop is independent
/// of the wire protocol. Outbound TUN packets are routed by destination IP to a
/// peer's session and sent via `transport`; inbound datagrams are demuxed to the
/// peer they came from (by source address).
///
/// `updates` carries replacement peer sets (e.g. from the coordinator's
/// `WatchNetworkMap` stream): each received set replaces the live mesh and
/// re-handshakes, so membership changes take effect without restarting the
/// process. When the sender is dropped the data plane keeps running with its
/// current peers. Pass a never-sending receiver for a static mesh.
pub async fn run_mesh<D, M, S>(
    mut device: D,
    transport: M,
    mut peers: Vec<MeshPeer>,
    mut updates: mpsc::Receiver<Vec<MeshPeer>>,
    shutdown: S,
) -> Result<()>
where
    D: TunDevice,
    M: MeshTransport,
    S: std::future::Future<Output = ()>,
{
    let mut out = vec![0u8; MAX_PACKET];

    // Kick off a handshake to every peer we start with.
    handshake_all(&transport, &mut peers, &mut out).await?;

    let mut tun_buf = vec![0u8; MAX_PACKET];
    let mut net_buf = vec![0u8; MAX_PACKET];
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    let mut updates_open = true;
    tokio::pin!(shutdown);

    info!(peers = peers.len(), "mesh data plane running");

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown requested; tearing down mesh");
                return Ok(());
            }

            // Live reconfiguration: a new peer set replaces the current mesh.
            new = updates.recv(), if updates_open => {
                match new {
                    Some(next) => {
                        info!(peers = next.len(), "applying updated network map");
                        peers = next;
                        handshake_all(&transport, &mut peers, &mut out).await?;
                    }
                    // Sender dropped: stop polling this branch, keep current peers.
                    None => updates_open = false,
                }
            }

            // Outbound: TUN -> route by dest IP -> encrypt -> peer.
            read = device.read_packet(&mut tun_buf) => {
                let n = read?;
                match dest_ip(&tun_buf[..n]).and_then(|ip| peer_for_dest(&peers, ip)) {
                    Some(idx) => {
                        let peer = &mut peers[idx];
                        if let Action::SendToPeer(pkt) = peer.session.encapsulate(&tun_buf[..n], &mut out)? {
                            transport.send_to(peer.endpoint, pkt).await?;
                        }
                    }
                    None => debug!("no peer route for outbound packet; dropping"),
                }
            }

            // Inbound: datagram -> crypto-demux -> decrypt -> TUN.
            //
            // Route by *which peer's session decrypts the packet* (WireGuard
            // receiver index / keys), not by source address. A mismatched
            // session rejects the datagram cheaply (unknown receiver index, or
            // peer-key mismatch on a handshake), so only the intended peer
            // accepts it. This makes the mesh work when the source address is
            // not the peer's advertised endpoint — e.g. traffic relayed through
            // a MASQUE proxy, or arriving from a NAT-rewritten port.
            recv = transport.recv_from(&mut net_buf) => {
                let (n, src) = recv?;
                let mut routed = false;
                for peer in &mut peers {
                    let action = match peer.session.decapsulate(&net_buf[..n], &mut out) {
                        Ok(a) => a,
                        // Not this peer's datagram — try the next session.
                        Err(_) => continue,
                    };
                    // Endpoint roaming: the datagram authenticated against this
                    // peer's session, so `src` is the peer's current reachable
                    // path. Trust it for future sends (the peer is behind a NAT
                    // that rewrote its port, or reached us via a relay/proxy).
                    // Safe because we only roam on a packet that decrypts —
                    // an attacker cannot forge one.
                    if peer.endpoint != src {
                        debug!(old = %peer.endpoint, new = %src, "peer endpoint roamed");
                        peer.endpoint = src;
                    }
                    match action {
                        Action::WriteToTun(pkt, _ip) => device.write_packet(pkt).await?,
                        // Handshake response / cookie: reply along the roamed path.
                        Action::SendToPeer(pkt) => transport.send_to(peer.endpoint, pkt).await?,
                        Action::Done => {}
                    }
                    routed = true;
                    break;
                }
                if !routed {
                    debug!(%src, "no peer session accepted inbound datagram; dropping");
                }
            }

            // Timers: service each peer's handshake/keepalive.
            _ = timer.tick() => {
                for peer in &mut peers {
                    match peer.session.update_timers(&mut out) {
                        Ok(Action::SendToPeer(pkt)) => { transport.send_to(peer.endpoint, pkt).await?; }
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
