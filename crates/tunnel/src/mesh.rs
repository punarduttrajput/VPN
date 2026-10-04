//! Multi-peer mesh data plane (PRD Phase 4 / ties Phase 3's network map to the
//! data plane).
//!
//! Phase 1's [`run`](crate::run) is point-to-point. `run_mesh` holds several
//! [`Session`]s — one per peer — over a [`MeshTransport`], routing:
//!   * **outbound** TUN packets by destination IP against each peer's `allowed_ips`,
//!   * **inbound** datagrams by *crypto-demux* — the peer whose WireGuard session
//!     decrypts the packet — so routing is independent of the source address and
//!     survives relays (MASQUE) and NAT rewriting. The decrypted packet is then
//!     delivered only if its inner source is inside that peer's `allowed_ips`
//!     (WireGuard's inbound crypto-routing rule, SEC-011).
//!
//! This is the shape a [`TunnelPlan`](../../ferrum_client_core) becomes: each plan
//! peer (public key, endpoint, allowed IPs) maps to one [`MeshPeer`].
//!
//! The wire protocol is abstracted behind [`MeshTransport`]: a shared UDP socket
//! ([`UdpMeshTransport`](ferrum_transport::UdpMeshTransport)), QUIC
//! ([`QuicMeshTransport`](ferrum_transport::QuicMeshTransport), the `quic` feature),
//! or MASQUE/HTTP3 ([`MasqueMeshTransport`](ferrum_transport::MasqueMeshTransport),
//! the `masque` feature). A pipelined mesh data path is a later increment.
//! Routing is verified in-process here (UDP, QUIC, and a MASQUE node reaching a
//! UDP peer); a real-TUN mesh run is a Linux/Codespaces path
//! (`verify-linux.sh TEST_MESH=1`, `MESH_QUIC=1` for QUIC).

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ferrum_core::config::Cidr;
use ferrum_transport::{Fingerprint, MeshTransport, RelayMeshTransport};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::device::TunDevice;
use crate::path::{Path, PathMachine};
use crate::session::{Action, Session, MAX_PACKET};
use crate::Result;

/// One peer in the mesh: its WireGuard session, reachable endpoint, the
/// destination CIDRs routed to it, and any extra ICE candidates to probe.
pub struct MeshPeer {
    /// WireGuard session for this peer.
    pub session: Session,
    /// The peer's currently selected reachable endpoint. Endpoint roaming
    /// updates this to the path a valid inbound packet actually arrived on.
    pub endpoint: SocketAddr,
    /// Destination CIDRs routed to this peer (crypto-routing).
    pub allowed_ips: Vec<Cidr>,
    /// Additional ICE candidate addresses (host + STUN server-reflexive) to try
    /// while no working path is yet confirmed. The handshake is sent to every
    /// candidate (plus `endpoint`) until one answers; roaming then locks
    /// `endpoint` onto whichever path worked. Empty means "only use `endpoint`".
    pub candidates: Vec<SocketAddr>,
    /// Expected outer-transport TLS cert pins for this peer (SEC-004), applied
    /// to its endpoint and every candidate. Only a TLS-carrying transport (the
    /// QUIC mesh) uses them; empty means "unpinned" (it warns).
    pub tls_pins: Vec<Fingerprint>,
}

impl MeshPeer {
    /// A peer reachable at a single known `endpoint` (no extra ICE candidates).
    pub fn new(session: Session, endpoint: SocketAddr, allowed_ips: Vec<Cidr>) -> Self {
        Self {
            session,
            endpoint,
            allowed_ips,
            candidates: Vec::new(),
            tls_pins: Vec::new(),
        }
    }

    /// Expect these TLS cert pins when dialing this peer (SEC-004).
    pub fn with_tls_pins(mut self, pins: Vec<Fingerprint>) -> Self {
        self.tls_pins = pins;
        self
    }

    /// A peer with extra ICE `candidates` to probe (Phase 4 connectivity checks).
    /// The handshake fans out across `endpoint` and every candidate until one
    /// answers; endpoint roaming then selects the path that worked.
    pub fn with_candidates(
        session: Session,
        endpoint: SocketAddr,
        allowed_ips: Vec<Cidr>,
        candidates: Vec<SocketAddr>,
    ) -> Self {
        Self {
            session,
            endpoint,
            allowed_ips,
            candidates,
            tls_pins: Vec::new(),
        }
    }
}

/// Push every peer's TLS pins to the transport, keyed by each address it may
/// be dialed at (endpoint + ICE candidates). A no-op for non-TLS transports.
fn apply_pins<M: MeshTransport>(transport: &M, peers: &[MeshPeer]) {
    // Several peers can share an address — most often an RFC 1918 host
    // candidate like 192.168.1.10:51820 on two different LANs — so the pins
    // for one address are the *union* over every peer listing it (WireGuard's
    // crypto-demux still decides which peer actually answered). A plain
    // overwrite would make one of those peers fail its own pin.
    let mut by_addr: std::collections::HashMap<SocketAddr, Vec<Fingerprint>> =
        std::collections::HashMap::new();
    for p in peers.iter().filter(|p| !p.tls_pins.is_empty()) {
        for addr in std::iter::once(p.endpoint).chain(p.candidates.iter().copied()) {
            let pins = by_addr.entry(addr).or_default();
            for pin in &p.tls_pins {
                if !pins.contains(pin) {
                    pins.push(*pin);
                }
            }
        }
    }
    let pins: Vec<(SocketAddr, Vec<Fingerprint>)> = by_addr.into_iter().collect();
    transport.set_peer_pins(&pins);
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

/// Decrypted packets dropped because their inner source wasn't within the
/// decrypting peer's `allowed_ips` (SEC-011). Process-wide and aggregate only:
/// no peer or address is recorded (NFR5).
static SPOOFED_SOURCE_DROPS: AtomicU64 = AtomicU64::new(0);

/// How many decrypted packets this process has dropped for carrying a source
/// address outside their sender's `allowed_ips` (SEC-011).
pub fn spoofed_source_drops() -> u64 {
    SPOOFED_SOURCE_DROPS.load(Ordering::Relaxed)
}

/// WireGuard crypto-routing's inbound rule (SEC-011): a packet that decrypted
/// under a peer's session is accepted only if its inner source address is
/// inside that peer's `allowed_ips`. Otherwise any authenticated peer could
/// inject packets claiming another peer's tunnel IP. A refusal is counted in
/// [`spoofed_source_drops`].
pub(crate) fn accept_inbound_source(allowed_ips: &[Cidr], src: IpAddr) -> bool {
    if allowed_ips.iter().any(|c| c.contains(src)) {
        return true;
    }
    SPOOFED_SOURCE_DROPS.fetch_add(1, Ordering::Relaxed);
    false
}

/// Index of the peer whose `allowed_ips` contains `ip`.
fn peer_for_dest(peers: &[MeshPeer], ip: IpAddr) -> Option<usize> {
    peers
        .iter()
        .position(|p| p.allowed_ips.iter().any(|c| c.contains(ip)))
}

/// Addresses to send a handshake/keepalive to for one peer (Phase 4 M2
/// connectivity check).
///
/// Until a working path is `confirmed` (no inbound datagram has decrypted for
/// this peer yet), fan handshakes out across *all* of the peer's candidates plus
/// its current endpoint: whichever candidate is actually reachable delivers the
/// handshake, and endpoint roaming locks `endpoint` onto the path that answered.
/// Once confirmed, send only along the roamed `endpoint` — no need to keep
/// probing dead candidates.
fn probe_targets(peer: &MeshPeer, confirmed: bool) -> Vec<SocketAddr> {
    if confirmed || peer.candidates.is_empty() {
        return vec![peer.endpoint];
    }
    // Order the fan-out by ICE priority (RFC 8445): a reachable LAN (host)
    // candidate is tried before the public (server-reflexive) endpoint, so peers
    // on a shared network punch through directly and fast.
    crate::ice::prioritized_targets(peer.endpoint, &peer.candidates)
}

/// Which underlay an inbound datagram arrived on (or an outbound should ride):
/// the **direct** transport or the **relay** fallback. Drives path confirmation
/// (direct vs relay liveness) and endpoint roaming (only the direct underlay
/// carries the peer's real source address).
#[derive(Debug, Clone, Copy)]
enum Underlay {
    Direct,
    Relay,
}

/// Each peer's stable relay handle: the [`SocketAddr`] the relay underlay uses to
/// address it. Captured from the peer's endpoint when the set is (re)built and
/// kept fixed even as `endpoint` roams on the direct path — the relay addresses
/// peers by public key behind this handle, so it must not follow direct roaming.
fn relay_handles(peers: &[MeshPeer]) -> Vec<SocketAddr> {
    peers.iter().map(|p| p.endpoint).collect()
}

/// Align the relay transport's `handle <-> key` table with the current peer set
/// (each peer's stable handle + its WireGuard public key), so relay sends and
/// inbound attribution track `peers`. A no-op when there is no relay underlay.
fn align_relay(relay: Option<&RelayMeshTransport>, peers: &[MeshPeer], handles: &[SocketAddr]) {
    if let Some(r) = relay {
        let pairs: Vec<(SocketAddr, [u8; 32])> = peers
            .iter()
            .zip(handles)
            .map(|(p, h)| (*h, p.session.peer_public_key()))
            .collect();
        r.set_peers(&pairs);
    }
}

/// Await the relay underlay's next inbound datagram, or never resolve when there
/// is no relay (so its `select!` branch stays inert).
async fn relay_recv(
    relay: &Option<RelayMeshTransport>,
    buf: &mut [u8],
) -> std::result::Result<(usize, SocketAddr), ferrum_transport::TransportError> {
    match relay {
        Some(r) => r.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

/// Send a *data* datagram for one peer over the underlay its path machine has
/// chosen: the confirmed direct path, the relay fallback, or — while no path is
/// confirmed yet — best-effort over the relay if present, else the direct
/// endpoint.
async fn send_data<M: MeshTransport>(
    direct: &M,
    relay: Option<&RelayMeshTransport>,
    peer: &MeshPeer,
    relay_handle: SocketAddr,
    path: Path,
    pkt: &[u8],
) -> Result<()> {
    match path {
        Path::Direct => direct.send_to(peer.endpoint, pkt).await?,
        Path::Relay => {
            if let Some(r) = relay {
                r.send_to(relay_handle, pkt).await?;
            }
        }
        Path::None => match relay {
            Some(r) => r.send_to(relay_handle, pkt).await?,
            None => direct.send_to(peer.endpoint, pkt).await?,
        },
    }
    Ok(())
}

/// Send *signaling* (a handshake or keepalive) for one peer. Unlike data, this
/// keeps probing for a better path: while on the relay (or with no path yet) it
/// fans the packet across the peer's direct candidates *and* the relay, so a
/// direct path can come up and trigger an upgrade. Once direct is confirmed it
/// only refreshes that path.
async fn send_signaling<M: MeshTransport>(
    direct: &M,
    relay: Option<&RelayMeshTransport>,
    peer: &MeshPeer,
    relay_handle: SocketAddr,
    path: Path,
    pkt: &[u8],
) -> Result<()> {
    match path {
        Path::Direct => direct.send_to(peer.endpoint, pkt).await?,
        Path::Relay | Path::None => {
            for target in probe_targets(peer, false) {
                direct.send_to(target, pkt).await?;
            }
            if let Some(r) = relay {
                r.send_to(relay_handle, pkt).await?;
            }
        }
    }
    Ok(())
}

/// Kick off a fresh handshake to every peer, fanning each across its direct
/// candidates (and the relay, if any), and move each peer's path machine into the
/// probing state.
async fn handshake_all<M: MeshTransport>(
    direct: &M,
    relay: Option<&RelayMeshTransport>,
    peers: &mut [MeshPeer],
    paths: &mut [PathMachine],
    handles: &[SocketAddr],
    out: &mut [u8],
) -> Result<()> {
    for i in 0..peers.len() {
        paths[i].begin_probing();
        if let Action::SendToPeer(pkt) = peers[i].session.start_handshake(out)? {
            let path = paths[i].path();
            send_signaling(direct, relay, &peers[i], handles[i], path, pkt).await?;
        }
    }
    Ok(())
}

/// Demux one inbound datagram to the peer whose session decrypts it, confirm the
/// path it proved (direct vs relay), roam that peer's endpoint on the direct
/// underlay, and act on the decrypted result (write to TUN, or reply along the
/// same underlay).
///
/// Routing is by *which peer's session decrypts the packet* (WireGuard receiver
/// index / keys), not by source address — a mismatched session rejects the
/// datagram cheaply, so only the intended peer accepts it. That is what lets the
/// mesh work when the source address is not the peer's advertised endpoint (NAT
/// rewrite, MASQUE proxy, or the relay).
#[allow(clippy::too_many_arguments)]
async fn handle_inbound<D: TunDevice, M: MeshTransport>(
    direct: &M,
    relay: Option<&RelayMeshTransport>,
    device: &mut D,
    peers: &mut [MeshPeer],
    paths: &mut [PathMachine],
    handles: &[SocketAddr],
    out: &mut [u8],
    datagram: &[u8],
    src: SocketAddr,
    underlay: Underlay,
) -> Result<()> {
    for i in 0..peers.len() {
        let action = match peers[i].session.decapsulate(datagram, out) {
            Ok(a) => a,
            // Not this peer's datagram — try the next session.
            Err(_) => continue,
        };
        // The datagram decrypted for this peer, so the underlay it arrived on
        // works: confirm/refresh that path. A direct packet upgrades to (or holds)
        // Direct; a relay packet brings up the relay fallback unless we are
        // already Direct, where it only keeps the relay a hot standby.
        let transition = match underlay {
            Underlay::Direct => paths[i].on_direct_packet(Instant::now()),
            Underlay::Relay => paths[i].on_relay_packet(Instant::now()),
        };
        if let Some(t) = transition {
            debug!(peer = i, ?underlay, transition = ?t, "peer path state changed");
        }
        // Endpoint roaming, but only on the direct underlay: there `src` is the
        // peer's real reachable address (e.g. a NAT-rewritten port), safe to trust
        // because we only roam on a packet that decrypts. On the relay underlay
        // `src` is a synthetic handle, so roaming onto it would break direct
        // addressing — leave `endpoint` alone.
        if matches!(underlay, Underlay::Direct) && peers[i].endpoint != src {
            debug!(old = %peers[i].endpoint, new = %src, "peer endpoint roamed");
            peers[i].endpoint = src;
        }
        match action {
            // boringtun reports the inner packet's source address; enforce
            // crypto-routing before the packet reaches the OS (SEC-011). The
            // path/roaming updates above still stand: the datagram genuinely
            // came from this peer, it just claimed an address it doesn't own.
            Action::WriteToTun(pkt, src) => {
                if accept_inbound_source(&peers[i].allowed_ips, src) {
                    device.write_packet(pkt).await?;
                } else {
                    debug!(
                        peer = i,
                        "dropped decrypted packet whose source is outside the peer's allowed_ips"
                    );
                }
            }
            // Handshake response / cookie: reply along the underlay it arrived on.
            Action::SendToPeer(pkt) => match underlay {
                Underlay::Direct => direct.send_to(peers[i].endpoint, pkt).await?,
                Underlay::Relay => {
                    if let Some(r) = relay {
                        r.send_to(handles[i], pkt).await?;
                    }
                }
            },
            Action::Done => {}
        }
        return Ok(());
    }
    debug!(%src, ?underlay, "no peer session accepted inbound datagram; dropping");
    Ok(())
}

/// Run the mesh data plane over a single (direct) `transport` until `shutdown`
/// resolves. See [`run_mesh_relayed`] to add an automatic relay fallback.
///
/// The mesh is carried over any [`MeshTransport`] — a shared UDP socket, a QUIC
/// endpoint, or a MASQUE session — so this loop is independent of the wire
/// protocol. Outbound TUN packets are routed by destination IP to a peer's
/// session and sent via `transport`; inbound datagrams are demuxed to the peer
/// whose session decrypts them.
///
/// `updates` carries replacement peer sets (e.g. from the coordinator's
/// `WatchNetworkMap` stream): each received set replaces the live mesh and
/// re-handshakes, so membership changes take effect without restarting the
/// process. When the sender is dropped the data plane keeps running with its
/// current peers. Pass a never-sending receiver for a static mesh.
pub async fn run_mesh<D, M, S>(
    device: D,
    transport: M,
    peers: Vec<MeshPeer>,
    updates: mpsc::Receiver<Vec<MeshPeer>>,
    shutdown: S,
) -> Result<()>
where
    D: TunDevice,
    M: MeshTransport,
    S: std::future::Future<Output = ()>,
{
    run_mesh_core(device, transport, None, peers, updates, shutdown).await
}

/// Run the mesh data plane with an automatic **relay fallback** underlay
/// alongside the direct `transport`.
///
/// Each peer rides whichever path its `idle → connecting → relay → direct` state
/// machine has confirmed: a direct (or relay) datagram that decrypts for a peer
/// proves and refreshes that path. While no direct path is up, handshakes fan
/// across *both* underlays, so a peer behind a hostile NAT comes up over the relay
/// and **upgrades** to direct the moment a direct path is punched — and
/// **downgrades** back to the relay if a confirmed direct path later goes stale.
///
/// The `relay` must already be connected to its
/// [`RelayServer`](ferrum_transport::RelayServer); its `handle <-> key` table is
/// (re)aligned to the live peer set here, including across `updates`.
pub async fn run_mesh_relayed<D, M, S>(
    device: D,
    transport: M,
    relay: RelayMeshTransport,
    peers: Vec<MeshPeer>,
    updates: mpsc::Receiver<Vec<MeshPeer>>,
    shutdown: S,
) -> Result<()>
where
    D: TunDevice,
    M: MeshTransport,
    S: std::future::Future<Output = ()>,
{
    run_mesh_core(device, transport, Some(relay), peers, updates, shutdown).await
}

/// Shared mesh loop driving the direct `transport` and, when present, a relay
/// fallback underlay. Underlay selection is per peer, by its [`PathMachine`].
async fn run_mesh_core<D, M, S>(
    mut device: D,
    transport: M,
    relay: Option<RelayMeshTransport>,
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

    // Per-peer NAT-traversal path state (`idle → connecting → relay → direct`),
    // parallel to `peers`. A path is confirmed once an inbound datagram decrypts
    // for that peer over the matching underlay; until then handshakes fan out
    // across its candidates and the relay. If a confirmed path later goes stale
    // the machine downgrades and we resume probing. Rebuilt with the peer set.
    let mut paths = vec![PathMachine::new(); peers.len()];
    // Stable relay handles, parallel to `peers`; align the relay's key table.
    let mut handles = relay_handles(&peers);
    align_relay(relay.as_ref(), &peers, &handles);
    apply_pins(&transport, &peers);

    // Kick off a handshake to every peer we start with.
    handshake_all(
        &transport,
        relay.as_ref(),
        &mut peers,
        &mut paths,
        &handles,
        &mut out,
    )
    .await?;

    let mut tun_buf = vec![0u8; MAX_PACKET];
    let mut net_buf = vec![0u8; MAX_PACKET];
    let mut relay_buf = vec![0u8; MAX_PACKET];
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    let mut updates_open = true;
    tokio::pin!(shutdown);

    info!(
        peers = peers.len(),
        relay = relay.is_some(),
        "mesh data plane running"
    );

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
                        // New sessions: fresh path machines + realigned relay table.
                        paths = vec![PathMachine::new(); peers.len()];
                        handles = relay_handles(&peers);
                        align_relay(relay.as_ref(), &peers, &handles);
                        apply_pins(&transport, &peers);
                        handshake_all(
                            &transport,
                            relay.as_ref(),
                            &mut peers,
                            &mut paths,
                            &handles,
                            &mut out,
                        )
                        .await?;
                    }
                    // Sender dropped: stop polling this branch, keep current peers.
                    None => updates_open = false,
                }
            }

            // Outbound: TUN -> route by dest IP -> encrypt -> chosen underlay.
            read = device.read_packet(&mut tun_buf) => {
                let n = read?;
                match dest_ip(&tun_buf[..n]).and_then(|ip| peer_for_dest(&peers, ip)) {
                    Some(idx) => {
                        let path = paths[idx].path();
                        if let Action::SendToPeer(pkt) =
                            peers[idx].session.encapsulate(&tun_buf[..n], &mut out)?
                        {
                            send_data(
                                &transport,
                                relay.as_ref(),
                                &peers[idx],
                                handles[idx],
                                path,
                                pkt,
                            )
                            .await?;
                        }
                    }
                    None => debug!("no peer route for outbound packet; dropping"),
                }
            }

            // Inbound over the direct underlay.
            recv = transport.recv_from(&mut net_buf) => {
                let (n, src) = recv?;
                handle_inbound(
                    &transport,
                    relay.as_ref(),
                    &mut device,
                    &mut peers,
                    &mut paths,
                    &handles,
                    &mut out,
                    &net_buf[..n],
                    src,
                    Underlay::Direct,
                )
                .await?;
            }

            // Inbound over the relay underlay (inert when there is no relay).
            recv = relay_recv(&relay, &mut relay_buf), if relay.is_some() => {
                let (n, src) = recv?;
                handle_inbound(
                    &transport,
                    relay.as_ref(),
                    &mut device,
                    &mut peers,
                    &mut paths,
                    &handles,
                    &mut out,
                    &relay_buf[..n],
                    src,
                    Underlay::Relay,
                )
                .await?;
            }

            // Timers: age each peer's path state and service its WireGuard
            // handshake/keepalive. A handshake retransmit for a peer without a
            // confirmed direct path re-probes its candidates and the relay, so a
            // path can come up even if it wasn't reachable on the first try.
            _ = timer.tick() => {
                let now = Instant::now();
                for i in 0..peers.len() {
                    // Downgrade a confirmed path that has gone stale (peer roamed,
                    // NAT mapping expired) and immediately re-probe, rather than
                    // black-holing on a dead path.
                    if let Some(t) = paths[i].tick(now) {
                        info!(peer = i, transition = ?t, "peer path state changed");
                        if t.should_resume_probing() {
                            if let Action::SendToPeer(pkt) =
                                peers[i].session.start_handshake(&mut out)?
                            {
                                let path = paths[i].path();
                                send_signaling(
                                    &transport,
                                    relay.as_ref(),
                                    &peers[i],
                                    handles[i],
                                    path,
                                    pkt,
                                )
                                .await?;
                            }
                            continue; // already sent a probe this tick
                        }
                    }
                    match peers[i].session.update_timers(&mut out) {
                        Ok(Action::SendToPeer(pkt)) => {
                            let path = paths[i].path();
                            send_signaling(
                                &transport,
                                relay.as_ref(),
                                &peers[i],
                                handles[i],
                                path,
                                pkt,
                            )
                            .await?;
                        }
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
        let a = ferrum_core::keys::KeyPair::generate();
        let b = ferrum_core::keys::KeyPair::generate();
        let me = ferrum_core::keys::KeyPair::generate();
        let peers = vec![
            MeshPeer::new(
                Session::from_bytes(me.private.to_bytes(), a.public.to_bytes(), 1).unwrap(),
                "127.0.0.1:1".parse().unwrap(),
                vec!["10.8.0.2/32".parse().unwrap()],
            ),
            MeshPeer::new(
                Session::from_bytes(me.private.to_bytes(), b.public.to_bytes(), 2).unwrap(),
                "127.0.0.1:2".parse().unwrap(),
                vec!["10.8.0.3/32".parse().unwrap()],
            ),
        ];
        assert_eq!(peer_for_dest(&peers, "10.8.0.2".parse().unwrap()), Some(0));
        assert_eq!(peer_for_dest(&peers, "10.8.0.3".parse().unwrap()), Some(1));
        assert_eq!(peer_for_dest(&peers, "10.8.0.9".parse().unwrap()), None);
    }

    /// SEC-004: each pinned peer's pin is applied to its endpoint *and* every
    /// ICE candidate (any of which the QUIC mesh may dial); unpinned peers add
    /// nothing.
    #[test]
    fn apply_pins_covers_endpoint_and_candidates() {
        #[derive(Default)]
        struct Recorder(std::sync::Mutex<Vec<(SocketAddr, Vec<Fingerprint>)>>);
        impl MeshTransport for Recorder {
            async fn send_to(
                &self,
                _: SocketAddr,
                _: &[u8],
            ) -> std::result::Result<(), ferrum_transport::TransportError> {
                Ok(())
            }
            async fn recv_from(
                &self,
                _: &mut [u8],
            ) -> std::result::Result<(usize, SocketAddr), ferrum_transport::TransportError>
            {
                std::future::pending().await
            }
            fn set_peer_pins(&self, pins: &[(SocketAddr, Vec<Fingerprint>)]) {
                *self.0.lock().unwrap() = pins.to_vec();
            }
        }

        let me = ferrum_core::keys::KeyPair::generate();
        let session = |i| {
            let k = ferrum_core::keys::KeyPair::generate();
            Session::from_bytes(me.private.to_bytes(), k.public.to_bytes(), i).unwrap()
        };
        let a: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let a_cand: SocketAddr = "192.168.1.5:1".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let peers = vec![
            MeshPeer::with_candidates(session(1), a, vec![], vec![a_cand])
                .with_tls_pins(vec![[1; 32]]),
            MeshPeer::new(session(2), b, vec![]), // unpinned
        ];
        let t = Recorder::default();
        apply_pins(&t, &peers);
        let mut got = t.0.lock().unwrap().clone();
        got.sort();
        assert_eq!(got, vec![(a, vec![[1; 32]]), (a_cand, vec![[1; 32]])]);

        // Review fix: two peers at different sites advertising the same LAN
        // host candidate get the *union* of their pins at that address, so
        // neither fails its own pin there.
        let shared: SocketAddr = "192.168.1.10:51820".parse().unwrap();
        let peers = vec![
            MeshPeer::with_candidates(session(3), a, vec![], vec![shared])
                .with_tls_pins(vec![[1; 32]]),
            MeshPeer::with_candidates(session(4), b, vec![], vec![shared])
                .with_tls_pins(vec![[2; 32]]),
        ];
        apply_pins(&t, &peers);
        let got = t.0.lock().unwrap().clone();
        let mut at_shared = got
            .iter()
            .find(|(addr, _)| *addr == shared)
            .map(|(_, pins)| pins.clone())
            .expect("shared candidate pinned");
        at_shared.sort();
        assert_eq!(at_shared, vec![[1; 32], [2; 32]]);
    }

    #[test]
    fn probe_targets_fans_out_until_confirmed() {
        let me = ferrum_core::keys::KeyPair::generate();
        let p = ferrum_core::keys::KeyPair::generate();
        let endpoint: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let cand: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let peer = MeshPeer::with_candidates(
            Session::from_bytes(me.private.to_bytes(), p.public.to_bytes(), 1).unwrap(),
            endpoint,
            vec!["10.8.0.2/32".parse().unwrap()],
            vec![endpoint, cand], // includes the endpoint; must be de-duped
        );
        // Unconfirmed: probe endpoint + each distinct candidate exactly once.
        assert_eq!(probe_targets(&peer, false), vec![endpoint, cand]);
        // Confirmed: only the (roamed) endpoint.
        assert_eq!(probe_targets(&peer, true), vec![endpoint]);

        // No candidates -> just the endpoint, confirmed or not.
        let bare = MeshPeer::new(
            Session::from_bytes(me.private.to_bytes(), p.public.to_bytes(), 2).unwrap(),
            endpoint,
            vec!["10.8.0.2/32".parse().unwrap()],
        );
        assert_eq!(probe_targets(&bare, false), vec![endpoint]);
    }
}
