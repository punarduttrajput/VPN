//! QUIC mesh transport (PRD Phase 3/4): the multi-peer counterpart of
//! [`QuicTransport`](crate::quic::QuicTransport).
//!
//! Carries the mesh data plane over QUIC instead of plain UDP. A single quinn
//! [`Endpoint`] both **accepts** incoming connections and **dials** peers, so one
//! local socket multiplexes a connection per peer (QUIC datagrams carry the
//! already-encrypted WireGuard packets).
//!
//! ## Identifying a peer on the accepting side
//!
//! [`MeshTransport`] is addressed by each peer's *advertised* endpoint (the
//! address the coordinator hands out). For a connection **we dial**, the remote
//! address is exactly that. But for a connection we **accept**, QUIC only tells us
//! the dialer's *ephemeral source* address, which differs from its advertised
//! endpoint. So right after connecting, a dialer sends a one-shot "hello" on a
//! unidirectional stream carrying its advertised endpoint; the acceptor reads it
//! and tags that connection's inbound datagrams with the advertised address. This
//! keeps the mesh runner's source-based demux working unchanged.
//!
//! Each pair ends up with two connections (A→B and B→A), each used one-way:
//! `send_to` always uses the connection *we* dialed to that peer, while inbound
//! arrives over the connection the peer dialed to us. This keeps send/receive
//! unambiguous without connection-dedup races.
//!
//! ## Outer-layer authentication (SEC-004)
//!
//! Every node presents its stable [`TlsIdentity`] (derived from its WireGuard
//! key), and each dial pins the destination peer's cert fingerprint, supplied via
//! [`set_peer_pins`](QuicMeshTransport::set_peer_pins) — keyed by every address
//! the peer may be dialed at (endpoint and ICE candidates). A peer with no pin is
//! still dialed, with a loud "outer transport unauthenticated" warning.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, warn};

use crate::tls::{self, Fingerprint, TlsIdentity};
use crate::{MeshTransport, TransportError};

/// Max bytes read for a peer's hello (an `ip:port` string is far smaller).
const HELLO_MAX: usize = 64;

fn setup(msg: impl std::fmt::Display) -> TransportError {
    TransportError::Setup(msg.to_string())
}
fn conn_err(msg: impl std::fmt::Display) -> TransportError {
    TransportError::Connection(msg.to_string())
}

/// One inbound datagram tagged with the advertised address of its sender.
type Tagged = (SocketAddr, Bytes);

/// A QUIC endpoint serving a whole mesh: one connection per peer, peers keyed by
/// their advertised [`SocketAddr`].
pub struct QuicMeshTransport {
    endpoint: Endpoint,
    local_addr: SocketAddr,
    /// This node's presented cert pin (what peers must be told to expect).
    fingerprint: Fingerprint,
    /// Expected cert pins per dialable peer address (SEC-004).
    pins: std::sync::Mutex<HashMap<SocketAddr, Vec<Fingerprint>>>,
    /// TLS name to dial peers with; `None` sends no SNI (SEC-020).
    server_name: Option<String>,
    /// Connections we dialed, keyed by the peer's advertised address (used to send).
    dialed: Mutex<HashMap<SocketAddr, Connection>>,
    /// Destinations whose last dial failed, and when to try again.
    backoff: std::sync::Mutex<DialBackoff>,
    /// Inbound datagrams from every connection (dialed + accepted).
    inbound_tx: mpsc::UnboundedSender<Tagged>,
    inbound_rx: Mutex<mpsc::UnboundedReceiver<Tagged>>,
    /// The background accept loop; aborted on drop.
    accept_task: tokio::task::JoinHandle<()>,
}

impl Drop for QuicMeshTransport {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

impl QuicMeshTransport {
    /// Bind a dual-role (accept + dial) QUIC endpoint to serve the mesh,
    /// presenting `identity` (pass [`TlsIdentity::from_wireguard_key`] so peers
    /// can pin it across restarts).
    pub async fn bind(local: SocketAddr, identity: &TlsIdentity) -> Result<Self, TransportError> {
        let endpoint = build_endpoint(local, identity)?;
        let local_addr = endpoint.local_addr().map_err(TransportError::Io)?;

        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let accept_task = tokio::spawn(accept_loop(endpoint.clone(), inbound_tx.clone()));

        Ok(Self {
            endpoint,
            local_addr,
            fingerprint: identity.fingerprint(),
            pins: std::sync::Mutex::new(HashMap::new()),
            server_name: None,
            dialed: Mutex::new(HashMap::new()),
            backoff: std::sync::Mutex::new(DialBackoff::default()),
            inbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            accept_task,
        })
    }

    /// Dial peers presenting `name` as the TLS server name (SNI) instead of
    /// the default of none (SEC-020). For operators who want the ClientHello to
    /// carry a hostname they control; pins still decide whom we accept.
    pub fn with_server_name(mut self, name: Option<String>) -> Self {
        self.server_name = name;
        self
    }

    /// The local (advertised) address this endpoint is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The SHA-256 pin of the cert this node presents.
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Client config for dialing `dst`, pinned to its expected cert(s).
    fn client_config_for(&self, dst: SocketAddr) -> Result<ClientConfig, TransportError> {
        let pins = self
            .pins
            .lock()
            .expect("quic mesh pins poisoned")
            .get(&dst)
            .cloned()
            .unwrap_or_default();
        let crypto = tls::client_crypto(pins, format!("QUIC mesh peer {dst}"), tls::QUIC_ALPN);
        Ok(ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).map_err(|e| setup(format!("quic client: {e}")))?,
        )))
    }

    /// Get the connection to `dst`, dialing (and announcing ourselves) if needed.
    async fn connection_to(&self, dst: SocketAddr) -> Result<Connection, TransportError> {
        let mut dialed = self.dialed.lock().await;
        if let Some(conn) = dialed.get(&dst) {
            return Ok(conn.clone());
        }
        let name = tls::dial_name(self.server_name.as_deref(), dst);
        let conn = self
            .endpoint
            .connect_with(self.client_config_for(dst)?, dst, &name)
            .map_err(|e| conn_err(format!("connect {dst}: {e}")))?
            .await
            .map_err(|e| conn_err(format!("handshake {dst}: {e}")))?;
        // Tell the peer who we are so it can tag our datagrams by advertised addr.
        send_hello(&conn, self.local_addr).await?;
        // Datagrams the peer sends back over this connection are tagged with `dst`.
        tokio::spawn(reader_loop(conn.clone(), dst, self.inbound_tx.clone()));
        dialed.insert(dst, conn.clone());
        Ok(conn)
    }
}

impl MeshTransport for QuicMeshTransport {
    /// Send to one peer. Like a UDP datagram, a send that can't be delivered
    /// — the peer is unreachable, refused our pin, or its connection died — is
    /// **dropped and logged, not an error**: the mesh loop treats a send error
    /// as fatal to the whole session, and one bad peer (or an on-path attacker
    /// presenting the wrong cert for it) must not take every other peer down.
    /// Failed dials back off (see [`DialBackoff`]) so a refused peer doesn't
    /// stall the loop with a handshake per packet.
    async fn send_to(&self, dst: SocketAddr, datagram: &[u8]) -> Result<(), TransportError> {
        if self
            .backoff
            .lock()
            .expect("quic mesh backoff poisoned")
            .is_waiting(dst, Instant::now())
        {
            return Ok(());
        }
        let conn = match self.connection_to(dst).await {
            Ok(conn) => conn,
            Err(e) => {
                let retry_in = self
                    .backoff
                    .lock()
                    .expect("quic mesh backoff poisoned")
                    .note_failure(dst, Instant::now());
                warn!("QUIC mesh: can't reach {dst} ({e}); dropping, retrying in {retry_in:?}");
                return Ok(());
            }
        };
        self.backoff
            .lock()
            .expect("quic mesh backoff poisoned")
            .note_success(dst);
        if let Err(e) = conn.send_datagram(Bytes::copy_from_slice(datagram)) {
            // A dead connection: forget it so the next send re-dials.
            debug!("QUIC mesh: send to {dst} failed ({e}); re-dialing on the next send");
            self.dialed.lock().await.remove(&dst);
        }
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), TransportError> {
        let mut rx = self.inbound_rx.lock().await;
        let (src, datagram) = rx
            .recv()
            .await
            .ok_or_else(|| conn_err("mesh transport closed"))?;
        let n = datagram.len().min(buf.len());
        buf[..n].copy_from_slice(&datagram[..n]);
        Ok((n, src))
    }

    /// Replace the expected cert pins, keyed by each address a peer may be dialed
    /// at. Applies to connections dialed from now on; one already established to
    /// an address keeps the pin it was verified against.
    fn set_peer_pins(&self, pins: &[(SocketAddr, Vec<Fingerprint>)]) {
        let new: HashMap<SocketAddr, Vec<Fingerprint>> = pins.iter().cloned().collect();
        let mut map = self.pins.lock().expect("quic mesh pins poisoned");
        // A changed pin is new information: retry that address now. Unchanged
        // ones keep their backoff — this runs on every network-map update, and
        // resetting everything would re-dial refused peers every few seconds.
        let mut backoff = self.backoff.lock().expect("quic mesh backoff poisoned");
        for addr in map.keys().chain(new.keys()) {
            if map.get(addr) != new.get(addr) {
                backoff.note_success(*addr);
            }
        }
        *map = new;
    }

    fn tls_fingerprint(&self) -> Option<Fingerprint> {
        Some(self.fingerprint)
    }
}

/// Per-destination exponential backoff for failed dials: 1 s, doubling to 30 s,
/// reset on a successful dial (or when that destination's pins change).
#[derive(Default)]
pub(crate) struct DialBackoff {
    /// `dst -> (retry not before, current delay)`.
    failed: HashMap<SocketAddr, (Instant, Duration)>,
}

const DIAL_BACKOFF_MIN: Duration = Duration::from_secs(1);
const DIAL_BACKOFF_MAX: Duration = Duration::from_secs(30);

impl DialBackoff {
    /// Whether `dst` is still waiting out a previous failure.
    pub(crate) fn is_waiting(&self, dst: SocketAddr, now: Instant) -> bool {
        self.failed
            .get(&dst)
            .is_some_and(|(retry_at, _)| now < *retry_at)
    }

    /// Record a failed dial; returns how long until the next attempt.
    pub(crate) fn note_failure(&mut self, dst: SocketAddr, now: Instant) -> Duration {
        let delay = self
            .failed
            .get(&dst)
            .map(|(_, d)| (*d * 2).min(DIAL_BACKOFF_MAX))
            .unwrap_or(DIAL_BACKOFF_MIN);
        self.failed.insert(dst, (now + delay, delay));
        delay
    }

    pub(crate) fn note_success(&mut self, dst: SocketAddr) {
        self.failed.remove(&dst);
    }
}

/// Accept incoming connections; for each, learn the dialer's advertised address
/// from its hello, then forward its datagrams tagged with that address.
async fn accept_loop(endpoint: Endpoint, inbound_tx: mpsc::UnboundedSender<Tagged>) {
    while let Some(incoming) = endpoint.accept().await {
        let inbound_tx = inbound_tx.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(_) => return,
            };
            // Without a valid hello we cannot attribute this peer, so drop it.
            if let Some(peer_addr) = read_hello(&conn).await {
                reader_loop(conn, peer_addr, inbound_tx).await;
            }
        });
    }
}

/// Pump a connection's inbound datagrams into the shared channel, tagged `src`.
async fn reader_loop(conn: Connection, src: SocketAddr, inbound_tx: mpsc::UnboundedSender<Tagged>) {
    // Ends when the connection closes (read error) or the transport is dropped.
    while let Ok(bytes) = conn.read_datagram().await {
        if inbound_tx.send((src, bytes)).is_err() {
            break; // receiver dropped (transport gone)
        }
    }
}

/// Announce our advertised address to a freshly dialed peer over a uni stream.
async fn send_hello(conn: &Connection, advertised: SocketAddr) -> Result<(), TransportError> {
    let mut stream = conn
        .open_uni()
        .await
        .map_err(|e| conn_err(format!("open hello stream: {e}")))?;
    stream
        .write_all(advertised.to_string().as_bytes())
        .await
        .map_err(|e| conn_err(format!("write hello: {e}")))?;
    stream
        .finish()
        .map_err(|e| conn_err(format!("finish hello: {e}")))?;
    Ok(())
}

/// Read a peer's hello (its advertised address) from the first uni stream.
async fn read_hello(conn: &Connection) -> Option<SocketAddr> {
    let mut stream = conn.accept_uni().await.ok()?;
    let bytes = stream.read_to_end(HELLO_MAX).await.ok()?;
    std::str::from_utf8(&bytes).ok()?.parse().ok()
}

/// Build a quinn endpoint that accepts connections presenting `identity`; dials
/// get a per-destination pinned client config (see `client_config_for`).
fn build_endpoint(local: SocketAddr, identity: &TlsIdentity) -> Result<Endpoint, TransportError> {
    let server_crypto = identity.server_crypto(tls::QUIC_ALPN)?;
    let server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto)
            .map_err(|e| setup(format!("quic server: {e}")))?,
    ));
    Endpoint::server(server_config, local).map_err(TransportError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mesh node on loopback with the stable identity for key `k`.
    async fn node(k: u8) -> QuicMeshTransport {
        let id = TlsIdentity::from_wireguard_key(&[k; 32]).unwrap();
        QuicMeshTransport::bind("127.0.0.1:0".parse().unwrap(), &id)
            .await
            .unwrap()
    }

    /// SEC-004 AC: dialing a peer whose cert doesn't match its pin fails, so
    /// nothing is sent to an interceptor; the right pin then works.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_mesh_refuses_a_peer_with_the_wrong_pin() {
        let a = node(3).await;
        let b = node(4).await;
        let addr_b = b.local_addr();
        let impostor = TlsIdentity::from_wireguard_key(&[5; 32]).unwrap();

        a.set_peer_pins(&[(addr_b, vec![impostor.fingerprint()])]);
        // Refused, but as a dropped datagram — not an error that would take
        // the whole mesh session down (review fix).
        a.send_to(addr_b, b"x").await.unwrap();
        let mut buf = [0u8; 16];
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), b.recv_from(&mut buf))
                .await
                .is_err(),
            "nothing may reach a peer that failed its pin"
        );
        // While backing off, a send doesn't even re-dial.
        let t0 = std::time::Instant::now();
        a.send_to(addr_b, b"y").await.unwrap();
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(100),
            "re-dialed during backoff"
        );

        // With the right pin (which also clears the backoff), the same dial
        // succeeds and B receives.
        a.set_peer_pins(&[(addr_b, vec![b.fingerprint()])]);
        a.send_to(addr_b, b"hello").await.unwrap();
        let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(5), b.recv_from(&mut buf))
            .await
            .expect("B did not receive after a correctly pinned dial")
            .unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    /// SEC-007 AC: mid-rotation, the dialer's map still lists the peer's old
    /// pin as current and the new one as *next*. A peer that has already
    /// rolled (it presents the next key) connects; a peer presenting a key in
    /// neither slot is refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_mesh_accepts_a_peer_that_rolled_to_its_announced_next_key() {
        let a = node(21).await;
        let old = TlsIdentity::from_wireguard_key(&[22; 32]).unwrap();
        let next = TlsIdentity::from_wireguard_key(&[23; 32]).unwrap();
        let (current_pin, next_pin) = (old.fingerprint(), next.fingerprint());
        let mut buf = [0u8; 16];

        // Rolled peer: already presenting its next key.
        let rolled = QuicMeshTransport::bind("127.0.0.1:0".parse().unwrap(), &next)
            .await
            .unwrap();
        a.set_peer_pins(&[(rolled.local_addr(), vec![current_pin, next_pin])]);
        a.send_to(rolled.local_addr(), b"rolled").await.unwrap();
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            rolled.recv_from(&mut buf),
        )
        .await
        .expect("a peer on its announced next key must still connect")
        .unwrap();
        assert_eq!(&buf[..n], b"rolled");

        // Unlisted key under the same (current, next) pins: refused.
        let stranger = node(24).await;
        a.set_peer_pins(&[(stranger.local_addr(), vec![current_pin, next_pin])]);
        a.send_to(stranger.local_addr(), b"x").await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(300),
                stranger.recv_from(&mut buf)
            )
            .await
            .is_err(),
            "a key in neither pin slot must be refused"
        );
    }

    /// Review fix: re-applying the *same* pins (every network-map update does)
    /// keeps a refused peer's backoff; changing its pin clears it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unchanged_pins_keep_their_backoff() {
        let a = node(11).await;
        assert_eq!(a.tls_fingerprint(), Some(a.fingerprint()));
        let dst: SocketAddr = "192.0.2.7:9".parse().unwrap();
        let pins = [(dst, vec![[7u8; 32]])];
        a.set_peer_pins(&pins);
        a.backoff.lock().unwrap().note_failure(dst, Instant::now());

        a.set_peer_pins(&pins); // same pins: still backing off
        assert!(a.backoff.lock().unwrap().is_waiting(dst, Instant::now()));

        a.set_peer_pins(&[(dst, vec![[8u8; 32]])]); // new pin: retry now
        assert!(!a.backoff.lock().unwrap().is_waiting(dst, Instant::now()));
    }

    #[test]
    fn dial_backoff_doubles_caps_and_resets() {
        let dst: SocketAddr = "192.0.2.1:1".parse().unwrap();
        let t0 = Instant::now();
        let mut b = DialBackoff::default();
        assert!(!b.is_waiting(dst, t0));
        assert_eq!(b.note_failure(dst, t0), DIAL_BACKOFF_MIN);
        assert!(b.is_waiting(dst, t0));
        assert!(!b.is_waiting(dst, t0 + DIAL_BACKOFF_MIN));
        assert_eq!(b.note_failure(dst, t0), DIAL_BACKOFF_MIN * 2);
        for _ in 0..10 {
            b.note_failure(dst, t0);
        }
        assert_eq!(b.note_failure(dst, t0), DIAL_BACKOFF_MAX);
        b.note_success(dst);
        assert!(!b.is_waiting(dst, t0));
    }

    /// No pin for a peer: still dialed (with the unauthenticated warning).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_mesh_dials_unpinned_peers_with_a_warning() {
        let a = node(6).await;
        let b = node(7).await;
        a.send_to(b.local_addr(), b"unpinned").await.unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = b.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"unpinned");
    }

    /// Two QUIC mesh endpoints exchange a datagram both ways, with each side
    /// identified by its advertised address (proves the hello attribution).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_mesh_roundtrip_both_directions() {
        let a = node(1).await;
        let b = node(2).await;
        let (addr_a, addr_b) = (a.local_addr(), b.local_addr());
        // Each side pins the other's stable cert.
        a.set_peer_pins(&[(addr_b, vec![b.fingerprint()])]);
        b.set_peer_pins(&[(addr_a, vec![a.fingerprint()])]);

        // A -> B.
        a.send_to(addr_b, b"from-a").await.unwrap();
        let mut buf = [0u8; 64];
        let (n, src) = b.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"from-a");
        assert_eq!(
            src, addr_a,
            "B must see the datagram as coming from A's address"
        );

        // B -> A.
        b.send_to(addr_a, b"from-b").await.unwrap();
        let (n, src) = a.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"from-b");
        assert_eq!(
            src, addr_b,
            "A must see the datagram as coming from B's address"
        );
    }
}
