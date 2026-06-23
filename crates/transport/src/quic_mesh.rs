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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};
use tokio::sync::{mpsc, Mutex};

use crate::quic::{install_provider, SkipServerVerification};
use crate::{MeshTransport, TransportError};

/// TLS server name presented/accepted (peer identity is the inner WireGuard
/// handshake, not TLS — see [`crate::quic`]).
const SERVER_NAME: &str = "ferrum";

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
    /// Connections we dialed, keyed by the peer's advertised address (used to send).
    dialed: Mutex<HashMap<SocketAddr, Connection>>,
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
    /// Bind a dual-role (accept + dial) QUIC endpoint to serve the mesh.
    pub async fn bind(local: SocketAddr) -> Result<Self, TransportError> {
        let endpoint = build_endpoint(local)?;
        let local_addr = endpoint.local_addr().map_err(TransportError::Io)?;

        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let accept_task = tokio::spawn(accept_loop(endpoint.clone(), inbound_tx.clone()));

        Ok(Self {
            endpoint,
            local_addr,
            dialed: Mutex::new(HashMap::new()),
            inbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            accept_task,
        })
    }

    /// The local (advertised) address this endpoint is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the connection to `dst`, dialing (and announcing ourselves) if needed.
    async fn connection_to(&self, dst: SocketAddr) -> Result<Connection, TransportError> {
        let mut dialed = self.dialed.lock().await;
        if let Some(conn) = dialed.get(&dst) {
            return Ok(conn.clone());
        }
        let conn = self
            .endpoint
            .connect(dst, SERVER_NAME)
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
    async fn send_to(&self, dst: SocketAddr, datagram: &[u8]) -> Result<(), TransportError> {
        let conn = self.connection_to(dst).await?;
        conn.send_datagram(Bytes::copy_from_slice(datagram))
            .map_err(|e| conn_err(format!("send_datagram {dst}: {e}")))
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

/// Build a quinn endpoint that can both accept connections and dial peers,
/// using a self-signed cert (transport encryption/camouflage only).
fn build_endpoint(local: SocketAddr) -> Result<Endpoint, TransportError> {
    install_provider();

    // Server side: self-signed cert (the inner WireGuard handshake authenticates).
    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])
        .map_err(|e| setup(format!("self-signed cert: {e}")))?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .map_err(|e| setup(format!("server tls: {e}")))?;
    let server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto)
            .map_err(|e| setup(format!("quic server: {e}")))?,
    ));

    let mut endpoint = Endpoint::server(server_config, local).map_err(TransportError::Io)?;

    // Client side: accept any server cert (peer identity is WireGuard's job).
    let client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
        .with_no_client_auth();
    let client_config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto)
            .map_err(|e| setup(format!("quic client: {e}")))?,
    ));
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two QUIC mesh endpoints exchange a datagram both ways, with each side
    /// identified by its advertised address (proves the hello attribution).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_mesh_roundtrip_both_directions() {
        let a = QuicMeshTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b = QuicMeshTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let (addr_a, addr_b) = (a.local_addr(), b.local_addr());

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
