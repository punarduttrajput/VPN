//! QUIC transport (PRD Phase 2, FR2).
//!
//! Carries WireGuard packets as QUIC datagrams. QUIC is encrypted, multiplexed,
//! and ubiquitous (HTTP/3), so the traffic blends with ordinary web QUIC and
//! gains roaming-friendly properties. Peer authenticity is guaranteed by the inner
//! WireGuard handshake; the QUIC layer is authenticated separately by **pinning**
//! the server's self-signed cert (SEC-004, see [`crate::tls`]): the server
//! presents a stable [`TlsIdentity`] derived from its WireGuard key, and the
//! client accepts only a cert whose public key's SHA-256 it was told to expect —
//! warning when it has no pin.
//!
//! Connection migration (FR4): a QUIC connection is keyed by connection IDs, not
//! by the 4-tuple, so it survives the client's local address changing (Wi-Fi →
//! cellular, NAT rebind). [`QuicTransport::rebind`] swaps the underlying UDP
//! socket; the next packet the client sends validates the new path and the server
//! follows it — the tunnel keeps running without a re-handshake.
//!
//! See also [`crate::masque`] (MASQUE / HTTP-3 CONNECT-UDP) and the padding and
//! timing-jitter decorators ([`crate::pad`], [`crate::jitter`]).

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};

use crate::tls::{self, Fingerprint, TlsIdentity};
use crate::{Transport, TransportError};

fn setup(msg: impl std::fmt::Display) -> TransportError {
    TransportError::Setup(msg.to_string())
}
fn conn(msg: impl std::fmt::Display) -> TransportError {
    TransportError::Connection(msg.to_string())
}

/// Install the ring crypto provider once (idempotent across calls/tests).
pub(crate) fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A QUIC datagram channel to a single peer.
pub struct QuicTransport {
    connection: Connection,
    // Owns the local UDP socket; kept for the connection's lifetime and used to
    // migrate the connection to a new local address (FR4).
    endpoint: Endpoint,
}

impl QuicTransport {
    /// Create a bound, configured server endpoint presenting `identity` (call
    /// [`accept`] to take a peer). Pass [`TlsIdentity::from_wireguard_key`] so the
    /// client can pin it.
    ///
    /// [`accept`]: QuicTransport::accept
    pub fn server_endpoint(
        local: SocketAddr,
        identity: &TlsIdentity,
    ) -> Result<Endpoint, TransportError> {
        let crypto = identity.server_crypto(tls::QUIC_ALPN)?;
        let quic_crypto =
            QuicServerConfig::try_from(crypto).map_err(|e| setup(format!("quic server: {e}")))?;
        let server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));

        Endpoint::server(server_config, local).map_err(TransportError::Io)
    }

    /// Accept one incoming connection on a server endpoint built by
    /// [`server_endpoint`](QuicTransport::server_endpoint).
    pub async fn accept(endpoint: Endpoint) -> Result<Self, TransportError> {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| conn("endpoint closed before a connection arrived"))?;
        let connection = incoming.await.map_err(|e| conn(format!("accept: {e}")))?;
        Ok(Self {
            connection,
            endpoint,
        })
    }

    /// Largest datagram the peer will currently accept, if datagrams are
    /// supported. The tunnel must keep encrypted packets within this limit, so
    /// the inner MTU over QUIC is reduced accordingly (QUIC adds header overhead
    /// and starts at a conservative path MTU until discovery raises it).
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }

    /// The connection's current remote address. For a server transport this
    /// follows the client after a migration (FR4), so it reflects the latest
    /// validated path.
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// The local address this transport's endpoint is currently bound to
    /// (changes after [`rebind`](QuicTransport::rebind)).
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint.local_addr().map_err(TransportError::Io)
    }

    /// Infallible form of [`local_addr`](QuicTransport::local_addr) for use in
    /// tests and assertions — panics if the OS rejects the query.
    pub fn local_addr_of_endpoint(&self) -> SocketAddr {
        self.endpoint.local_addr().expect("endpoint local addr")
    }

    /// Migrate this (client) connection to a fresh local UDP socket bound at
    /// `new_local` — QUIC connection migration / roaming (FR4).
    ///
    /// The QUIC connection is identified by connection IDs, not the 4-tuple, so
    /// it survives the local address change: the next datagram the client sends
    /// goes out the new socket, the server validates the new path, and traffic
    /// continues without a re-handshake. Call this on the client side after a
    /// network change; pass `0.0.0.0:0` / `[::]:0` to let the OS pick a port.
    pub fn rebind(&self, new_local: SocketAddr) -> Result<(), TransportError> {
        let socket = std::net::UdpSocket::bind(new_local).map_err(TransportError::Io)?;
        self.endpoint.rebind(socket).map_err(TransportError::Io)?;
        Ok(())
    }

    /// Connect to a QUIC server at `server` from local address `local`,
    /// accepting only a server cert whose SHA-256 is in `pins`. An empty `pins`
    /// connects anyway but logs an "outer transport unauthenticated" warning.
    pub async fn connect(
        local: SocketAddr,
        server: SocketAddr,
        server_name: &str,
        pins: Vec<Fingerprint>,
    ) -> Result<Self, TransportError> {
        let mut endpoint = Endpoint::client(local).map_err(TransportError::Io)?;

        let crypto = tls::client_crypto(pins, format!("QUIC server {server}"), tls::QUIC_ALPN);
        let quic_crypto =
            QuicClientConfig::try_from(crypto).map_err(|e| setup(format!("quic client: {e}")))?;
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(quic_crypto)));

        let connection = endpoint
            .connect(server, server_name)
            .map_err(|e| conn(format!("connect: {e}")))?
            .await
            .map_err(|e| conn(format!("handshake: {e}")))?;

        Ok(Self {
            connection,
            endpoint,
        })
    }
}

impl Transport for QuicTransport {
    async fn send(&self, datagram: &[u8]) -> Result<(), TransportError> {
        self.connection
            .send_datagram(Bytes::copy_from_slice(datagram))
            .map_err(|e| conn(format!("send_datagram: {e}")))
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let datagram = self
            .connection
            .read_datagram()
            .await
            .map_err(|e| conn(format!("read_datagram: {e}")))?;
        let n = datagram.len().min(buf.len());
        buf[..n].copy_from_slice(&datagram[..n]);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server endpoint on loopback with a stable identity; returns its address
    /// and pin.
    fn pinned_server(key: u8) -> (Endpoint, SocketAddr, Fingerprint) {
        let id = TlsIdentity::from_wireguard_key(&[key; 32]).unwrap();
        let ep = QuicTransport::server_endpoint("127.0.0.1:0".parse().unwrap(), &id).unwrap();
        let addr = ep.local_addr().unwrap();
        (ep, addr, id.fingerprint())
    }

    /// The SNI and ALPN the server saw for one client connection dialed with
    /// `name`.
    async fn hello_seen_by_server(name: Option<&str>) -> (Option<String>, Option<Vec<u8>>) {
        let (endpoint, server_addr, pin) = pinned_server(4);
        let server = tokio::spawn(async move {
            let t = QuicTransport::accept(endpoint).await.unwrap();
            let data = t.connection.handshake_data().expect("handshake done");
            let data = data
                .downcast::<quinn::crypto::rustls::HandshakeData>()
                .expect("rustls handshake data");
            t.connection.close(0u32.into(), b"done");
            (data.server_name, data.protocol)
        });
        let _client = QuicTransport::connect(
            "127.0.0.1:0".parse().unwrap(),
            server_addr,
            &tls::dial_name(name, server_addr),
            vec![pin],
        )
        .await
        .unwrap();
        server.await.unwrap()
    }

    /// SEC-020: by default the ClientHello carries no SNI at all, so nothing
    /// on the path reads a product name; a configured name is sent verbatim.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sni_is_absent_by_default_and_configurable() {
        assert_eq!(hello_seen_by_server(None).await.0, None);
        assert_eq!(
            hello_seen_by_server(Some("cdn.example.net"))
                .await
                .0
                .as_deref(),
            Some("cdn.example.net")
        );
    }

    /// SEC-021: plain QUIC negotiates ALPN `h3`, like web QUIC, rather than
    /// offering none.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_negotiates_h3_alpn() {
        assert_eq!(
            hello_seen_by_server(None).await.1.as_deref(),
            Some(&b"h3"[..])
        );
    }

    /// SEC-021 is a flag day: a pre-SEC-021 client that offers no ALPN can't
    /// complete a handshake with an upgraded server (RFC 9001 §8.1, enforced
    /// by rustls in QUIC mode). Pins the documented incompatibility.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_without_alpn_is_refused() {
        let (endpoint, server_addr, pin) = pinned_server(5);
        tokio::spawn(async move {
            let _ = QuicTransport::accept(endpoint).await;
        });
        let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let legacy = tls::client_crypto(vec![pin], "legacy client", &[]);
        client.set_default_client_config(ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(legacy).unwrap(),
        )));
        let res = client
            .connect(server_addr, &tls::dial_name(None, server_addr))
            .unwrap()
            .await;
        assert!(res.is_err(), "an ALPN-less client must be refused");
    }

    /// A WireGuard-sized packet survives a QUIC datagram round trip (FR2).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_datagram_roundtrip() {
        let (endpoint, server_addr, pin) = pinned_server(1);

        // Server: accept, echo one datagram, then stay alive until the client
        // closes so the (unreliable) echoed datagram is actually flushed.
        let server = tokio::spawn(async move {
            let t = QuicTransport::accept(endpoint).await.unwrap();
            let mut buf = [0u8; 1500];
            let n = t.recv(&mut buf).await.unwrap();
            t.send(&buf[..n]).await.unwrap();
            t.connection.closed().await;
        });

        let client = QuicTransport::connect(
            "127.0.0.1:0".parse().unwrap(),
            server_addr,
            "ferrum",
            vec![pin],
        )
        .await
        .unwrap();

        // Size the payload to the negotiated datagram limit (a realistic
        // WireGuard-sized packet that fits QUIC's conservative initial MTU).
        let max = client.max_datagram_size().expect("datagrams supported");
        assert!(max >= 1000, "expected a usable datagram size, got {max}");
        let payload = vec![0xABu8; max.min(1200)];
        client.send(&payload).await.unwrap();
        let mut buf = [0u8; 1500];
        let n = client.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &payload[..]);

        // Closing the client lets the server's `closed()` resolve and the task end.
        drop(client);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server).await;
    }

    /// The connection survives the client rebinding to a new local socket
    /// (QUIC connection migration / roaming, FR4): datagrams still flow after
    /// the address change, and the server observes the client's new address.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_connection_survives_client_migration() {
        use std::time::Duration;

        let (endpoint, server_addr, pin) = pinned_server(2);

        // Server: echo every datagram until the client closes, reporting the
        // remote address it saw on the last datagram.
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let t = QuicTransport::accept(endpoint).await.unwrap();
            let mut buf = [0u8; 1500];
            // First datagram (pre-migration).
            let n = t.recv(&mut buf).await.unwrap();
            t.send(&buf[..n]).await.unwrap();
            // Second datagram (post-migration) arrives over the new path.
            let n = t.recv(&mut buf).await.unwrap();
            t.send(&buf[..n]).await.unwrap();
            let _ = addr_tx.send(t.remote_address());
            t.connection.closed().await;
        });

        let client = QuicTransport::connect(
            "127.0.0.1:0".parse().unwrap(),
            server_addr,
            "ferrum",
            vec![pin],
        )
        .await
        .unwrap();
        let before = client.local_addr_of_endpoint();

        // Pre-migration exchange.
        client.send(b"before").await.unwrap();
        let mut buf = [0u8; 1500];
        let n = client.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"before");

        // Roam: rebind to a fresh local socket. The connection must survive.
        client.rebind("127.0.0.1:0".parse().unwrap()).unwrap();
        let after = client.local_addr_of_endpoint();
        assert_ne!(
            before, after,
            "endpoint should be bound to a new local port"
        );

        // Post-migration exchange over the new path.
        client.send(b"after").await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
            .await
            .expect("post-migration recv timed out")
            .unwrap();
        assert_eq!(&buf[..n], b"after", "datagrams flow after migration");

        // The server saw the client's new (migrated) address on the last packet.
        let seen = tokio::time::timeout(Duration::from_secs(5), addr_rx)
            .await
            .expect("server address report timed out")
            .unwrap();
        assert_eq!(seen, after, "server followed the client to its new address");

        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }

    /// SEC-004 AC: a client refuses a server whose cert doesn't match its pin —
    /// the case of an on-path interceptor presenting its own cert.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_rejects_a_server_that_does_not_match_the_pin() {
        let (endpoint, server_addr, _real_pin) = pinned_server(3);
        tokio::spawn(async move {
            let _ = QuicTransport::accept(endpoint).await;
        });
        let wrong = TlsIdentity::from_wireguard_key(&[4; 32])
            .unwrap()
            .fingerprint();
        let res = QuicTransport::connect(
            "127.0.0.1:0".parse().unwrap(),
            server_addr,
            "ferrum",
            vec![wrong],
        )
        .await;
        let err = res.err().expect("mismatched pin must fail the handshake");
        assert!(err.to_string().contains("handshake"), "{err}");
    }

    /// Several pins (current + next across a rotation): any match is accepted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn any_configured_pin_matches() {
        let (endpoint, server_addr, pin) = pinned_server(5);
        tokio::spawn(async move {
            let _ = QuicTransport::accept(endpoint).await;
        });
        let other = TlsIdentity::from_wireguard_key(&[6; 32])
            .unwrap()
            .fingerprint();
        QuicTransport::connect(
            "127.0.0.1:0".parse().unwrap(),
            server_addr,
            "ferrum",
            vec![other, pin],
        )
        .await
        .expect("a matching pin in the set must be accepted");
    }

    /// SEC-004 AC (no-pin path): with nothing to pin, the client still connects
    /// (the warning is logged by `tls::PinnedVerifier`), preserving the
    /// pre-pinning behavior rather than breaking unconfigured deployments.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unpinned_client_still_connects() {
        let id = TlsIdentity::ephemeral().unwrap();
        let endpoint = QuicTransport::server_endpoint("127.0.0.1:0".parse().unwrap(), &id).unwrap();
        let server_addr = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = QuicTransport::accept(endpoint).await;
        });
        QuicTransport::connect(
            "127.0.0.1:0".parse().unwrap(),
            server_addr,
            "ferrum",
            vec![],
        )
        .await
        .expect("unpinned connect should succeed (with a warning)");
    }
}
