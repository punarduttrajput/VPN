//! QUIC transport (PRD Phase 2, FR2).
//!
//! Carries WireGuard packets as QUIC datagrams. QUIC is encrypted, multiplexed,
//! and ubiquitous (HTTP/3), so the traffic blends with ordinary web QUIC and
//! gains roaming-friendly properties. Peer authenticity is already guaranteed by
//! the inner WireGuard handshake, so the QUIC layer uses a self-signed cert with
//! a permissive verifier — the TLS layer here is for transport encryption and
//! camouflage, not peer identity.
//!
//! Deferred to later Phase 2 increments: MASQUE/HTTP3 framing, connection
//! migration, and padding/timing obfuscation.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};

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
    // Endpoint is kept alive for the duration of the connection.
    _endpoint: Endpoint,
}

impl QuicTransport {
    /// Create a bound, configured server endpoint (call [`accept`] to take a peer).
    ///
    /// [`accept`]: QuicTransport::accept
    pub fn server_endpoint(local: SocketAddr) -> Result<Endpoint, TransportError> {
        install_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["vpn".to_string()])
            .map_err(|e| setup(format!("self-signed cert: {e}")))?;
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

        let crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der.into())
            .map_err(|e| setup(format!("server tls: {e}")))?;
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
            _endpoint: endpoint,
        })
    }

    /// Largest datagram the peer will currently accept, if datagrams are
    /// supported. The tunnel must keep encrypted packets within this limit, so
    /// the inner MTU over QUIC is reduced accordingly (QUIC adds header overhead
    /// and starts at a conservative path MTU until discovery raises it).
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }

    /// Connect to a QUIC server at `server` from local address `local`.
    pub async fn connect(
        local: SocketAddr,
        server: SocketAddr,
        server_name: &str,
    ) -> Result<Self, TransportError> {
        install_provider();
        let mut endpoint = Endpoint::client(local).map_err(TransportError::Io)?;

        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
            .with_no_client_auth();
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
            _endpoint: endpoint,
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

/// A rustls verifier that accepts any server certificate. Safe here because the
/// inner WireGuard handshake — not TLS — authenticates the peer (see module docs).
#[derive(Debug)]
pub(crate) struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    pub(crate) fn new() -> Self {
        Self(Arc::new(rustls::crypto::ring::default_provider()))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A WireGuard-sized packet survives a QUIC datagram round trip (FR2).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_datagram_roundtrip() {
        let endpoint = QuicTransport::server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = endpoint.local_addr().unwrap();

        // Server: accept, echo one datagram, then stay alive until the client
        // closes so the (unreliable) echoed datagram is actually flushed.
        let server = tokio::spawn(async move {
            let t = QuicTransport::accept(endpoint).await.unwrap();
            let mut buf = [0u8; 1500];
            let n = t.recv(&mut buf).await.unwrap();
            t.send(&buf[..n]).await.unwrap();
            t.connection.closed().await;
        });

        let client = QuicTransport::connect("127.0.0.1:0".parse().unwrap(), server_addr, "vpn")
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
}
