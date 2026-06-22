//! MASQUE CONNECT-UDP over HTTP/3 (PRD Phase 2, FR3).
//!
//! The tunnel's encrypted WireGuard packets are carried inside HTTP/3 datagrams
//! of a CONNECT-UDP request (RFC 9298, on top of RFC 9297 HTTP datagrams). On the
//! wire this is ordinary HTTP/3 (ALPN `h3`) on UDP/443, so a censor sees web QUIC
//! rather than a VPN. A [`MasqueProxy`] terminates HTTP/3 and relays the inner UDP
//! to the real WireGuard endpoint; [`MasqueTransport`] is the client side and
//! implements [`Transport`].
//!
//! Built on the (pre-1.0) `h3` / `h3-datagram` crates. The RFC 9297 quarter-
//! stream-id framing is handled by `h3-datagram`; this module adds the RFC 9298
//! context-id (0 = UDP payload) prefix. To sidestep naming h3's generic types,
//! the h3 datagram handles live in spawned tasks that exchange bytes with the
//! transport over channels.
//!
//! Scope: verified in-process (client ↔ proxy ↔ UDP echo). Interop with
//! third-party MASQUE proxies (capsule protocol, full path conformance) is not
//! yet verified.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use h3_datagram::datagram_handler::HandleDatagramsExt;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use crate::quic::{install_provider, SkipServerVerification};
use crate::{Transport, TransportError};

const CHANNEL_CAP: usize = 1024;

fn setup(e: impl std::fmt::Display) -> TransportError {
    TransportError::Setup(e.to_string())
}
fn conn_err(e: impl std::fmt::Display) -> TransportError {
    TransportError::Connection(e.to_string())
}

/// Prepend the RFC 9298 context-id (0 = UDP payload, a single-byte varint).
fn frame_ctx(payload: &[u8]) -> Bytes {
    let mut b = BytesMut::with_capacity(payload.len() + 1);
    b.put_u8(0);
    b.extend_from_slice(payload);
    b.freeze()
}

/// Strip the context-id; return the UDP payload for context 0, else `None`.
fn strip_ctx(datagram: Bytes) -> Option<Bytes> {
    if datagram.first() != Some(&0) {
        return None;
    }
    Some(datagram.slice(1..))
}

/// ALPN-`h3` rustls client config that accepts any server cert (peer identity is
/// established by the inner WireGuard handshake, not TLS).
fn h3_client_crypto() -> Result<QuicClientConfig, TransportError> {
    install_provider();
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    QuicClientConfig::try_from(crypto).map_err(setup)
}

/// ALPN-`h3` rustls server config with a self-signed cert.
fn h3_server_crypto() -> Result<QuicServerConfig, TransportError> {
    install_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["vpn".to_string()]).map_err(setup)?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key.into())
        .map_err(setup)?;
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    QuicServerConfig::try_from(crypto).map_err(setup)
}

/// Client side of a MASQUE CONNECT-UDP tunnel.
pub struct MasqueTransport {
    out_tx: mpsc::Sender<Bytes>,
    in_rx: Mutex<mpsc::Receiver<Bytes>>,
    _endpoint: Endpoint,
}

impl MasqueTransport {
    /// Open a CONNECT-UDP session to a MASQUE `proxy` that will relay to `target`.
    pub async fn connect(
        local: SocketAddr,
        proxy: SocketAddr,
        authority: &str,
        target: SocketAddr,
    ) -> Result<Self, TransportError> {
        let mut endpoint = Endpoint::client(local).map_err(TransportError::Io)?;
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(h3_client_crypto()?)));

        let conn = endpoint
            .connect(proxy, authority)
            .map_err(conn_err)?
            .await
            .map_err(conn_err)?;
        let h3c = h3_quinn::Connection::new(conn);

        let (mut driver, mut send_request) = h3::client::builder()
            .enable_datagram(true)
            .enable_extended_connect(true)
            .build::<h3_quinn::Connection, h3_quinn::OpenStreams, Bytes>(h3c)
            .await
            .map_err(conn_err)?;

        // Extended CONNECT-UDP request (RFC 9298 well-known template).
        let path = format!("/.well-known/masque/udp/{}/{}/", target.ip(), target.port());
        let uri: http::Uri = format!("https://{authority}{path}")
            .parse()
            .map_err(setup)?;
        let mut req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(uri)
            .body(())
            .map_err(setup)?;
        req.extensions_mut().insert(h3::ext::Protocol::CONNECT_UDP);

        let mut req_stream = send_request.send_request(req).await.map_err(conn_err)?;
        let resp = req_stream.recv_response().await.map_err(conn_err)?;
        if resp.status() != http::StatusCode::OK {
            return Err(conn_err(format!("masque proxy refused: {}", resp.status())));
        }
        let stream_id = req_stream.id();

        let mut sender = driver.get_datagram_sender(stream_id);
        let mut reader = driver.get_datagram_reader();

        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(CHANNEL_CAP);
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(CHANNEL_CAP);

        // Outbound: channel -> HTTP datagram.
        tokio::spawn(async move {
            while let Some(b) = out_rx.recv().await {
                if sender.send_datagram(b).is_err() {
                    break;
                }
            }
        });
        // Inbound: HTTP datagram -> strip ctx -> channel.
        tokio::spawn(async move {
            while let Ok(dg) = reader.read_datagram().await {
                if let Some(p) = strip_ctx(dg.into_payload()) {
                    if in_tx.send(p).await.is_err() {
                        break;
                    }
                }
            }
        });
        // Drive the h3 connection; keep the request stream open for the session.
        tokio::spawn(async move {
            let _req = req_stream;
            let _sr = send_request;
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        Ok(Self {
            out_tx,
            in_rx: Mutex::new(in_rx),
            _endpoint: endpoint,
        })
    }
}

impl Transport for MasqueTransport {
    async fn send(&self, datagram: &[u8]) -> Result<(), TransportError> {
        self.out_tx
            .send(frame_ctx(datagram))
            .await
            .map_err(|_| conn_err("masque send channel closed"))
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let mut rx = self.in_rx.lock().await;
        let pkt = rx
            .recv()
            .await
            .ok_or_else(|| conn_err("masque recv channel closed"))?;
        let n = pkt.len().min(buf.len());
        buf[..n].copy_from_slice(&pkt[..n]);
        Ok(n)
    }
}

/// Parse the target UDP endpoint from an RFC 9298 CONNECT-UDP path template,
/// `/.well-known/masque/udp/{target_host}/{target_port}/`.
fn parse_connect_udp_target(path: &str) -> Option<SocketAddr> {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    // Find the "udp" marker; host and port are the next two segments.
    let i = segs.iter().position(|s| *s == "udp")?;
    let host = segs.get(i + 1)?;
    let port: u16 = segs.get(i + 2)?.parse().ok()?;
    let ip: std::net::IpAddr = host.parse().ok()?;
    Some(SocketAddr::new(ip, port))
}

/// A MASQUE proxy that terminates HTTP/3 CONNECT-UDP sessions and relays each to
/// the UDP target named in its request. Handles many concurrent sessions, one
/// per QUIC connection — which is what a mesh node needs (one session per peer).
pub struct MasqueProxy {
    endpoint: Endpoint,
}

impl MasqueProxy {
    /// Bind a MASQUE proxy (HTTP/3, ALPN `h3`) on `local`.
    pub fn bind(local: SocketAddr) -> Result<Self, TransportError> {
        let server_config = ServerConfig::with_crypto(Arc::new(h3_server_crypto()?));
        let endpoint = Endpoint::server(server_config, local).map_err(TransportError::Io)?;
        Ok(Self { endpoint })
    }

    /// The proxy's bound address.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint.local_addr().map_err(TransportError::Io)
    }

    /// Accept connections forever, relaying each CONNECT-UDP session to the
    /// target named in its request path. One session per connection.
    pub async fn serve(&self) -> Result<(), TransportError> {
        while let Some(incoming) = self.endpoint.accept().await {
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        if let Err(e) = relay_connection(conn, None).await {
                            tracing::debug!("masque session ended: {e}");
                        }
                    }
                    Err(e) => tracing::debug!("masque accept failed: {e}"),
                }
            });
        }
        Ok(())
    }

    /// Accept one CONNECT-UDP session and relay it to `target` (ignoring the
    /// request path). Retained for the point-to-point path and tests.
    pub async fn serve_one(&self, target: SocketAddr) -> Result<(), TransportError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| conn_err("endpoint closed before a connection arrived"))?;
        let conn = incoming.await.map_err(conn_err)?;
        relay_connection(conn, Some(target)).await
    }
}

/// Relay a single CONNECT-UDP session on `conn`. The target is `target_override`
/// when given (point-to-point), else parsed from the request path (mesh proxy).
async fn relay_connection(
    conn: quinn::Connection,
    target_override: Option<SocketAddr>,
) -> Result<(), TransportError> {
    let h3c = h3_quinn::Connection::new(conn);
    let mut h3conn = h3::server::builder()
        .enable_datagram(true)
        .enable_extended_connect(true)
        .build::<h3_quinn::Connection, Bytes>(h3c)
        .await
        .map_err(conn_err)?;

    let resolver = h3conn
        .accept()
        .await
        .map_err(conn_err)?
        .ok_or_else(|| conn_err("no request on connection"))?;
    let (req, mut req_stream) = resolver.resolve_request().await.map_err(conn_err)?;

    let target = match target_override {
        Some(t) => t,
        None => parse_connect_udp_target(req.uri().path())
            .ok_or_else(|| conn_err(format!("bad CONNECT-UDP path: {}", req.uri().path())))?,
    };

    req_stream
        .send_response(
            http::Response::builder()
                .status(200)
                .body(())
                .map_err(setup)?,
        )
        .await
        .map_err(conn_err)?;
    let stream_id = req_stream.id();

    let mut sender = h3conn.get_datagram_sender(stream_id);
    let mut reader = h3conn.get_datagram_reader();

    let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(TransportError::Io)?;
    udp.connect(target).await.map_err(TransportError::Io)?;
    let udp = Arc::new(udp);

    // HTTP datagram -> UDP (to target).
    let udp_tx = udp.clone();
    tokio::spawn(async move {
        while let Ok(dg) = reader.read_datagram().await {
            if let Some(p) = strip_ctx(dg.into_payload()) {
                let _ = udp_tx.send(&p).await;
            }
        }
    });
    // UDP (from target) -> HTTP datagram.
    let udp_rx = udp.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok(n) = udp_rx.recv(&mut buf).await {
            if sender.send_datagram(frame_ctx(&buf[..n])).is_err() {
                break;
            }
        }
    });

    // Drive the connection (keep the request stream open) until it closes;
    // ignore any further requests on this session.
    let _req = req_stream;
    while let Ok(Some(_)) = h3conn.accept().await {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Full CONNECT-UDP path: client -> HTTP/3 datagram -> proxy -> UDP echo and back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn masque_connect_udp_roundtrip() {
        // UDP echo "server" standing in for the WireGuard endpoint.
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = echo.recv_from(&mut b).await {
                let _ = echo.send_to(&b[..n], from).await;
            }
        });

        let proxy = MasqueProxy::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = proxy.serve_one(target).await;
        });

        let client =
            MasqueTransport::connect("127.0.0.1:0".parse().unwrap(), proxy_addr, "vpn", target)
                .await
                .unwrap();

        client.send(b"masque-hello").await.unwrap();
        let mut out = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(8), client.recv(&mut out))
            .await
            .expect("masque roundtrip timed out")
            .unwrap();
        assert_eq!(&out[..n], b"masque-hello");
    }

    #[test]
    fn parses_connect_udp_target_from_path() {
        assert_eq!(
            parse_connect_udp_target("/.well-known/masque/udp/10.0.0.5/51820/"),
            Some("10.0.0.5:51820".parse().unwrap())
        );
        // Without a trailing slash.
        assert_eq!(
            parse_connect_udp_target("/.well-known/masque/udp/127.0.0.1/443"),
            Some("127.0.0.1:443".parse().unwrap())
        );
        assert_eq!(parse_connect_udp_target("/nope"), None);
        assert_eq!(
            parse_connect_udp_target("/.well-known/masque/udp/bad/x/"),
            None
        );
    }

    /// One proxy, two concurrent CONNECT-UDP sessions to *different* targets,
    /// each routed by its request path (the multi-session mesh shape).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn masque_proxy_serves_multiple_targets() {
        // Two distinct echo "peers".
        async fn echo(tag: u8) -> (SocketAddr, tokio::task::JoinHandle<()>) {
            let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = s.local_addr().unwrap();
            let h = tokio::spawn(async move {
                let mut b = [0u8; 2048];
                while let Ok((n, from)) = s.recv_from(&mut b).await {
                    // Echo with the peer tag prepended so we can tell them apart.
                    let mut reply = vec![tag];
                    reply.extend_from_slice(&b[..n]);
                    let _ = s.send_to(&reply, from).await;
                }
            });
            (addr, h)
        }
        let (t1, _h1) = echo(1).await;
        let (t2, _h2) = echo(2).await;

        let proxy = MasqueProxy::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = proxy.serve().await;
        });

        // Two clients through the *same* proxy, each targeting a different peer.
        let c1 = MasqueTransport::connect("127.0.0.1:0".parse().unwrap(), proxy_addr, "vpn", t1)
            .await
            .unwrap();
        let c2 = MasqueTransport::connect("127.0.0.1:0".parse().unwrap(), proxy_addr, "vpn", t2)
            .await
            .unwrap();

        c1.send(b"to-one").await.unwrap();
        c2.send(b"to-two").await.unwrap();

        let mut b1 = [0u8; 64];
        let n1 = tokio::time::timeout(Duration::from_secs(8), c1.recv(&mut b1))
            .await
            .expect("c1 timed out")
            .unwrap();
        let mut b2 = [0u8; 64];
        let n2 = tokio::time::timeout(Duration::from_secs(8), c2.recv(&mut b2))
            .await
            .expect("c2 timed out")
            .unwrap();

        // Each client reached its own target (tag 1 / tag 2), proving the proxy
        // routed by request path, not a single fixed target.
        assert_eq!(&b1[..n1], b"\x01to-one");
        assert_eq!(&b2[..n2], b"\x02to-two");
    }
}
