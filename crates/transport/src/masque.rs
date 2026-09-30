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
//! [`MasqueMeshTransport`] is the multi-peer counterpart used by the mesh data
//! plane: one CONNECT-UDP session per peer through a single proxy.
//!
//! RFC 9298/9297 conformance: the request/response carry `Capsule-Protocol: ?1`
//! (RFC 9297 §3.4), the client accepts any 2xx as success, and the proxy parses
//! the well-known path template (IPv4/IPv6 literals, bracketed or bare). Scope:
//! verified in-process (client ↔ proxy ↔ UDP echo, and a MASQUE mesh node
//! reaching a UDP peer through the proxy). Interop against a *third-party* MASQUE
//! proxy (full capsule handling on the stream, percent-encoded hostnames) still
//! needs a live proxy to confirm.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use h3_datagram::datagram_handler::HandleDatagramsExt;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use crate::tls::{self, Fingerprint, TlsIdentity};
use crate::{MeshTransport, Transport, TransportError};

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

/// ALPN-`h3` rustls client config pinning the proxy's cert to `pins` (SEC-004;
/// an empty list connects with the "outer transport unauthenticated" warning).
fn h3_client_crypto(
    pins: Vec<Fingerprint>,
    proxy: SocketAddr,
) -> Result<QuicClientConfig, TransportError> {
    let crypto = tls::client_crypto(pins, format!("MASQUE proxy {proxy}"), &[b"h3"]);
    QuicClientConfig::try_from(crypto).map_err(setup)
}

/// ALPN-`h3` rustls server config presenting `identity`.
fn h3_server_crypto(identity: &TlsIdentity) -> Result<QuicServerConfig, TransportError> {
    QuicServerConfig::try_from(identity.server_crypto(&[b"h3"])?).map_err(setup)
}

/// Client side of a MASQUE CONNECT-UDP tunnel.
pub struct MasqueTransport {
    out_tx: mpsc::Sender<Bytes>,
    in_rx: Mutex<mpsc::Receiver<Bytes>>,
    _endpoint: Endpoint,
}

impl MasqueTransport {
    /// Open a CONNECT-UDP session to a MASQUE `proxy` that will relay to `target`,
    /// accepting only a proxy cert whose SHA-256 is in `pins` (empty: connect
    /// with a warning).
    pub async fn connect(
        local: SocketAddr,
        proxy: SocketAddr,
        authority: &str,
        target: SocketAddr,
        pins: Vec<Fingerprint>,
    ) -> Result<Self, TransportError> {
        let mut endpoint = Endpoint::client(local).map_err(TransportError::Io)?;
        endpoint
            .set_default_client_config(ClientConfig::new(Arc::new(h3_client_crypto(pins, proxy)?)));

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

        // Extended CONNECT-UDP request (RFC 9298 well-known template). The
        // `capsule-protocol: ?1` header (RFC 9297 §3.4) signals capsule-protocol
        // support on the request stream — third-party proxies expect it.
        let path = format!("/.well-known/masque/udp/{}/{}/", target.ip(), target.port());
        let uri: http::Uri = format!("https://{authority}{path}")
            .parse()
            .map_err(setup)?;
        let mut req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(uri)
            .header("capsule-protocol", "?1")
            .body(())
            .map_err(setup)?;
        req.extensions_mut().insert(h3::ext::Protocol::CONNECT_UDP);

        let mut req_stream = send_request.send_request(req).await.map_err(conn_err)?;
        let resp = req_stream.recv_response().await.map_err(conn_err)?;
        // RFC 9298: any 2xx response means the CONNECT-UDP session is established.
        if !resp.status().is_success() {
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
///
/// `target_host` is an IP literal here (our targets are always coordinator-
/// assigned addresses, not names). IPv6 colons are valid path characters and
/// parse directly; an optional bracketed form (`[2001:db8::1]`) is also accepted
/// for robustness against clients that bracket the literal.
pub(crate) fn parse_connect_udp_target(path: &str) -> Option<SocketAddr> {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    // Find the "udp" marker; host and port are the next two segments.
    let i = segs.iter().position(|s| *s == "udp")?;
    let host = segs.get(i + 1)?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port: u16 = segs.get(i + 2)?.parse().ok()?;
    let ip: std::net::IpAddr = host.parse().ok()?;
    Some(SocketAddr::new(ip, port))
}

/// A MASQUE proxy that terminates HTTP/3 CONNECT-UDP sessions and relays each to
/// the UDP target named in its request. Handles many concurrent sessions, one
/// per QUIC connection — which is what a mesh node needs (one session per peer).
pub struct MasqueProxy {
    endpoint: Endpoint,
    fingerprint: Fingerprint,
}

impl MasqueProxy {
    /// Bind a MASQUE proxy (HTTP/3, ALPN `h3`) on `local` with a fresh random
    /// cert — clients can only pin it for this run (see [`fingerprint`](Self::fingerprint)).
    pub fn bind(local: SocketAddr) -> Result<Self, TransportError> {
        Self::bind_with_identity(local, &TlsIdentity::ephemeral()?)
    }

    /// Bind a MASQUE proxy presenting `identity` (a stable one is pinnable).
    pub fn bind_with_identity(
        local: SocketAddr,
        identity: &TlsIdentity,
    ) -> Result<Self, TransportError> {
        let server_config = ServerConfig::with_crypto(Arc::new(h3_server_crypto(identity)?));
        let endpoint = Endpoint::server(server_config, local).map_err(TransportError::Io)?;
        Ok(Self {
            endpoint,
            fingerprint: identity.fingerprint(),
        })
    }

    /// The SHA-256 pin of the cert this proxy presents.
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
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
                .header("capsule-protocol", "?1")
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

/// Multi-peer MASQUE transport for the mesh: one CONNECT-UDP session per peer,
/// all through a single proxy. `send_to(dst)` opens (lazily) and uses the session
/// whose target is `dst`; inbound datagrams from every session are merged and
/// tagged with that session's target.
///
/// A node using this never listens on a plain UDP endpoint — all its peer traffic
/// is tunnelled out through the proxy. Peers see that traffic arriving from the
/// proxy and (thanks to the mesh's crypto-demux + endpoint roaming) attribute it
/// to the right peer and reply along the proxy path. Each target peer must itself
/// be reachable as a UDP endpoint by the proxy.
pub struct MasqueMeshTransport {
    proxy: SocketAddr,
    authority: String,
    /// The proxy's expected cert pins (SEC-004); empty warns per session.
    pins: Vec<Fingerprint>,
    sessions: Mutex<HashMap<SocketAddr, Arc<MasqueTransport>>>,
    /// Targets whose session setup last failed (e.g. the proxy failed its pin).
    backoff: std::sync::Mutex<crate::quic_mesh::DialBackoff>,
    inbound_tx: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    inbound_rx: Mutex<mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>>,
}

impl MasqueMeshTransport {
    /// Create a mesh transport that tunnels every peer through `proxy`,
    /// presenting `authority` as the HTTP/3 `:authority` (also the TLS name) and
    /// pinning the proxy's cert to `pins` (empty: every session warns).
    pub fn new(proxy: SocketAddr, authority: impl Into<String>, pins: Vec<Fingerprint>) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        Self {
            proxy,
            authority: authority.into(),
            pins,
            sessions: Mutex::new(HashMap::new()),
            backoff: std::sync::Mutex::new(Default::default()),
            inbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
        }
    }

    /// Get the CONNECT-UDP session to `dst`, opening it (and its reader) if new.
    async fn session_for(&self, dst: SocketAddr) -> Result<Arc<MasqueTransport>, TransportError> {
        let mut sessions = self.sessions.lock().await;
        if let Some(s) = sessions.get(&dst) {
            return Ok(s.clone());
        }
        let local: SocketAddr = (Ipv4Addr::UNSPECIFIED, 0).into();
        let session = Arc::new(
            MasqueTransport::connect(local, self.proxy, &self.authority, dst, self.pins.clone())
                .await?,
        );

        // Pump this session's inbound datagrams into the shared channel, tagged
        // with the peer's target address.
        let reader = session.clone();
        let inbound_tx = self.inbound_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            // Ends when the session errors (closed) or the mesh transport drops.
            while let Ok(n) = reader.recv(&mut buf).await {
                if inbound_tx.send((dst, buf[..n].to_vec())).is_err() {
                    break;
                }
            }
        });

        sessions.insert(dst, session.clone());
        Ok(session)
    }
}

impl MeshTransport for MasqueMeshTransport {
    /// Send to one peer through the proxy. As with the QUIC mesh, a session that
    /// can't be set up (proxy unreachable, or it failed its pin) or has died is
    /// a dropped datagram, not a session-fatal error, with backed-off retries.
    async fn send_to(&self, dst: SocketAddr, datagram: &[u8]) -> Result<(), TransportError> {
        let now = std::time::Instant::now();
        if self
            .backoff
            .lock()
            .expect("masque backoff poisoned")
            .is_waiting(dst, now)
        {
            return Ok(());
        }
        let session = match self.session_for(dst).await {
            Ok(s) => s,
            Err(e) => {
                let retry_in = self
                    .backoff
                    .lock()
                    .expect("masque backoff poisoned")
                    .note_failure(dst, now);
                tracing::warn!(
                    "MASQUE mesh: no session to {dst} via {} ({e}); dropping, retrying in {retry_in:?}",
                    self.proxy
                );
                return Ok(());
            }
        };
        self.backoff
            .lock()
            .expect("masque backoff poisoned")
            .note_success(dst);
        if let Err(e) = session.send(datagram).await {
            tracing::debug!("MASQUE mesh: send to {dst} failed ({e}); reopening on the next send");
            self.sessions.lock().await.remove(&dst);
        }
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), TransportError> {
        let mut rx = self.inbound_rx.lock().await;
        let (src, data) = rx
            .recv()
            .await
            .ok_or_else(|| conn_err("masque mesh transport closed"))?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((n, src))
    }
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
        let pin = proxy.fingerprint();
        tokio::spawn(async move {
            let _ = proxy.serve_one(target).await;
        });

        let client = MasqueTransport::connect(
            "127.0.0.1:0".parse().unwrap(),
            proxy_addr,
            "ferrum",
            target,
            vec![pin],
        )
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
        // IPv6 literal (colons are valid path characters), bare and bracketed.
        assert_eq!(
            parse_connect_udp_target("/.well-known/masque/udp/2001:db8::42/443/"),
            Some("[2001:db8::42]:443".parse().unwrap())
        );
        assert_eq!(
            parse_connect_udp_target("/.well-known/masque/udp/[2001:db8::1]/51820/"),
            Some("[2001:db8::1]:51820".parse().unwrap())
        );
        // Rejections: not the template, bad host, oversized port, missing port.
        assert_eq!(parse_connect_udp_target("/nope"), None);
        assert_eq!(
            parse_connect_udp_target("/.well-known/masque/udp/bad/x/"),
            None
        );
        assert_eq!(
            parse_connect_udp_target("/.well-known/masque/udp/10.0.0.5/99999/"),
            None
        );
        assert_eq!(
            parse_connect_udp_target("/.well-known/masque/udp/10.0.0.5/"),
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
        let pin = proxy.fingerprint();
        tokio::spawn(async move {
            let _ = proxy.serve().await;
        });

        // Two clients through the *same* proxy, each targeting a different peer.
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let c1 = MasqueTransport::connect(local, proxy_addr, "ferrum", t1, vec![pin])
            .await
            .unwrap();
        let c2 = MasqueTransport::connect(local, proxy_addr, "ferrum", t2, vec![pin])
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

    /// `MasqueMeshTransport` reaches two different peers through one proxy and
    /// tags each inbound datagram with the peer it came from.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn masque_mesh_reaches_multiple_peers() {
        async fn echo(tag: u8) -> SocketAddr {
            let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = s.local_addr().unwrap();
            tokio::spawn(async move {
                let mut b = [0u8; 2048];
                while let Ok((n, from)) = s.recv_from(&mut b).await {
                    let mut reply = vec![tag];
                    reply.extend_from_slice(&b[..n]);
                    let _ = s.send_to(&reply, from).await;
                }
            });
            addr
        }
        let p1 = echo(1).await;
        let p2 = echo(2).await;

        let proxy = MasqueProxy::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let pin = proxy.fingerprint();
        tokio::spawn(async move {
            let _ = proxy.serve().await;
        });

        let mesh = MasqueMeshTransport::new(proxy_addr, "ferrum", vec![pin]);
        mesh.send_to(p1, b"hi-1").await.unwrap();
        mesh.send_to(p2, b"hi-2").await.unwrap();

        // Collect two inbound datagrams; each should be tagged with its peer.
        let mut got: std::collections::HashMap<SocketAddr, Vec<u8>> = HashMap::new();
        let mut buf = [0u8; 64];
        for _ in 0..2 {
            let (n, src) = tokio::time::timeout(Duration::from_secs(8), mesh.recv_from(&mut buf))
                .await
                .expect("masque mesh recv timed out")
                .unwrap();
            got.insert(src, buf[..n].to_vec());
        }

        assert_eq!(
            got.get(&p1).map(|v| v.as_slice()),
            Some(b"\x01hi-1".as_ref())
        );
        assert_eq!(
            got.get(&p2).map(|v| v.as_slice()),
            Some(b"\x02hi-2".as_ref())
        );
    }

    /// SEC-004 AC: a client pinned to the real proxy refuses an impostor proxy
    /// (e.g. an on-path box presenting its own cert).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn masque_client_rejects_an_impostor_proxy() {
        let expected = TlsIdentity::from_wireguard_key(&[9; 32]).unwrap();
        let impostor = MasqueProxy::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let impostor_addr = impostor.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = impostor.serve().await;
        });
        let res = MasqueTransport::connect(
            "127.0.0.1:0".parse().unwrap(),
            impostor_addr,
            "ferrum",
            "127.0.0.1:9".parse().unwrap(),
            vec![expected.fingerprint()],
        )
        .await;
        assert!(res.is_err(), "impostor proxy must be refused");
    }

    /// A proxy bound with a stable identity presents exactly that pin.
    #[tokio::test]
    async fn stable_proxy_identity_is_pinnable() {
        let id = TlsIdentity::from_wireguard_key(&[10; 32]).unwrap();
        let proxy = MasqueProxy::bind_with_identity("127.0.0.1:0".parse().unwrap(), &id).unwrap();
        assert_eq!(proxy.fingerprint(), id.fingerprint());
    }
}
