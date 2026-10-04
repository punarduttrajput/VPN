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
//! **Access control (SEC-015).** A proxy that relays anywhere is an SSRF hop and a
//! UDP reflector, so [`MasqueProxy`] enforces a [`TargetPolicy`] (default:
//! public unicast targets only; private ranges must be allowlisted), validates
//! that each request really is an extended CONNECT for `connect-udp`, and can
//! require client authentication through a [`ProxyAuthorizer`] (the
//! `authorization` bearer token the client sends via
//! [`MasqueTransport::connect_with_token`] /
//! [`MasqueMeshTransport::with_bearer_token`]). Without an authorizer it runs in
//! **open mode**: any client may use it within the target policy. That's
//! acceptable only on a network where reaching the proxy is itself the
//! authorization, and it is logged at startup.
//!
//! RFC 9298/9297 conformance: the request/response carry `Capsule-Protocol: ?1`
//! (RFC 9297 §3.4), the client accepts any 2xx as success, and the proxy parses
//! the well-known path template (IPv4/IPv6 literals, bracketed or bare). Scope:
//! verified in-process (client ↔ proxy ↔ UDP echo, and a MASQUE mesh node
//! reaching a UDP peer through the proxy). Interop against a *third-party* MASQUE
//! proxy (full capsule handling on the stream, percent-encoded hostnames) still
//! needs a live proxy to confirm.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use h3_datagram::datagram_handler::HandleDatagramsExt;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use crate::masque_policy::TargetPolicy;
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
    let crypto = tls::client_crypto(pins, format!("MASQUE proxy {proxy}"), tls::QUIC_ALPN);
    QuicClientConfig::try_from(crypto).map_err(setup)
}

/// ALPN-`h3` rustls server config presenting `identity`.
fn h3_server_crypto(identity: &TlsIdentity) -> Result<QuicServerConfig, TransportError> {
    QuicServerConfig::try_from(identity.server_crypto(tls::QUIC_ALPN)?).map_err(setup)
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
    /// with a warning). `authority` is the TLS name and HTTP/3 `:authority`;
    /// an IP literal (from [`tls::dial_name`](crate::tls::dial_name)) sends no
    /// SNI (SEC-020).
    pub async fn connect(
        local: SocketAddr,
        proxy: SocketAddr,
        authority: &str,
        target: SocketAddr,
        pins: Vec<Fingerprint>,
    ) -> Result<Self, TransportError> {
        Self::connect_with_token(local, proxy, authority, target, pins, None).await
    }

    /// [`connect`](Self::connect), presenting `token` as an
    /// `authorization: Bearer <token>` header on the CONNECT-UDP request, for a
    /// proxy that requires client authentication (SEC-015).
    pub async fn connect_with_token(
        local: SocketAddr,
        proxy: SocketAddr,
        authority: &str,
        target: SocketAddr,
        pins: Vec<Fingerprint>,
        token: Option<&str>,
    ) -> Result<Self, TransportError> {
        let mut endpoint = Endpoint::client(local).map_err(TransportError::Io)?;
        endpoint
            .set_default_client_config(ClientConfig::new(Arc::new(h3_client_crypto(pins, proxy)?)));

        // An IP-literal authority (the SEC-020 default) dials with no SNI; the
        // URI needs IPv6 literals bracketed, the TLS name doesn't.
        let tls_name = authority.trim_start_matches('[').trim_end_matches(']');
        let conn = endpoint
            .connect(proxy, tls_name)
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
        let uri_authority = match tls_name.parse::<std::net::Ipv6Addr>() {
            Ok(v6) => format!("[{v6}]"),
            Err(_) => tls_name.to_string(),
        };
        let uri: http::Uri = format!("https://{uri_authority}{path}")
            .parse()
            .map_err(setup)?;
        let mut builder = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(uri)
            .header("capsule-protocol", "?1");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let mut req = builder.body(()).map_err(setup)?;
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

/// Decides whether a CONNECT-UDP client may use the proxy (SEC-015). Given the
/// bearer token from the request's `authorization` header (`None` if absent or
/// not a bearer token), return `true` to allow. For example, check it against
/// the coordinator's OIDC verifier, or compare it (in constant time) against a
/// configured shared secret.
pub type ProxyAuthorizer = Arc<dyn Fn(Option<&str>) -> bool + Send + Sync>;

/// A MASQUE proxy that terminates HTTP/3 CONNECT-UDP sessions and relays each to
/// the UDP target named in its request. Handles many concurrent sessions, one
/// per QUIC connection — which is what a mesh node needs (one session per peer).
/// Targets are limited by a [`TargetPolicy`] and clients optionally checked by a
/// [`ProxyAuthorizer`] (see the module docs, SEC-015).
pub struct MasqueProxy {
    endpoint: Endpoint,
    fingerprint: Fingerprint,
    policy: Arc<TargetPolicy>,
    authorizer: Option<ProxyAuthorizer>,
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
            policy: Arc::new(TargetPolicy::public_only()),
            authorizer: None,
        })
    }

    /// Replace the target policy (default: [`TargetPolicy::public_only`]).
    pub fn with_target_policy(mut self, policy: TargetPolicy) -> Self {
        self.policy = Arc::new(policy);
        self
    }

    /// Require every client to pass `authorizer` (default: open mode).
    pub fn with_authorizer(mut self, authorizer: ProxyAuthorizer) -> Self {
        self.authorizer = Some(authorizer);
        self
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
        if self.authorizer.is_none() {
            tracing::warn!(
                "MASQUE proxy running in OPEN mode: no client authentication, any client \
                 may relay to targets its target policy allows"
            );
        }
        while let Some(incoming) = self.endpoint.accept().await {
            let (policy, authorizer) = (self.policy.clone(), self.authorizer.clone());
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        let access = Access::Policy(&policy);
                        if let Err(e) = relay_connection(conn, access, authorizer.as_ref()).await {
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
    /// request path). Retained for the point-to-point path and tests. The
    /// target is the operator's own choice here, so the target policy doesn't
    /// apply; the authorizer still does.
    pub async fn serve_one(&self, target: SocketAddr) -> Result<(), TransportError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| conn_err("endpoint closed before a connection arrived"))?;
        let conn = incoming.await.map_err(conn_err)?;
        relay_connection(conn, Access::Fixed(target), self.authorizer.as_ref()).await
    }
}

/// Where a session may relay: a fixed operator-chosen target, or whatever the
/// request names subject to the policy.
enum Access<'a> {
    Fixed(SocketAddr),
    Policy(&'a TargetPolicy),
}

/// The bearer token in a request's `authorization` header, if any.
fn bearer_token<B>(req: &http::Request<B>) -> Option<&str> {
    let value = req.headers().get("authorization")?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
}

/// Relay a single CONNECT-UDP session on `conn`. The target is `target_override`
/// when given (point-to-point), else parsed from the request path (mesh proxy).
async fn relay_connection(
    conn: quinn::Connection,
    access: Access<'_>,
    authorizer: Option<&ProxyAuthorizer>,
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

    // SEC-015: refuse (with a status the client can see) anything that isn't an
    // authorized extended CONNECT for connect-udp to a permitted target.
    let refusal = if req.method() != http::Method::CONNECT
        || req.extensions().get::<h3::ext::Protocol>() != Some(&h3::ext::Protocol::CONNECT_UDP)
    {
        Some((
            http::StatusCode::BAD_REQUEST,
            "not an extended CONNECT for connect-udp",
        ))
    } else if authorizer.is_some_and(|auth| !auth(bearer_token(&req))) {
        Some((http::StatusCode::UNAUTHORIZED, "client not authorized"))
    } else {
        None
    };
    let target = match (&refusal, &access) {
        (Some(_), _) => None,
        (None, Access::Fixed(t)) => Some(*t),
        (None, Access::Policy(_)) => parse_connect_udp_target(req.uri().path()),
    };
    let refusal = refusal.or(match (target, &access) {
        (None, _) => Some((http::StatusCode::BAD_REQUEST, "bad CONNECT-UDP path")),
        (Some(t), Access::Policy(policy)) if !policy.allows(t) => {
            Some((http::StatusCode::FORBIDDEN, "target not permitted"))
        }
        _ => None,
    });
    if let Some((status, why)) = refusal {
        // Don't log the requested path: it's client-chosen.
        tracing::debug!(%status, "refusing CONNECT-UDP request: {why}");
        let resp = http::Response::builder()
            .status(status)
            .body(())
            .map_err(setup)?;
        let _ = req_stream.send_response(resp).await;
        let _ = req_stream.finish().await;
        // Keep driving the connection until the client hangs up (bounded), or
        // dropping it here would close QUIC before the status reached them.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while let Ok(Some(_)) = h3conn.accept().await {}
        })
        .await;
        return Err(conn_err(format!("refused CONNECT-UDP request: {why}")));
    }
    let target = target.expect("target resolved when not refused");

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

    // Bind in the target's family, so IPv6 targets work too.
    let local: SocketAddr = if target.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let udp = UdpSocket::bind(local).await.map_err(TransportError::Io)?;
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
    /// Bearer token for a proxy that requires client authentication (SEC-015).
    token: Option<String>,
    sessions: Mutex<HashMap<SocketAddr, Arc<MasqueTransport>>>,
    /// Targets whose session setup last failed (e.g. the proxy failed its pin).
    backoff: std::sync::Mutex<crate::quic_mesh::DialBackoff>,
    inbound_tx: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    inbound_rx: Mutex<mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>>,
}

impl MasqueMeshTransport {
    /// Create a mesh transport that tunnels every peer through `proxy`,
    /// presenting `authority` as the HTTP/3 `:authority` (also the TLS name) and
    /// pinning the proxy's cert to `pins` (empty: every session warns). Pass
    /// [`tls::dial_name`](crate::tls::dial_name)`(configured, proxy)`: an IP
    /// literal there sends no SNI (SEC-020).
    pub fn new(proxy: SocketAddr, authority: impl Into<String>, pins: Vec<Fingerprint>) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        Self {
            proxy,
            authority: authority.into(),
            pins,
            token: None,
            sessions: Mutex::new(HashMap::new()),
            backoff: std::sync::Mutex::new(Default::default()),
            inbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
        }
    }

    /// Present `token` as a bearer token on every CONNECT-UDP session, for a
    /// proxy that requires client authentication (SEC-015).
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Get the CONNECT-UDP session to `dst`, opening it (and its reader) if new.
    async fn session_for(&self, dst: SocketAddr) -> Result<Arc<MasqueTransport>, TransportError> {
        let mut sessions = self.sessions.lock().await;
        if let Some(s) = sessions.get(&dst) {
            return Ok(s.clone());
        }
        let local: SocketAddr = (Ipv4Addr::UNSPECIFIED, 0).into();
        let session = Arc::new(
            MasqueTransport::connect_with_token(
                local,
                self.proxy,
                &self.authority,
                dst,
                self.pins.clone(),
                self.token.as_deref(),
            )
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

    /// The echo "peers" below live on loopback, which the default policy
    /// refuses (SEC-015), so these tests opt in explicitly.
    fn loopback_only() -> TargetPolicy {
        TargetPolicy::allowlist(["127.0.0.0/8"]).unwrap()
    }

    async fn echo_server() -> SocketAddr {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = s.recv_from(&mut b).await {
                let _ = s.send_to(&b[..n], from).await;
            }
        });
        addr
    }

    /// SEC-015: the default policy refuses a loopback target (the SSRF case)
    /// with 403, visible to the client as a refused session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn default_proxy_refuses_a_loopback_target() {
        let target = echo_server().await;
        let proxy = MasqueProxy::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let (proxy_addr, pin) = (proxy.local_addr().unwrap(), proxy.fingerprint());
        tokio::spawn(async move {
            let _ = proxy.serve().await;
        });
        let err = MasqueTransport::connect(
            "127.0.0.1:0".parse().unwrap(),
            proxy_addr,
            "127.0.0.1",
            target,
            vec![pin],
        )
        .await
        .err()
        .expect("a loopback target must be refused");
        assert!(err.to_string().contains("403"), "{err}");
    }

    /// SEC-015: with an authorizer, a client without the right bearer token
    /// is refused (401); the right token gets a working session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn authorizer_gates_the_proxy() {
        let target = echo_server().await;
        let authorizer: ProxyAuthorizer = Arc::new(|t| t == Some("s3cret"));
        let proxy = MasqueProxy::bind("127.0.0.1:0".parse().unwrap())
            .unwrap()
            .with_target_policy(loopback_only())
            .with_authorizer(authorizer);
        let (proxy_addr, pin) = (proxy.local_addr().unwrap(), proxy.fingerprint());
        tokio::spawn(async move {
            let _ = proxy.serve().await;
        });
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        for bad in [None, Some("wrong")] {
            let err = MasqueTransport::connect_with_token(
                local,
                proxy_addr,
                "127.0.0.1",
                target,
                vec![pin],
                bad,
            )
            .await
            .err()
            .expect("an unauthorized client must be refused");
            assert!(err.to_string().contains("401"), "{bad:?}: {err}");
        }
        let ok = MasqueTransport::connect_with_token(
            local,
            proxy_addr,
            "127.0.0.1",
            target,
            vec![pin],
            Some("s3cret"),
        )
        .await
        .unwrap();
        ok.send(b"authorized").await.unwrap();
        let mut out = [0u8; 32];
        let n = tokio::time::timeout(Duration::from_secs(8), ok.recv(&mut out))
            .await
            .expect("authorized session timed out")
            .unwrap();
        assert_eq!(&out[..n], b"authorized");
    }

    #[test]
    fn bearer_token_is_extracted_from_the_authorization_header() {
        let req = |v: &str| {
            http::Request::builder()
                .header("authorization", v)
                .body(())
                .unwrap()
        };
        assert_eq!(bearer_token(&req("Bearer abc")), Some("abc"));
        assert_eq!(bearer_token(&req("bearer abc")), Some("abc"));
        assert_eq!(bearer_token(&req("Basic abc")), None);
        assert_eq!(bearer_token(&http::Request::new(())), None);
    }

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

        let proxy = MasqueProxy::bind("127.0.0.1:0".parse().unwrap())
            .unwrap()
            .with_target_policy(loopback_only());
        let proxy_addr = proxy.local_addr().unwrap();
        let pin = proxy.fingerprint();
        tokio::spawn(async move {
            let _ = proxy.serve_one(target).await;
        });

        let client = MasqueTransport::connect(
            "127.0.0.1:0".parse().unwrap(),
            proxy_addr,
            "127.0.0.1",
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

        let proxy = MasqueProxy::bind("127.0.0.1:0".parse().unwrap())
            .unwrap()
            .with_target_policy(loopback_only());
        let proxy_addr = proxy.local_addr().unwrap();
        let pin = proxy.fingerprint();
        tokio::spawn(async move {
            let _ = proxy.serve().await;
        });

        // Two clients through the *same* proxy, each targeting a different peer.
        // SEC-020: a configured hostname, and a bare IPv6 literal (no SNI; the
        // URI must bracket it) both reach the in-tree proxy.
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let c1 = MasqueTransport::connect(local, proxy_addr, "cdn.example.net", t1, vec![pin])
            .await
            .unwrap();
        let c2 = MasqueTransport::connect(local, proxy_addr, "::1", t2, vec![pin])
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

        let proxy = MasqueProxy::bind("127.0.0.1:0".parse().unwrap())
            .unwrap()
            .with_target_policy(loopback_only());
        let proxy_addr = proxy.local_addr().unwrap();
        let pin = proxy.fingerprint();
        tokio::spawn(async move {
            let _ = proxy.serve().await;
        });

        let mesh = MasqueMeshTransport::new(proxy_addr, "127.0.0.1", vec![pin]);
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
        let impostor = MasqueProxy::bind("127.0.0.1:0".parse().unwrap())
            .unwrap()
            .with_target_policy(loopback_only());
        let impostor_addr = impostor.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = impostor.serve().await;
        });
        let res = MasqueTransport::connect(
            "127.0.0.1:0".parse().unwrap(),
            impostor_addr,
            "127.0.0.1",
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
