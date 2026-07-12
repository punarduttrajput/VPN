//! DERP-style packet relay, keyed by public key (PRD Phase 4, milestone M3).
//!
//! When two peers can't establish a direct path (symmetric NATs, hostile
//! firewalls), they fall back to a shared **relay**: both connect *out* to a
//! public relay server and it forwards packets between them. Unlike the MASQUE
//! proxy — which relays to a peer's UDP *address* (so the sender must know it) —
//! this relay is keyed by the peer's **WireGuard public key**. A node says only
//! "deliver this to public key X"; it never needs X's address. That is what lets
//! the relay connect two peers that are each unreachable by address.
//!
//! Wire protocol (one UDP datagram per frame), deliberately tiny:
//!   * **Register** — `0x01 || self_pubkey(32)`: a client tells the relay "I am
//!     this key, reachable at the source address you see." Sent on connect and
//!     periodically (a NAT-keepalive; also re-binds the mapping if the client
//!     roams). The relay records `key -> addr` and `addr -> key`.
//!   * **Data** — `0x02 || key(32) || payload`: client→relay, `key` is the
//!     *destination*; relay→client, `key` is the *source*. The relay looks up the
//!     sender's key by its source address, finds the destination's address by its
//!     key, and forwards `0x02 || src_key || payload`.
//!
//! The relay never sees plaintext: `payload` is an opaque WireGuard datagram, so
//! the relay is an untrusted forwarder (it learns who talks to whom and when, but
//! not what). On the receiving node the inbound payload is routed by the mesh's
//! crypto-demux (which session decrypts it), exactly like a direct datagram —
//! so [`RelayMeshTransport`] plugs into [`run_mesh`](../../ferrum_tunnel) with no
//! changes to the data-plane loop.
//!
//! Dependency-free (std + tokio UDP), mirroring the in-tree STUN client and OIDC
//! verifier rather than pulling a full relay stack.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::{MeshTransport, TransportError};

/// A peer's 32-byte WireGuard public key — the relay's routing key.
pub type PublicKey = [u8; 32];

/// Length of a public key on the wire.
const KEY_LEN: usize = 32;
/// Frame tag: a client announcing its own key (and, implicitly, its address).
const TAG_REGISTER: u8 = 0x01;
/// Frame tag: a data frame carrying a destination (out) or source (in) key.
const TAG_DATA: u8 = 0x02;
/// Data-frame header: tag + key, before the opaque payload.
const DATA_HEADER: usize = 1 + KEY_LEN;
/// Receive buffer: a data header plus a full WireGuard datagram. Matches the
/// tunnel's `MAX_PACKET` (65535 + overhead) so a relayed datagram is never
/// truncated.
const FRAME_BUF: usize = DATA_HEADER + 65_600;
/// How often a connected client re-announces itself, to keep its NAT mapping
/// (and the relay's `addr -> key` record) fresh.
const KEEPALIVE: Duration = Duration::from_secs(25);

/// Build a register frame announcing `key`.
fn register_frame(key: &PublicKey) -> Vec<u8> {
    let mut f = Vec::with_capacity(1 + KEY_LEN);
    f.push(TAG_REGISTER);
    f.extend_from_slice(key);
    f
}

/// Build a data frame: tag, the routing `key`, then `payload`.
fn data_frame(key: &PublicKey, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(DATA_HEADER + payload.len());
    f.push(TAG_DATA);
    f.extend_from_slice(key);
    f.extend_from_slice(payload);
    f
}

/// Privacy-preserving relay metrics (PRD Phase 6, FR4 / NFR5).
///
/// Aggregate counts only — **no labels carrying public keys, addresses, or any
/// per-client/flow identity** (the relay knows who-talks-to-whom, but that never
/// leaves it as a metric). Rendered in the Prometheus text exposition format by
/// the `ferrum relay --metrics-listen` endpoint, mirroring the coordinator's
/// hand-rolled, dependency-free approach.
#[derive(Default)]
pub struct RelayMetrics {
    registers_total: AtomicU64,
    frames_forwarded_total: AtomicU64,
    bytes_forwarded_total: AtomicU64,
    frames_dropped_total: AtomicU64,
    clients_registered: AtomicU64,
    /// Cumulative fast-pathed frames/bytes (PRD `phase-6-ebpf-xdp-relay.md`
    /// FR4) — set (not added to) by the XDP loader from its own already-
    /// cumulative kernel counters, so a missed poll never double-counts.
    /// Separate metric names rather than a label on the two counters above,
    /// deliberately: those two already have an exact-match test
    /// (`relay_metrics_render_in_prometheus_format`) and, in production,
    /// potentially dashboards depending on their unlabeled shape.
    xdp_frames_forwarded_total: AtomicU64,
    xdp_bytes_forwarded_total: AtomicU64,
    /// 1 while the relay is draining (PRD `phase-6-anycast-autoscaling.md`
    /// FR2), else 0.
    draining: AtomicU64,
    /// Register frames refused because they arrived from an unknown key while
    /// draining.
    registers_refused_total: AtomicU64,
}

impl RelayMetrics {
    /// A register frame was processed; `client_count` is the live `key -> addr`
    /// table size right after it (the current gauge value).
    fn note_register(&self, client_count: usize) {
        self.registers_total.fetch_add(1, Ordering::Relaxed);
        self.clients_registered
            .store(client_count as u64, Ordering::Relaxed);
    }

    /// A data frame of `payload_len` bytes was forwarded to its destination.
    fn note_forwarded(&self, payload_len: usize) {
        self.frames_forwarded_total.fetch_add(1, Ordering::Relaxed);
        self.bytes_forwarded_total
            .fetch_add(payload_len as u64, Ordering::Relaxed);
    }

    /// A frame was dropped (unknown sender/destination, malformed, or a failed
    /// forward).
    fn note_dropped(&self) {
        self.frames_dropped_total.fetch_add(1, Ordering::Relaxed);
    }

    /// The relay entered (or left) the draining state.
    fn set_draining(&self, draining: bool) {
        self.draining.store(draining as u64, Ordering::Relaxed);
    }

    /// A register frame from an unknown key was refused while draining.
    fn note_register_refused(&self) {
        self.registers_refused_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Publish the XDP fast path's current cumulative totals (PRD FR4) — the
    /// loader calls this after summing the eBPF program's per-CPU counters,
    /// passing the running totals it read, not a delta.
    pub fn set_xdp_totals(&self, frames: u64, bytes: u64) {
        self.xdp_frames_forwarded_total
            .store(frames, Ordering::Relaxed);
        self.xdp_bytes_forwarded_total
            .store(bytes, Ordering::Relaxed);
    }

    /// Render all relay metrics in the Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(512);
        gauge(
            &mut out,
            "ferrum_relay_clients_registered",
            "Relay clients currently in the key->addr table.",
            self.clients_registered.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_relay_registers_total",
            "Total register frames processed.",
            self.registers_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_relay_frames_forwarded_total",
            "Total data frames forwarded to a destination.",
            self.frames_forwarded_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_relay_bytes_forwarded_total",
            "Total payload bytes forwarded (opaque WireGuard datagrams).",
            self.bytes_forwarded_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_relay_frames_dropped_total",
            "Total frames dropped (unknown sender/destination, malformed, or failed forward).",
            self.frames_dropped_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_relay_xdp_frames_forwarded_total",
            "Total data frames forwarded entirely in-kernel by the XDP fast path (0 if not enabled).",
            self.xdp_frames_forwarded_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_relay_xdp_bytes_forwarded_total",
            "Total payload bytes forwarded entirely in-kernel by the XDP fast path (0 if not enabled).",
            self.xdp_bytes_forwarded_total.load(Ordering::Relaxed),
        );
        gauge(
            &mut out,
            "ferrum_relay_draining",
            "1 while the relay is draining (refusing new clients before shutdown), else 0.",
            self.draining.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_relay_registers_refused_total",
            "Total register frames refused from unknown keys while draining.",
            self.registers_refused_total.load(Ordering::Relaxed),
        );
        out
    }
}

/// Append one `gauge`-typed metric (HELP + TYPE + value) to the exposition text.
fn gauge(out: &mut String, name: &str, help: &str, value: u64) {
    emit(out, name, help, "gauge", value);
}

/// Append one `counter`-typed metric to the exposition text.
fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    emit(out, name, help, "counter", value);
}

fn emit(out: &mut String, name: &str, help: &str, typ: &str, value: u64) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} {typ}\n{name} {value}\n"
    ));
}

/// What changed in the `Clients` table as a result of one `register` call —
/// enough for an observer (the eBPF fast path's userspace loader; PRD
/// `phase-6-ebpf-xdp-relay.md` FR3) to mirror the update *and* clean up
/// whatever it had cached for a stale mapping, without needing to see the
/// whole table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RegisterDelta {
    key: PublicKey,
    addr: SocketAddr,
    /// This key's previous address, if it just roamed (now stale).
    evicted_addr: Option<SocketAddr>,
    /// This address's previous key, if it was just reassigned (now stale).
    evicted_key: Option<PublicKey>,
}

/// An observer notified of every successful registration, so a fast-path
/// implementation can mirror `RelayServer`'s state without ever becoming a
/// second source of truth for it (PRD FR3: userspace stays authoritative).
///
/// The default relay (no hook attached) behaves exactly as before this
/// existed — see [`RelayServer::set_xdp_hook`].
pub trait RelayXdpHook: Send + Sync {
    /// Called with the fully up-to-date `(key, addr)` pairing plus whatever
    /// mapping it just made stale, immediately after `RelayServer` commits a
    /// `Register` frame to its own table.
    fn on_register(
        &self,
        key: PublicKey,
        addr: SocketAddr,
        evicted_addr: Option<SocketAddr>,
        evicted_key: Option<PublicKey>,
    );
}

/// The relay server: a public-key-keyed UDP packet forwarder.
///
/// Bind it on a reachable address, then drive [`serve`](RelayServer::serve).
/// It keeps no persistent state beyond the live `key <-> addr` table, so a
/// restart simply re-learns clients from their next register/keepalive.
pub struct RelayServer {
    socket: UdpSocket,
    clients: Mutex<Clients>,
    metrics: Arc<RelayMetrics>,
    xdp_hook: Mutex<Option<Arc<dyn RelayXdpHook>>>,
    /// Set by [`begin_drain`](Self::begin_drain): refuse registrations from
    /// unknown keys while continuing to serve existing clients (PRD
    /// `phase-6-anycast-autoscaling.md` FR2).
    draining: AtomicBool,
}

/// The relay's bidirectional `key <-> addr` table.
#[derive(Default)]
struct Clients {
    by_key: HashMap<PublicKey, SocketAddr>,
    by_addr: HashMap<SocketAddr, PublicKey>,
}

impl Clients {
    /// Record `key` as reachable at `addr`, clearing any stale mappings for
    /// either side (a client that roamed to a new address, or an address reused
    /// by a different key), and reporting exactly what was cleared.
    fn register(&mut self, key: PublicKey, addr: SocketAddr) -> RegisterDelta {
        let mut evicted_addr = None;
        let mut evicted_key = None;
        if let Some(old_addr) = self.by_key.insert(key, addr) {
            if old_addr != addr {
                self.by_addr.remove(&old_addr);
                evicted_addr = Some(old_addr);
            }
        }
        if let Some(old_key) = self.by_addr.insert(addr, key) {
            if old_key != key {
                self.by_key.remove(&old_key);
                evicted_key = Some(old_key);
            }
        }
        RegisterDelta {
            key,
            addr,
            evicted_addr,
            evicted_key,
        }
    }
}

impl RelayServer {
    /// Bind the relay on `local`.
    pub async fn bind(local: SocketAddr) -> Result<Self, TransportError> {
        Ok(Self {
            socket: UdpSocket::bind(local).await?,
            clients: Mutex::new(Clients::default()),
            metrics: Arc::new(RelayMetrics::default()),
            xdp_hook: Mutex::new(None),
            draining: AtomicBool::new(false),
        })
    }

    /// The address the relay is listening on (useful when bound to port 0).
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.socket.local_addr()?)
    }

    /// A handle to this relay's metrics, for a `/metrics` exporter to render
    /// (PRD Phase 6 FR4). Clone it before moving the server into its serve loop.
    pub fn metrics(&self) -> Arc<RelayMetrics> {
        self.metrics.clone()
    }

    /// Attach an eBPF/XDP fast-path observer (PRD `phase-6-ebpf-xdp-relay.md`)
    /// — call before [`serve`](Self::serve). Every future registration also
    /// notifies `hook`; nothing about the existing forwarding/drop/metrics
    /// behavior changes, on this or any other path. Only one hook can be
    /// attached at a time (a second call replaces the first).
    pub fn set_xdp_hook(&self, hook: Arc<dyn RelayXdpHook>) {
        *self.xdp_hook.lock().expect("relay xdp hook poisoned") = Some(hook);
    }

    /// Enter the draining state (PRD `phase-6-anycast-autoscaling.md` FR2) —
    /// call on the shutdown signal, ahead of actually stopping [`serve`](Self::serve).
    ///
    /// While draining the relay refuses register frames from **unknown** keys
    /// (so no new client can land on a relay that's going away — and, because
    /// the XDP fast path only learns flows through an *accepted* registration,
    /// the refusal starves both paths identically), but keeps honoring
    /// keepalive re-registrations from already-registered keys — including
    /// roams to a new address — and keeps forwarding their data frames, so
    /// existing sessions ride out the drain window undisturbed. A readiness
    /// probe (`/readyz`) should report 503 from this point on.
    pub fn begin_drain(&self) {
        self.draining.store(true, Ordering::Relaxed);
        self.metrics.set_draining(true);
    }

    /// Whether [`begin_drain`](Self::begin_drain) has been called — the
    /// readiness signal for a `/readyz` endpoint.
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// Forward frames until the socket errors. Register frames update the table;
    /// data frames are forwarded to the destination key's current address,
    /// rewritten to carry the *source* key. Unknown senders or destinations are
    /// dropped (a client must register before it can be reached).
    // One span for the serve loop's lifetime (cheap — not per frame); the
    // per-frame debug events nest under it. `skip_all`: no addresses/keys/payloads
    // enter the span (NFR5).
    #[tracing::instrument(skip_all, name = "relay_serve")]
    pub async fn serve(&self) -> Result<(), TransportError> {
        let mut buf = vec![0u8; FRAME_BUF];
        loop {
            let (n, from) = self.socket.recv_from(&mut buf).await?;
            let frame = &buf[..n];
            match frame.first() {
                Some(&TAG_REGISTER) if n == 1 + KEY_LEN => {
                    let mut key = [0u8; KEY_LEN];
                    key.copy_from_slice(&frame[1..1 + KEY_LEN]);
                    let draining = self.is_draining();
                    let (delta, count) = {
                        let mut clients = self.clients.lock().expect("relay table poisoned");
                        // Draining: only known keys may (re-)register — their
                        // keepalives and roams stay honored so existing
                        // sessions survive; new clients must go elsewhere.
                        if draining && !clients.by_key.contains_key(&key) {
                            self.metrics.note_register_refused();
                            debug!(%from, "relay draining: refusing unknown client");
                            continue;
                        }
                        let delta = clients.register(key, from);
                        (delta, clients.by_key.len())
                    };
                    self.metrics.note_register(count);
                    if let Some(hook) = self
                        .xdp_hook
                        .lock()
                        .expect("relay xdp hook poisoned")
                        .as_ref()
                    {
                        hook.on_register(
                            delta.key,
                            delta.addr,
                            delta.evicted_addr,
                            delta.evicted_key,
                        );
                    }
                    debug!(%from, "relay client registered");
                }
                Some(&TAG_DATA) if n >= DATA_HEADER => {
                    let mut dst_key = [0u8; KEY_LEN];
                    dst_key.copy_from_slice(&frame[1..1 + KEY_LEN]);
                    let (src_key, dst_addr) = {
                        let clients = self.clients.lock().expect("relay table poisoned");
                        // The sender must be registered, so we know whose packet
                        // this is; the destination must be registered to receive.
                        match (clients.by_addr.get(&from), clients.by_key.get(&dst_key)) {
                            (Some(src), Some(dst)) => (*src, *dst),
                            _ => {
                                self.metrics.note_dropped();
                                debug!(%from, "relay: unknown sender or destination; dropping");
                                continue;
                            }
                        }
                    };
                    let payload = &frame[DATA_HEADER..];
                    let out = data_frame(&src_key, payload);
                    match self.socket.send_to(&out, dst_addr).await {
                        Ok(_) => self.metrics.note_forwarded(payload.len()),
                        Err(e) => {
                            self.metrics.note_dropped();
                            warn!(%dst_addr, "relay forward failed: {e}");
                        }
                    }
                }
                _ => {
                    self.metrics.note_dropped();
                    debug!(%from, len = n, "relay: malformed frame; dropping");
                }
            }
        }
    }
}

/// A [`MeshTransport`] that carries the mesh over a [`RelayServer`], addressing
/// peers by public key.
///
/// The mesh loop still addresses peers by [`SocketAddr`] (`peer.endpoint`); this
/// transport maps each peer's endpoint to its public key for the relay framing,
/// and maps an inbound frame's source key back to that same endpoint so the
/// mesh's crypto-demux and endpoint-roaming behave exactly as over UDP. The
/// endpoint is just a stable handle here — it need not be routable, since all
/// traffic goes to the relay.
pub struct RelayMeshTransport {
    socket: Arc<UdpSocket>,
    relay: SocketAddr,
    peers: Arc<Mutex<PeerMap>>,
    keepalive: tokio::task::JoinHandle<()>,
}

/// This node's view of its mesh peers, for translating between the mesh's
/// per-peer [`SocketAddr`] handle and the relay's public-key addressing.
#[derive(Default)]
struct PeerMap {
    /// `endpoint handle -> peer key` (for `send_to`).
    key_of_addr: HashMap<SocketAddr, PublicKey>,
    /// `peer key -> endpoint handle` (for `recv_from`).
    addr_of_key: HashMap<PublicKey, SocketAddr>,
}

impl RelayMeshTransport {
    /// Connect to the relay at `relay` as `self_key`, knowing `peers` as a list
    /// of `(endpoint handle, peer public key)`.
    ///
    /// Sends an initial register frame and spawns a keepalive task that
    /// re-announces this node every [`KEEPALIVE`] (so its relay mapping survives
    /// NAT timeouts). The keepalive is aborted when the transport is dropped.
    pub async fn connect(
        relay: SocketAddr,
        self_key: PublicKey,
        peers: &[(SocketAddr, PublicKey)],
    ) -> Result<Self, TransportError> {
        let bind: SocketAddr = match relay {
            SocketAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = Arc::new(UdpSocket::bind(bind).await?);

        let mut map = PeerMap::default();
        for (addr, key) in peers {
            map.key_of_addr.insert(*addr, *key);
            map.addr_of_key.insert(*key, *addr);
        }

        // Announce ourselves so peers can be told to reach us by key.
        socket.send_to(&register_frame(&self_key), relay).await?;

        // Keepalive: re-register periodically to refresh the NAT mapping.
        let ka_socket = Arc::clone(&socket);
        let keepalive = tokio::spawn(async move {
            let frame = register_frame(&self_key);
            let mut tick = tokio::time::interval(KEEPALIVE);
            tick.tick().await; // consume the immediate first tick (already sent)
            loop {
                tick.tick().await;
                if let Err(e) = ka_socket.send_to(&frame, relay).await {
                    warn!("relay keepalive failed: {e}");
                }
            }
        });

        Ok(Self {
            socket,
            relay,
            peers: Arc::new(Mutex::new(map)),
            keepalive,
        })
    }

    /// Replace the known peer set (e.g. on a live network-map update).
    pub fn set_peers(&self, peers: &[(SocketAddr, PublicKey)]) {
        let mut map = self.peers.lock().expect("relay peer map poisoned");
        map.key_of_addr.clear();
        map.addr_of_key.clear();
        for (addr, key) in peers {
            map.key_of_addr.insert(*addr, *key);
            map.addr_of_key.insert(*key, *addr);
        }
    }
}

impl Drop for RelayMeshTransport {
    fn drop(&mut self) {
        self.keepalive.abort();
    }
}

impl MeshTransport for RelayMeshTransport {
    async fn send_to(&self, dst: SocketAddr, datagram: &[u8]) -> Result<(), TransportError> {
        let dst_key = self
            .peers
            .lock()
            .expect("relay peer map poisoned")
            .key_of_addr
            .get(&dst)
            .copied();
        match dst_key {
            // Frame for the relay: "deliver this to <dst_key>".
            Some(key) => {
                self.socket
                    .send_to(&data_frame(&key, datagram), self.relay)
                    .await?;
                Ok(())
            }
            // No key for this handle (e.g. a stray probe to an address that isn't
            // a relayed peer). Drop rather than erroring out the mesh loop.
            None => {
                debug!(%dst, "relay: no peer key for destination handle; dropping");
                Ok(())
            }
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), TransportError> {
        let mut frame = vec![0u8; FRAME_BUF];
        loop {
            let (n, from) = self.socket.recv_from(&mut frame).await?;
            if from != self.relay {
                continue; // only the relay should be talking to us
            }
            if frame.first() != Some(&TAG_DATA) || n < DATA_HEADER {
                continue; // not a data frame
            }
            let mut src_key = [0u8; KEY_LEN];
            src_key.copy_from_slice(&frame[1..1 + KEY_LEN]);
            // Report the inbound packet as coming from this peer's endpoint
            // handle, so crypto-demux + roaming match the direct-UDP path.
            let src_addr = self
                .peers
                .lock()
                .expect("relay peer map poisoned")
                .addr_of_key
                .get(&src_key)
                .copied();
            let Some(src_addr) = src_addr else {
                debug!("relay: inbound from unknown peer key; dropping");
                continue;
            };
            let payload = &frame[DATA_HEADER..n];
            if payload.len() > buf.len() {
                warn!(
                    len = payload.len(),
                    "relay: inbound payload too large; dropping"
                );
                continue;
            }
            buf[..payload.len()].copy_from_slice(payload);
            return Ok((payload.len(), src_addr));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> PublicKey {
        [b; KEY_LEN]
    }

    /// Spawn a relay server on loopback and return its address + metrics handle.
    async fn start_relay() -> (SocketAddr, Arc<RelayMetrics>) {
        let server = Arc::new(
            RelayServer::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        );
        let addr = server.local_addr().unwrap();
        let metrics = server.metrics();
        tokio::spawn(async move {
            let _ = server.serve().await;
        });
        (addr, metrics)
    }

    #[test]
    fn relay_metrics_render_in_prometheus_format() {
        let m = RelayMetrics::default();
        m.note_register(1);
        m.note_register(2);
        m.note_forwarded(100);
        m.note_dropped();
        let t = m.render();
        assert!(t.contains("# TYPE ferrum_relay_clients_registered gauge"));
        assert!(t.contains("ferrum_relay_clients_registered 2\n"));
        assert!(t.contains("# TYPE ferrum_relay_registers_total counter"));
        assert!(t.contains("ferrum_relay_registers_total 2\n"));
        assert!(t.contains("ferrum_relay_frames_forwarded_total 1\n"));
        assert!(t.contains("ferrum_relay_bytes_forwarded_total 100\n"));
        assert!(t.contains("ferrum_relay_frames_dropped_total 1\n"));
        // XDP totals default to zero when the fast path isn't enabled.
        assert!(t.contains("ferrum_relay_xdp_frames_forwarded_total 0\n"));
        assert!(t.contains("ferrum_relay_xdp_bytes_forwarded_total 0\n"));
        // Drain metrics default to "not draining, nothing refused".
        assert!(t.contains("# TYPE ferrum_relay_draining gauge"));
        assert!(t.contains("ferrum_relay_draining 0\n"));
        assert!(t.contains("ferrum_relay_registers_refused_total 0\n"));
    }

    #[test]
    fn xdp_totals_are_set_not_accumulated() {
        let m = RelayMetrics::default();
        m.set_xdp_totals(10, 2000);
        m.set_xdp_totals(15, 3200); // a later poll's cumulative totals
        let t = m.render();
        assert!(t.contains("ferrum_relay_xdp_frames_forwarded_total 15\n"));
        assert!(t.contains("ferrum_relay_xdp_bytes_forwarded_total 3200\n"));
    }

    #[test]
    fn register_clears_stale_mappings_on_roam() {
        let mut c = Clients::default();
        let a1: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let a2: SocketAddr = "127.0.0.1:2".parse().unwrap();
        c.register(key(1), a1);
        c.register(key(1), a2); // same key, new address (roamed)
        assert_eq!(c.by_key.get(&key(1)), Some(&a2));
        assert!(!c.by_addr.contains_key(&a1), "stale address dropped");
        assert_eq!(c.by_addr.get(&a2), Some(&key(1)));
    }

    /// The delta a fast-path observer relies on (PRD FR3) reports exactly
    /// what became stale — nothing on a first registration, the old address
    /// on a roam, the old key when an address is reassigned.
    #[test]
    fn register_delta_reports_evicted_mappings() {
        let mut c = Clients::default();
        let a1: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let a2: SocketAddr = "127.0.0.1:2".parse().unwrap();

        let first = c.register(key(1), a1);
        assert_eq!(first.evicted_addr, None);
        assert_eq!(first.evicted_key, None);

        let roamed = c.register(key(1), a2); // same key, new address
        assert_eq!(roamed.evicted_addr, Some(a1));
        assert_eq!(roamed.evicted_key, None);

        let reassigned = c.register(key(2), a1); // a1 now claimed by a new key
        assert_eq!(reassigned.evicted_addr, None);
        assert_eq!(reassigned.evicted_key, None); // a1 had no key registered anymore
    }

    /// A registered `RelayXdpHook` (the eBPF fast path's userspace loader, in
    /// production) is notified on every `Register` frame the server handles,
    /// with the same eviction info `Clients::register` computed — proving the
    /// wiring in `serve()` without needing any BPF/aya machinery at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn xdp_hook_is_notified_on_register() {
        type Call = (PublicKey, SocketAddr, Option<SocketAddr>, Option<PublicKey>);

        #[derive(Default)]
        struct RecordingHook {
            calls: Mutex<Vec<Call>>,
        }
        impl RelayXdpHook for RecordingHook {
            fn on_register(
                &self,
                key: PublicKey,
                addr: SocketAddr,
                evicted_addr: Option<SocketAddr>,
                evicted_key: Option<PublicKey>,
            ) {
                self.calls
                    .lock()
                    .unwrap()
                    .push((key, addr, evicted_addr, evicted_key));
            }
        }

        let server = Arc::new(
            RelayServer::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        );
        let addr = server.local_addr().unwrap();
        let hook = Arc::new(RecordingHook::default());
        server.set_xdp_hook(hook.clone());
        tokio::spawn({
            let server = server.clone();
            async move {
                let _ = server.serve().await;
            }
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&register_frame(&key(0x42)), addr)
            .await
            .unwrap();

        // Poll briefly rather than a fixed sleep — the frame is local UDP
        // and should land almost immediately.
        for _ in 0..50 {
            if !hook.calls.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let calls = hook.calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "hook should fire exactly once");
        let (seen_key, seen_addr, evicted_addr, evicted_key) = calls[0];
        assert_eq!(seen_key, key(0x42));
        assert_eq!(seen_addr, client.local_addr().unwrap());
        assert_eq!(evicted_addr, None);
        assert_eq!(evicted_key, None);
    }

    /// Two clients registered with the relay exchange an opaque payload addressed
    /// purely by public key; the receiver sees it tagged with the sender's key
    /// (reported as that peer's endpoint handle).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relays_payload_between_two_clients_by_key() {
        let (relay, metrics) = start_relay().await;
        let (ka, kb) = (key(0xAA), key(0xBB));
        // Endpoint handles the mesh would use for each peer (need not be routable).
        let handle_b: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        let handle_a: SocketAddr = "127.0.0.1:9001".parse().unwrap();

        let a = RelayMeshTransport::connect(relay, ka, &[(handle_b, kb)])
            .await
            .unwrap();
        let b = RelayMeshTransport::connect(relay, kb, &[(handle_a, ka)])
            .await
            .unwrap();

        // Let both registrations land at the relay.
        tokio::time::sleep(Duration::from_millis(100)).await;

        a.send_to(handle_b, b"ping through the relay")
            .await
            .unwrap();

        let mut buf = [0u8; 128];
        let (n, src) = tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut buf))
            .await
            .expect("relay did not deliver in time")
            .unwrap();
        assert_eq!(&buf[..n], b"ping through the relay");
        // B sees the packet as coming from A's endpoint handle.
        assert_eq!(src, handle_a);

        // Metrics reflect the exchange: both clients registered, one frame (of
        // the payload's length) forwarded, none dropped.
        let text = metrics.render();
        assert!(
            text.contains("ferrum_relay_clients_registered 2\n"),
            "{text}"
        );
        assert!(
            text.contains("ferrum_relay_frames_forwarded_total 1\n"),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "ferrum_relay_bytes_forwarded_total {}\n",
                b"ping through the relay".len()
            )),
            "{text}"
        );
        assert!(
            text.contains("ferrum_relay_frames_dropped_total 0\n"),
            "{text}"
        );
    }

    /// Draining (PRD `phase-6-anycast-autoscaling.md` FR2): a draining relay
    /// refuses register frames from unknown keys but keeps honoring existing
    /// clients' keepalives (including roams) and keeps forwarding their data.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_refuses_new_clients_but_serves_existing() {
        let server = Arc::new(
            RelayServer::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        );
        let relay = server.local_addr().unwrap();
        let metrics = server.metrics();
        tokio::spawn({
            let server = server.clone();
            async move {
                let _ = server.serve().await;
            }
        });

        // Two clients register before the drain starts.
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        a.send_to(&register_frame(&key(1)), relay).await.unwrap();
        b.send_to(&register_frame(&key(2)), relay).await.unwrap();
        for _ in 0..50 {
            if metrics
                .render()
                .contains("ferrum_relay_clients_registered 2\n")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert!(!server.is_draining());
        server.begin_drain();
        assert!(server.is_draining());
        assert!(metrics.render().contains("ferrum_relay_draining 1\n"));

        // A new client's registration is refused: the table stays at 2.
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        c.send_to(&register_frame(&key(3)), relay).await.unwrap();
        for _ in 0..50 {
            if metrics
                .render()
                .contains("ferrum_relay_registers_refused_total 1\n")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let t = metrics.render();
        assert!(
            t.contains("ferrum_relay_registers_refused_total 1\n"),
            "{t}"
        );
        assert!(t.contains("ferrum_relay_clients_registered 2\n"), "{t}");

        // An existing client's keepalive re-registration is still honored,
        // even from a new source address (a mid-drain roam).
        let a2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        a2.send_to(&register_frame(&key(1)), relay).await.unwrap();
        for _ in 0..50 {
            if metrics
                .render()
                .contains("ferrum_relay_registers_total 3\n")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let t = metrics.render();
        assert!(t.contains("ferrum_relay_registers_total 3\n"), "{t}");
        assert!(
            t.contains("ferrum_relay_registers_refused_total 1\n"),
            "{t}"
        );

        // Existing clients' data still forwards: A (from its roamed socket)
        // reaches B mid-drain.
        a2.send_to(&data_frame(&key(2), b"still flowing"), relay)
            .await
            .unwrap();
        let mut buf = [0u8; 128];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut buf))
            .await
            .expect("draining relay did not forward for an existing client")
            .unwrap();
        assert_eq!(&buf[..n], &data_frame(&key(1), b"still flowing")[..]);
    }

    /// A data frame for an unregistered destination key is dropped (no panic, no
    /// delivery), and the sender's own loop is unaffected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drops_data_for_unknown_destination() {
        let (relay, _metrics) = start_relay().await;
        let ka = key(0x01);
        let handle_ghost: SocketAddr = "127.0.0.1:9009".parse().unwrap();
        let a = RelayMeshTransport::connect(relay, ka, &[(handle_ghost, key(0x99))])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Destination key 0x99 never registered: the relay drops it. We just
        // assert the send path doesn't error.
        a.send_to(handle_ghost, b"into the void").await.unwrap();
    }
}
