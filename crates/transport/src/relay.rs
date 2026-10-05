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
//!   * **Register** — `0x01 || self_pubkey(32) || reserved(32)`: a client tells
//!     the relay "I am this key, reachable at the source address you see." Sent
//!     on connect and periodically as a NAT keepalive. If that exact
//!     `key -> addr` mapping is already live it's just refreshed; otherwise
//!     (a new client, a roam, or a relay restart) the relay answers with a
//!     challenge and changes nothing yet. The zero-filled `reserved` tail keeps
//!     the frame larger than the challenge it can trigger, so a spoofed register
//!     can never be reflected at a victim with amplification.
//!   * **Challenge** — `0x03 || relay_x25519_pub(32) || cookie(16)`, relay→client.
//!   * **Response** — `0x04 || self_pubkey(32) || cookie(16) || proof(16)`,
//!     client→relay from the same source: the echoed cookie proves return
//!     routability, the proof proves possession of the key's private half. Only
//!     then does the relay record `key -> addr` and `addr -> key`. See
//!     `relay_auth.rs` (PRD `security-hardening.md` FR3 / SEC-003) for the
//!     construction and the rate limits.
//!   * **Data** — `0x02 || key(32) || payload`: client→relay, `key` is the
//!     *destination*; relay→client, `key` is the *source*. The relay looks up the
//!     sender's key by its source address, finds the destination's address by its
//!     key, and forwards `0x02 || src_key || payload`. Data is the only frame the
//!     XDP fast path touches; every control frame falls through to userspace.
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
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tracing::{debug, warn};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use crate::relay_auth::{self, RateLimiter, RegisterAuth, COOKIE_LEN, PROOF_LEN};
use crate::{MeshTransport, TransportError};

/// A peer's 32-byte WireGuard public key — the relay's routing key.
pub type PublicKey = [u8; 32];

/// Length of a public key on the wire.
const KEY_LEN: usize = 32;
/// Frame tag: a client announcing its own key (and, implicitly, its address).
const TAG_REGISTER: u8 = 0x01;
/// Frame tag: a data frame carrying a destination (out) or source (in) key.
const TAG_DATA: u8 = 0x02;
/// Frame tag: the relay's register challenge (relay→client).
const TAG_CHALLENGE: u8 = 0x03;
/// Frame tag: a client's answer to a challenge (client→relay).
const TAG_RESPONSE: u8 = 0x04;
/// Register frame: tag + key + zero-filled reserved tail (see the module doc).
const REGISTER_LEN: usize = 1 + KEY_LEN + 32;
/// Challenge frame: tag + relay X25519 public key + cookie.
const CHALLENGE_LEN: usize = 1 + KEY_LEN + COOKIE_LEN;
/// Response frame: tag + key + cookie + proof.
const RESPONSE_LEN: usize = 1 + KEY_LEN + COOKIE_LEN + PROOF_LEN;
// A challenge must never be larger than the register that elicits it.
const _: () = assert!(CHALLENGE_LEN <= REGISTER_LEN);

/// Per-source-IP budget for challenges issued + proofs checked: a burst of 32,
/// refilling at 8/s. Sized for many clients behind one CGNAT address all
/// re-registering after a relay restart (they retry on their next keepalive).
const IP_BURST: u32 = 32;
const IP_REFILL_PER_SEC: f64 = 8.0;
/// Per-key budget for committed mapping *changes* (first claim or roam): a
/// burst of 10, then one per second. Only the key holder can commit (the
/// proof), so this bounds a flapping client's churn — including XDP map
/// updates — without letting third parties exhaust a victim's budget. Roomy
/// on purpose: a phone bouncing between Wi-Fi and cellular re-registers on
/// every NAT rebind, and a throttled roam leaves its relayed traffic going to
/// a dead address until the next keepalive.
const KEY_BURST: u32 = 10;
const KEY_REFILL_PER_SEC: f64 = 1.0;
/// Bucket-table bound for each limiter (see `RateLimiter`).
const MAX_TRACKED: usize = 65_536;
/// Data-frame header: tag + key, before the opaque payload.
const DATA_HEADER: usize = 1 + KEY_LEN;
/// Receive buffer: a data header plus a full WireGuard datagram. Matches the
/// tunnel's `MAX_PACKET` (65535 + overhead) so a relayed datagram is never
/// truncated.
const FRAME_BUF: usize = DATA_HEADER + 65_600;
/// How often a connected client re-announces itself, to keep its NAT mapping
/// (and the relay's `addr -> key` record) fresh.
const KEEPALIVE: Duration = Duration::from_secs(25);
/// How long [`RelayMeshTransport::connect`] waits for the register challenge —
/// a relay RTT is far below this; past it the challenge is answered on receive.
pub const CONNECT_HANDSHAKE: Duration = Duration::from_millis(500);

/// Build a register frame announcing `key` (reserved tail zero-filled).
fn register_frame(key: &PublicKey) -> Vec<u8> {
    let mut f = vec![0u8; REGISTER_LEN];
    f[0] = TAG_REGISTER;
    f[1..1 + KEY_LEN].copy_from_slice(key);
    f
}

/// Build a challenge frame carrying the relay's X25519 key and a cookie.
fn challenge_frame(relay_pub: &[u8; 32], cookie: &[u8; COOKIE_LEN]) -> Vec<u8> {
    let mut f = Vec::with_capacity(CHALLENGE_LEN);
    f.push(TAG_CHALLENGE);
    f.extend_from_slice(relay_pub);
    f.extend_from_slice(cookie);
    f
}

/// The response to a challenge frame, proving we hold `secret` — or `None` if
/// `frame` isn't a well-formed challenge (or names a low-order relay key).
pub(crate) fn answer_challenge(secret: &StaticSecret, frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() != CHALLENGE_LEN || frame[0] != TAG_CHALLENGE {
        return None;
    }
    let relay_pub: [u8; 32] = frame[1..1 + KEY_LEN].try_into().ok()?;
    let cookie: [u8; COOKIE_LEN] = frame[1 + KEY_LEN..].try_into().ok()?;
    let (me, proof) = relay_auth::answer(secret, &relay_pub, &cookie)?;
    let mut f = Vec::with_capacity(RESPONSE_LEN);
    f.push(TAG_RESPONSE);
    f.extend_from_slice(&me);
    f.extend_from_slice(&cookie);
    f.extend_from_slice(&proof);
    Some(f)
}

/// Register `secret`'s public key with the relay at `relay` from `socket`,
/// completing the challenge round-trip; `Ok(true)` once the response is sent.
///
/// Receives on `socket`, so only call it while nothing else is — e.g. before
/// handing the socket to a receive loop. ([`RelayMeshTransport::connect`] calls
/// this; a running mesh answers any later challenge from inside `recv_from`.)
/// `Ok(false)` means
/// no challenge arrived within `timeout` (relay down, or the mapping was
/// already live — in which case a register is a silent refresh).
pub async fn register_via(
    socket: &UdpSocket,
    relay: SocketAddr,
    secret: &StaticSecret,
    timeout: Duration,
) -> Result<bool, TransportError> {
    let me = XPublicKey::from(secret).to_bytes();
    socket.send_to(&register_frame(&me), relay).await?;
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = vec![0u8; FRAME_BUF];
    loop {
        let recv = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await;
        let Ok(res) = recv else { return Ok(false) };
        let (n, from) = match res {
            Ok(v) => v,
            // Windows reports an ICMP port-unreachable (relay not listening)
            // on the next receive; that's "no challenge yet", not a failure.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Err(e) => return Err(e.into()),
        };
        if from != relay {
            continue;
        }
        if let Some(resp) = answer_challenge(secret, &buf[..n]) {
            socket.send_to(&resp, relay).await?;
            return Ok(true);
        }
    }
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
    /// Register challenges sent (SEC-003).
    register_challenges_total: AtomicU64,
    /// Register/response frames dropped by the per-IP or per-key rate limits.
    registers_rate_limited_total: AtomicU64,
    /// Responses rejected for a stale/foreign cookie or a bad possession proof.
    register_proofs_rejected_total: AtomicU64,
    /// Malformed *control* frames (wrong-length register/response, unknown
    /// tag) — e.g. a pre-SEC-003 client's 33-byte register during a rolling
    /// upgrade. Kept out of `frames_dropped_total`, the forwarding SLI, so
    /// they can't trip the relay-forwarding SLO alerts.
    control_frames_invalid_total: AtomicU64,
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

    fn note_challenge(&self) {
        self.register_challenges_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn note_rate_limited(&self) {
        self.registers_rate_limited_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn note_proof_rejected(&self) {
        self.register_proofs_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn note_control_invalid(&self) {
        self.control_frames_invalid_total
            .fetch_add(1, Ordering::Relaxed);
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
            "Total registrations accepted (verified new/roamed mappings plus keepalive refreshes).",
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
        counter(
            &mut out,
            "ferrum_relay_register_challenges_total",
            "Total register challenges sent (return-routability + key-possession check).",
            self.register_challenges_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_relay_registers_rate_limited_total",
            "Total register/response frames dropped by the per-IP or per-key rate limits.",
            self.registers_rate_limited_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_relay_register_proofs_rejected_total",
            "Total challenge responses rejected (stale or foreign cookie, or bad key-possession proof).",
            self.register_proofs_rejected_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_relay_control_frames_invalid_total",
            "Total malformed control frames (wrong-length register/response, unknown tag), e.g. from pre-upgrade clients. Not a forwarding drop.",
            self.control_frames_invalid_total.load(Ordering::Relaxed),
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
    /// Register challenge issuer/verifier (SEC-003).
    auth: RegisterAuth,
    limits: Mutex<Limits>,
}

/// The register path's flood limits (SEC-003).
struct Limits {
    per_ip: RateLimiter<IpAddr>,
    per_key: RateLimiter<PublicKey>,
}

/// The relay's decision for an incoming register/response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admit {
    /// This exact `key -> addr` mapping is already live.
    Refresh,
    /// A new client or a roam: must pass the challenge.
    Challenge,
    /// Draining and the key is unknown.
    Refused,
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
            auth: RegisterAuth::new(),
            limits: Mutex::new(Limits {
                per_ip: RateLimiter::new(IP_BURST, IP_REFILL_PER_SEC, MAX_TRACKED),
                per_key: RateLimiter::new(KEY_BURST, KEY_REFILL_PER_SEC, MAX_TRACKED),
            }),
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

    /// How a register/response for `key` from `from` should be treated, given
    /// the live table and the drain state.
    fn admit(&self, key: PublicKey, from: SocketAddr) -> Admit {
        let clients = self.clients.lock().expect("relay table poisoned");
        match clients.by_key.get(&key) {
            Some(addr) if *addr == from => Admit::Refresh,
            // Draining: only known keys may (re-)register — their keepalives
            // and roams stay honored so existing sessions survive; new clients
            // must go elsewhere (and aren't even challenged).
            None if self.is_draining() => {
                self.metrics.note_register_refused();
                debug!(%from, "relay draining: refusing unknown client");
                Admit::Refused
            }
            _ => Admit::Challenge,
        }
    }

    /// Take a token from `from`'s per-IP register budget, counting a refusal.
    fn allow_ip(&self, from: SocketAddr) -> bool {
        let ok = self
            .limits
            .lock()
            .expect("relay limits poisoned")
            .per_ip
            .allow(from.ip(), Instant::now());
        if !ok {
            self.metrics.note_rate_limited();
            debug!(%from, "relay: per-IP register rate limit");
        }
        ok
    }

    /// Record `key -> from` (a verified claim, or a refresh of the live
    /// mapping) and tell the XDP observer.
    fn commit(&self, key: PublicKey, from: SocketAddr) {
        let (delta, count) = {
            let mut clients = self.clients.lock().expect("relay table poisoned");
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
            hook.on_register(delta.key, delta.addr, delta.evicted_addr, delta.evicted_key);
        }
        debug!(%from, "relay client registered");
    }

    /// Forward frames until the socket errors. Register frames refresh a live
    /// mapping or draw a challenge; a verified response updates the table; data
    /// frames are forwarded to the destination key's current address,
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
                Some(&TAG_REGISTER) if n == REGISTER_LEN => {
                    let mut key = [0u8; KEY_LEN];
                    key.copy_from_slice(&frame[1..1 + KEY_LEN]);
                    match self.admit(key, from) {
                        // Keepalive for the live mapping: refresh, no challenge.
                        Admit::Refresh => self.commit(key, from),
                        Admit::Refused => {}
                        Admit::Challenge => {
                            if !self.allow_ip(from) {
                                continue;
                            }
                            let cookie = self.auth.issue(from, &key, Instant::now());
                            let out = challenge_frame(&self.auth.public(), &cookie);
                            match self.socket.send_to(&out, from).await {
                                Ok(_) => self.metrics.note_challenge(),
                                Err(e) => debug!(%from, "relay challenge send failed: {e}"),
                            }
                        }
                    }
                }
                Some(&TAG_RESPONSE) if n == RESPONSE_LEN => {
                    let key: PublicKey = frame[1..1 + KEY_LEN].try_into().expect("sized");
                    let cookie: [u8; COOKIE_LEN] = frame[1 + KEY_LEN..1 + KEY_LEN + COOKIE_LEN]
                        .try_into()
                        .expect("sized");
                    let proof: [u8; PROOF_LEN] =
                        frame[1 + KEY_LEN + COOKIE_LEN..].try_into().expect("sized");
                    let admit = self.admit(key, from);
                    if admit == Admit::Refused || !self.allow_ip(from) {
                        continue;
                    }
                    // Cheap cookie check (return routability) first; only then
                    // spend an X25519 on the possession proof.
                    if !self.auth.check_cookie(from, &key, &cookie, Instant::now())
                        || !self.auth.verify_proof(&key, &cookie, &proof)
                    {
                        self.metrics.note_proof_rejected();
                        debug!(%from, "relay: register proof rejected");
                        continue;
                    }
                    // A verified change of mapping is budgeted per key.
                    if admit == Admit::Challenge
                        && !self
                            .limits
                            .lock()
                            .expect("relay limits poisoned")
                            .per_key
                            .allow(key, Instant::now())
                    {
                        self.metrics.note_rate_limited();
                        debug!(%from, "relay: per-key register rate limit");
                        continue;
                    }
                    self.commit(key, from);
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
                // A short Data frame is a forwarding drop (it was meant to be
                // forwarded); anything else malformed is a control-plane
                // problem and stays out of the forwarding SLI.
                Some(&TAG_DATA) => {
                    self.metrics.note_dropped();
                    debug!(%from, len = n, "relay: truncated data frame; dropping");
                }
                _ => {
                    self.metrics.note_control_invalid();
                    debug!(%from, len = n, "relay: malformed control frame; dropping");
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
    /// This node's WireGuard private key — answers the relay's register
    /// challenges (SEC-003); never leaves the process.
    secret: StaticSecret,
    /// Only answer challenges we could have solicited (see [`ChallengeGate`]).
    gate: Arc<Mutex<ChallengeGate>>,
    /// Reused receive buffer — one full frame, allocated once rather than per
    /// datagram on the relayed data path.
    recv_buf: tokio::sync::Mutex<Vec<u8>>,
    peers: Arc<Mutex<PeerMap>>,
    keepalive: tokio::task::JoinHandle<()>,
}

/// How long after sending a Register the client will answer a challenge.
const ANSWER_WINDOW: Duration = Duration::from_secs(5);
/// How many challenges one Register may draw an answer to (a retransmitted
/// or duplicated challenge is fine; a flood is not).
const MAX_ANSWERS_PER_REGISTER: u32 = 2;

/// Client-side guard on answering register challenges. The relay only ever
/// challenges in reply to one of our Register frames, so a challenge outside
/// [`ANSWER_WINDOW`] of our last Register — or beyond
/// [`MAX_ANSWERS_PER_REGISTER`] of them — is unsolicited: most likely spoofed
/// from the relay's address. Answering those would cost an X25519 each and
/// reflect a Response at the relay, draining our own per-IP register budget
/// there so a genuine re-registration later gets rate-limited.
#[derive(Default)]
struct ChallengeGate {
    last_register: Option<Instant>,
    answered: u32,
}

impl ChallengeGate {
    fn note_register(&mut self, now: Instant) {
        self.last_register = Some(now);
        self.answered = 0;
    }

    fn allow_answer(&mut self, now: Instant) -> bool {
        let fresh = self
            .last_register
            .is_some_and(|t| now.saturating_duration_since(t) <= ANSWER_WINDOW);
        if fresh && self.answered < MAX_ANSWERS_PER_REGISTER {
            self.answered += 1;
            true
        } else {
            false
        }
    }
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
    /// Connect to the relay at `relay` as the holder of `secret` (this node's
    /// WireGuard private key), knowing `peers` as a list of
    /// `(endpoint handle, peer public key)`.
    ///
    /// Registers — completing the relay's challenge round-trip, waiting at most
    /// [`CONNECT_HANDSHAKE`] — and spawns a keepalive task that re-announces this
    /// node every [`KEEPALIVE`] (so its relay mapping survives NAT timeouts). The
    /// keepalive is aborted when the transport is dropped.
    ///
    /// Completing the round-trip here means the mapping is live before the
    /// caller's first send, so a mesh's first WireGuard handshake over the relay
    /// isn't dropped (its retry would only come 5 s later). An unreachable relay
    /// costs that bounded wait, not an error; any later challenge (the relay
    /// restarted, or our NAT mapping changed) is answered from inside
    /// [`recv_from`](MeshTransport::recv_from).
    pub async fn connect(
        relay: SocketAddr,
        secret: &StaticSecret,
        peers: &[(SocketAddr, PublicKey)],
    ) -> Result<Self, TransportError> {
        let self_key = XPublicKey::from(secret).to_bytes();
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

        // Announce ourselves (proving the key) so peers can reach us by key. A
        // challenge that arrives after this bounded wait is answered from
        // `recv_from`, so open the answer window now.
        let gate = Arc::new(Mutex::new(ChallengeGate::default()));
        gate.lock()
            .expect("relay challenge gate poisoned")
            .note_register(Instant::now());
        if !register_via(&socket, relay, secret, CONNECT_HANDSHAKE).await? {
            debug!(%relay, "relay sent no register challenge yet; will answer it on receive");
        }

        // Keepalive: re-register periodically to refresh the NAT mapping.
        let ka_socket = Arc::clone(&socket);
        let ka_gate = Arc::clone(&gate);
        let keepalive = tokio::spawn(async move {
            let frame = register_frame(&self_key);
            let mut tick = tokio::time::interval(KEEPALIVE);
            tick.tick().await; // consume the immediate first tick (already sent)
            loop {
                tick.tick().await;
                ka_gate
                    .lock()
                    .expect("relay challenge gate poisoned")
                    .note_register(Instant::now());
                if let Err(e) = ka_socket.send_to(&frame, relay).await {
                    warn!("relay keepalive failed: {e}");
                }
            }
        });

        Ok(Self {
            socket,
            relay,
            secret: secret.clone(),
            gate,
            recv_buf: tokio::sync::Mutex::new(vec![0u8; FRAME_BUF]),
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
        let mut frame = self.recv_buf.lock().await;
        loop {
            let (n, from) = self.socket.recv_from(&mut frame[..]).await?;
            if from != self.relay {
                continue; // only the relay should be talking to us
            }
            if frame.first() == Some(&TAG_CHALLENGE) {
                // The relay wants proof before (re-)binding our mapping — on
                // first connect, after a roam, or after it restarted. Only
                // answer one we could have solicited (see `ChallengeGate`).
                let solicited = self
                    .gate
                    .lock()
                    .expect("relay challenge gate poisoned")
                    .allow_answer(Instant::now());
                if !solicited {
                    debug!("relay: ignoring unsolicited register challenge");
                    continue;
                }
                if let Some(resp) = answer_challenge(&self.secret, &frame[..n]) {
                    if let Err(e) = self.socket.send_to(&resp, self.relay).await {
                        warn!("relay challenge response failed: {e}");
                    }
                }
                continue;
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

    /// A deterministic test identity: the private key, and its public key.
    fn ident(b: u8) -> (StaticSecret, PublicKey) {
        let s = StaticSecret::from([b; 32]);
        let p = XPublicKey::from(&s).to_bytes();
        (s, p)
    }

    /// Spawn a relay server on loopback; return it (for drain/metrics access).
    async fn start_server() -> Arc<RelayServer> {
        let server = Arc::new(
            RelayServer::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        );
        tokio::spawn({
            let server = server.clone();
            async move {
                let _ = server.serve().await;
            }
        });
        server
    }

    /// Spawn a relay server on loopback and return its address + metrics handle.
    async fn start_relay() -> (SocketAddr, Arc<RelayMetrics>) {
        let server = start_server().await;
        (server.local_addr().unwrap(), server.metrics())
    }

    /// Complete a full register handshake for `secret` from `sock`.
    async fn register(sock: &UdpSocket, relay: SocketAddr, secret: &StaticSecret) {
        assert!(
            register_via(sock, relay, secret, Duration::from_secs(2))
                .await
                .unwrap(),
            "relay never challenged the register"
        );
    }

    /// Current value of an (unlabelled) metric.
    fn metric(metrics: &RelayMetrics, name: &str) -> u64 {
        let text = metrics.render();
        let prefix = format!("{name} ");
        text.lines()
            .find_map(|l| l.strip_prefix(&prefix))
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("{name} missing:\n{text}"))
    }

    /// Poll the metrics text until it contains `needle` (or ~1 s passes).
    async fn wait_for(metrics: &RelayMetrics, needle: &str) {
        for _ in 0..50 {
            if metrics.render().contains(needle) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
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
        // Register-hardening counters (SEC-003) start at zero.
        assert!(t.contains("# TYPE ferrum_relay_register_challenges_total counter"));
        assert!(t.contains("ferrum_relay_register_challenges_total 0\n"));
        assert!(t.contains("ferrum_relay_registers_rate_limited_total 0\n"));
        assert!(t.contains("ferrum_relay_register_proofs_rejected_total 0\n"));
        assert!(t.contains("ferrum_relay_control_frames_invalid_total 0\n"));
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
        let (secret, pubkey) = ident(0x42);
        client
            .send_to(&register_frame(&pubkey), addr)
            .await
            .unwrap();
        // A bare register only draws a challenge — nothing is committed, so
        // the fast path must not have been told anything yet.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            hook.calls.lock().unwrap().is_empty(),
            "unverified register reached the hook"
        );

        register(&client, addr, &secret).await;

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
        assert_eq!(seen_key, pubkey);
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
        let ((sa, ka), (sb, kb)) = (ident(0xAA), ident(0xBB));
        // Endpoint handles the mesh would use for each peer (need not be routable).
        let handle_b: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        let handle_a: SocketAddr = "127.0.0.1:9001".parse().unwrap();

        let a = RelayMeshTransport::connect(relay, &sa, &[(handle_b, kb)])
            .await
            .unwrap();
        let b = RelayMeshTransport::connect(relay, &sb, &[(handle_a, ka)])
            .await
            .unwrap();

        // `connect` completed each register challenge, so both mappings are
        // live before any receive loop runs.
        wait_for(&metrics, "ferrum_relay_clients_registered 2\n").await;

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
        let server = start_server().await;
        let relay = server.local_addr().unwrap();
        let metrics = server.metrics();
        let ((s1, k1), (s2, k2), (s3, _)) = (ident(1), ident(2), ident(3));

        // Two clients register before the drain starts.
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        register(&a, relay, &s1).await;
        register(&b, relay, &s2).await;
        wait_for(&metrics, "ferrum_relay_clients_registered 2\n").await;

        assert!(!server.is_draining());
        server.begin_drain();
        assert!(server.is_draining());
        assert!(metrics.render().contains("ferrum_relay_draining 1\n"));

        // A new client isn't even challenged while draining: the table stays at 2.
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let challenged = register_via(&c, relay, &s3, Duration::from_millis(300))
            .await
            .unwrap();
        assert!(!challenged, "a draining relay challenged an unknown key");
        let t = metrics.render();
        assert!(
            t.contains("ferrum_relay_registers_refused_total 1\n"),
            "{t}"
        );
        assert!(t.contains("ferrum_relay_clients_registered 2\n"), "{t}");

        // An existing client can still re-register from a new source address
        // (a mid-drain roam) — challenged like any roam, then honored.
        let a2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        register(&a2, relay, &s1).await;
        wait_for(&metrics, "ferrum_relay_registers_total 3\n").await;
        let t = metrics.render();
        assert!(t.contains("ferrum_relay_registers_total 3\n"), "{t}");
        assert!(
            t.contains("ferrum_relay_registers_refused_total 1\n"),
            "{t}"
        );

        // Existing clients' data still forwards: A (from its roamed socket)
        // reaches B mid-drain.
        a2.send_to(&data_frame(&k2, b"still flowing"), relay)
            .await
            .unwrap();
        let mut buf = [0u8; 128];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut buf))
            .await
            .expect("draining relay did not forward for an existing client")
            .unwrap();
        assert_eq!(&buf[..n], &data_frame(&k1, b"still flowing")[..]);
    }

    /// SEC-003 AC: a register alone captures nothing — without the echoed
    /// cookie (which a spoofed source never receives), no mapping exists, so
    /// traffic for that key is dropped rather than sent to the claimed address.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bare_register_does_not_create_a_mapping() {
        let (relay, metrics) = start_relay().await;
        let (sa, _) = ident(1);
        let (_, kb) = ident(2);

        // "Spoofed" B: a register for B's key whose challenge goes unanswered.
        let spoof = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        spoof.send_to(&register_frame(&kb), relay).await.unwrap();
        wait_for(&metrics, "ferrum_relay_register_challenges_total 1\n").await;
        assert!(metrics
            .render()
            .contains("ferrum_relay_clients_registered 0\n"));

        // A registered sender's data for B goes nowhere.
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        register(&a, relay, &sa).await;
        wait_for(&metrics, "ferrum_relay_clients_registered 1\n").await;
        a.send_to(&data_frame(&kb, b"for B"), relay).await.unwrap();
        wait_for(&metrics, "ferrum_relay_frames_dropped_total 1\n").await;
        let t = metrics.render();
        assert!(t.contains("ferrum_relay_frames_dropped_total 1\n"), "{t}");
        assert!(t.contains("ferrum_relay_frames_forwarded_total 0\n"), "{t}");

        // The spoof socket only ever saw its challenge — never B's traffic.
        let mut buf = [0u8; 256];
        let (n, _) = spoof.recv_from(&mut buf).await.unwrap();
        assert_eq!(buf[0], TAG_CHALLENGE);
        assert_eq!(n, CHALLENGE_LEN);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), spoof.recv_from(&mut buf))
                .await
                .is_err(),
            "spoofed register received relayed traffic"
        );
    }

    /// SEC-003 AC: someone who knows a victim's public key — and can even
    /// receive a real cookie at their own address — can't hijack the victim's
    /// live mapping, because the response needs the victim's private key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hijack_without_private_key_is_rejected() {
        let (relay, metrics) = start_relay().await;
        let ((sa, ka), (sb, kb)) = (ident(1), ident(2));
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        register(&a, relay, &sa).await;
        register(&b, relay, &sb).await;
        wait_for(&metrics, "ferrum_relay_clients_registered 2\n").await;

        // The attacker claims B's key from its own address and answers the
        // challenge it receives — but with its own private key.
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        attacker.send_to(&register_frame(&kb), relay).await.unwrap();
        let mut buf = [0u8; 256];
        let (n, _) = attacker.recv_from(&mut buf).await.unwrap();
        let (sx, _) = ident(0x66);
        let mut forged = answer_challenge(&sx, &buf[..n]).expect("well-formed challenge");
        forged[1..1 + KEY_LEN].copy_from_slice(&kb); // claim B's key
        attacker.send_to(&forged, relay).await.unwrap();

        // The cookie was honestly routed to it, so replaying it from another
        // address is rejected too (cookies are bound to the source).
        let elsewhere = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        elsewhere.send_to(&forged, relay).await.unwrap();

        wait_for(&metrics, "ferrum_relay_register_proofs_rejected_total 2\n").await;
        let t = metrics.render();
        assert!(
            t.contains("ferrum_relay_register_proofs_rejected_total 2\n"),
            "{t}"
        );

        // B's mapping is intact: A's data still reaches B, not the attacker.
        a.send_to(&data_frame(&kb, b"still B"), relay)
            .await
            .unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut buf))
            .await
            .expect("B lost its mapping")
            .unwrap();
        assert_eq!(&buf[..n], &data_frame(&ka, b"still B")[..]);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), attacker.recv_from(&mut buf))
                .await
                .is_err(),
            "attacker received B's traffic"
        );
    }

    /// SEC-003 AC: a register flood from one source is throttled — challenges
    /// stop at the per-IP burst and the refusals are counted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn register_flood_is_rate_limited() {
        let (relay, metrics) = start_relay().await;
        let flood = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sent = 200u32;
        for i in 0..sent {
            let mut k = key(0);
            k[..4].copy_from_slice(&i.to_le_bytes());
            flood.send_to(&register_frame(&k), relay).await.unwrap();
        }
        // Count the challenges that come back.
        let mut buf = [0u8; 256];
        let mut challenges = 0u32;
        while let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(300), flood.recv_from(&mut buf)).await
        {
            challenges += 1;
        }
        // Bounds, not exact counts: loopback UDP can drop under a burst, and a
        // slow runner lets a few tokens refill (8/s) while the loop runs.
        assert!(
            challenges <= IP_BURST + 16,
            "{challenges} challenges for {sent} registers"
        );
        assert!(
            challenges >= IP_BURST / 2,
            "burst never served: {challenges}"
        );
        let limited = metric(&metrics, "ferrum_relay_registers_rate_limited_total");
        assert!(
            limited >= u64::from(sent - IP_BURST - 16),
            "only {limited} of {sent} registers rate-limited"
        );
    }

    /// SEC-003: the key holder itself is budgeted on mapping *changes* (roams),
    /// so a flapping client can't churn the table (or the XDP maps) unboundedly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn roams_are_rate_limited_per_key() {
        let (relay, metrics) = start_relay().await;
        let (s, _) = ident(9);
        let attempts = KEY_BURST + 4;
        for _ in 0..attempts {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            register(&sock, relay, &s).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Bounds: the per-key bucket refills at 1/s while the handshakes run.
        let accepted = metric(&metrics, "ferrum_relay_registers_total");
        let limited = metric(&metrics, "ferrum_relay_registers_rate_limited_total");
        assert!(
            accepted >= u64::from(KEY_BURST) && accepted < u64::from(attempts),
            "accepted {accepted} of {attempts}"
        );
        assert!(limited >= 1, "no roam was rate-limited");
    }

    /// Review fix: pre-SEC-003 clients' 33-byte registers (and other malformed
    /// control frames) are counted as control errors, not forwarding drops,
    /// so a rolling upgrade can't trip the relay-forwarding SLO.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_control_frames_stay_out_of_the_forwarding_sli() {
        let (relay, metrics) = start_relay().await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut old_register = vec![TAG_REGISTER];
        old_register.extend_from_slice(&key(7));
        sock.send_to(&old_register, relay).await.unwrap(); // 33 bytes
        sock.send_to(&[0x7f, 1, 2, 3], relay).await.unwrap(); // unknown tag
        sock.send_to(&[TAG_DATA, 1, 2], relay).await.unwrap(); // truncated data

        // Wait for both counters: the invalid count reaches 2 after the second
        // datagram, and the relay may not have read the third (the truncated
        // data frame) yet. Asserting right then raced on loaded CI runners.
        wait_for(&metrics, "ferrum_relay_control_frames_invalid_total 2\n").await;
        wait_for(&metrics, "ferrum_relay_frames_dropped_total 1\n").await;
        assert_eq!(
            metric(&metrics, "ferrum_relay_control_frames_invalid_total"),
            2
        );
        assert_eq!(metric(&metrics, "ferrum_relay_frames_dropped_total"), 1);
    }

    #[test]
    fn challenge_gate_only_answers_soon_after_a_register() {
        let t0 = Instant::now();
        let mut gate = ChallengeGate::default();
        assert!(!gate.allow_answer(t0), "no register sent yet");
        gate.note_register(t0);
        assert!(gate.allow_answer(t0));
        assert!(gate.allow_answer(t0), "one duplicate allowed");
        assert!(!gate.allow_answer(t0), "flood capped");
        gate.note_register(t0 + Duration::from_secs(25));
        assert!(
            !gate.allow_answer(t0 + Duration::from_secs(31)),
            "window expired"
        );
    }

    /// Review fix: challenges spoofed from the relay's address are answered at
    /// most `MAX_ANSWERS_PER_REGISTER` times per Register — the client neither
    /// burns an X25519 per packet nor reflects a Response flood at the relay.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_caps_answers_to_spoofed_challenges() {
        // A stand-in "relay" we fully control (never answers on its own).
        let fake = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fake_addr = fake.local_addr().unwrap();
        let (s, _) = ident(3);
        let t = RelayMeshTransport::connect(fake_addr, &s, &[])
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let (_, client) = fake.recv_from(&mut buf).await.unwrap(); // its Register

        let relay_pub = XPublicKey::from(&StaticSecret::random()).to_bytes();
        for _ in 0..20 {
            fake.send_to(&challenge_frame(&relay_pub, &[1; COOKIE_LEN]), client)
                .await
                .unwrap();
        }
        let drive = tokio::spawn(async move {
            let mut b = [0u8; 256];
            let _ = t.recv_from(&mut b).await;
        });
        let mut responses = 0u32;
        while let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(400), fake.recv_from(&mut buf)).await
        {
            if n == RESPONSE_LEN && buf[0] == TAG_RESPONSE {
                responses += 1;
            }
        }
        drive.abort();
        assert_eq!(
            responses, MAX_ANSWERS_PER_REGISTER,
            "answered {responses} of 20"
        );
    }

    /// The fixed frame sizes the reflection argument rests on.
    #[test]
    fn challenge_is_never_larger_than_register() {
        let (s, k) = ident(1);
        let reg = register_frame(&k);
        let chal = challenge_frame(&[9; 32], &[1; COOKIE_LEN]);
        assert_eq!(reg.len(), REGISTER_LEN);
        assert_eq!(chal.len(), CHALLENGE_LEN);
        assert!(chal.len() <= reg.len());
        assert_eq!(answer_challenge(&s, &chal).unwrap().len(), RESPONSE_LEN);
        assert!(answer_challenge(&s, &reg).is_none(), "not a challenge");
    }

    /// A data frame for an unregistered destination key is dropped (no panic, no
    /// delivery), and the sender's own loop is unaffected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drops_data_for_unknown_destination() {
        let (relay, _metrics) = start_relay().await;
        let (sa, _) = ident(0x01);
        let handle_ghost: SocketAddr = "127.0.0.1:9009".parse().unwrap();
        let a = RelayMeshTransport::connect(relay, &sa, &[(handle_ghost, key(0x99))])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Destination key 0x99 never registered: the relay drops it. We just
        // assert the send path doesn't error.
        a.send_to(handle_ghost, b"into the void").await.unwrap();
    }
}
