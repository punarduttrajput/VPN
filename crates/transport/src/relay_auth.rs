//! Register authentication for the DERP-style relay (PRD `security-hardening.md`
//! FR3 / SEC-003).
//!
//! A bare `Register` frame used to bind `key -> source addr` on sight, so anyone
//! who knew a peer's (public, non-secret) key could redirect its relayed traffic,
//! and a spoofed source address turned the relay into a reflector. A mapping now
//! only changes after a one-round-trip challenge:
//!
//! 1. client → relay `Register(key)`;
//! 2. relay → client `Challenge(relay_pub, cookie)`, where `cookie` is a keyed
//!    BLAKE2s MAC over `(epoch, source addr, key)` — **stateless**, so a flood of
//!    spoofed registers costs the relay a hash each and no memory;
//! 3. client → relay `Response(key, cookie, proof)` from the same source, where
//!    `proof` is a keyed BLAKE2s MAC under `X25519(client_priv, relay_pub)`.
//!
//! The cookie proves **return routability** (the client really receives at that
//! address — a blind spoofer never sees it); the proof proves **possession of the
//! key's private half** (the relay recomputes the same shared secret as
//! `X25519(relay_priv, key)`). Together: only the key holder, reachable at the
//! address, can claim the mapping. This mirrors WireGuard's own cookie/MAC design
//! and reuses its primitives (X25519 + keyed BLAKE2s), already in the tree.
//!
//! [`RateLimiter`] is the flood side: token buckets per source IP (challenges
//! issued + proofs checked — the proof costs one X25519, so it's gated behind the
//! cheap cookie check *and* this bucket) and per key (committed mapping changes).

use std::collections::HashMap;
use std::hash::Hash;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use blake2::digest::{KeyInit, Mac};
use blake2::Blake2sMac256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use crate::relay::PublicKey;

/// Length of a relay-issued cookie on the wire.
pub(crate) const COOKIE_LEN: usize = 16;
/// Length of a client's possession proof on the wire.
pub(crate) const PROOF_LEN: usize = 16;
/// Cookie validity is bucketed into epochs of this length; the current and the
/// previous epoch are accepted, so a cookie lives 30–60 s — ample for one RTT.
const COOKIE_EPOCH: Duration = Duration::from_secs(30);
/// Domain-separates the proof MAC from any other use of the shared secret.
const PROOF_LABEL: &[u8] = b"ferrum-relay-register-v1";

/// Keyed BLAKE2s over `parts`, truncated to 16 bytes.
fn mac16(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut m =
        <Blake2sMac256 as KeyInit>::new_from_slice(key).expect("BLAKE2s accepts 32-byte keys");
    for p in parts {
        m.update(p);
    }
    let full = m.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Constant-time equality for short MACs.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Canonical bytes for a socket address (family-tagged so v4 and v6 can't alias).
fn addr_bytes(addr: SocketAddr) -> Vec<u8> {
    let mut v = Vec::with_capacity(19);
    match addr {
        SocketAddr::V4(a) => {
            v.push(4);
            v.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            v.push(6);
            v.extend_from_slice(&a.ip().octets());
        }
    }
    v.extend_from_slice(&addr.port().to_be_bytes());
    v
}

/// The proof MAC both sides compute from the X25519 shared secret.
fn proof(
    shared: &[u8; 32],
    relay_pub: &[u8; 32],
    cookie: &[u8; COOKIE_LEN],
    key: &PublicKey,
) -> [u8; PROOF_LEN] {
    mac16(shared, &[PROOF_LABEL, relay_pub, cookie, key])
}

/// The relay's side: issues cookies and verifies responses.
///
/// The X25519 secret and the cookie key are per-process and never persisted — a
/// restarted relay simply re-challenges clients on their next keepalive.
pub(crate) struct RegisterAuth {
    secret: StaticSecret,
    public: [u8; 32],
    cookie_key: [u8; 32],
    started: Instant,
}

impl RegisterAuth {
    pub(crate) fn new() -> Self {
        let secret = StaticSecret::random();
        let public = XPublicKey::from(&secret).to_bytes();
        let mut cookie_key = [0u8; 32];
        getrandom::getrandom(&mut cookie_key).expect("OS RNG unavailable");
        Self {
            secret,
            public,
            cookie_key,
            started: Instant::now(),
        }
    }

    /// The relay's X25519 public key, carried in every challenge.
    pub(crate) fn public(&self) -> [u8; 32] {
        self.public
    }

    fn epoch(&self, now: Instant) -> u64 {
        now.duration_since(self.started).as_secs() / COOKIE_EPOCH.as_secs()
    }

    fn cookie_at(&self, epoch: u64, from: SocketAddr, key: &PublicKey) -> [u8; COOKIE_LEN] {
        mac16(
            &self.cookie_key,
            &[&epoch.to_le_bytes(), &addr_bytes(from), key],
        )
    }

    /// A fresh cookie binding `from` + `key` to the current epoch.
    pub(crate) fn issue(
        &self,
        from: SocketAddr,
        key: &PublicKey,
        now: Instant,
    ) -> [u8; COOKIE_LEN] {
        self.cookie_at(self.epoch(now), from, key)
    }

    /// Whether `cookie` was issued by this relay to `from` for `key`, recently.
    /// Cheap (hashing only) — check this before [`verify_proof`](Self::verify_proof).
    pub(crate) fn check_cookie(
        &self,
        from: SocketAddr,
        key: &PublicKey,
        cookie: &[u8; COOKIE_LEN],
        now: Instant,
    ) -> bool {
        let e = self.epoch(now);
        ct_eq(&self.cookie_at(e, from, key), cookie)
            || (e > 0 && ct_eq(&self.cookie_at(e - 1, from, key), cookie))
    }

    /// Whether `proof` shows possession of `key`'s private half (one X25519).
    /// A low-order `key` (a non-contributory exchange, whose "shared secret" is
    /// predictable) is always rejected.
    pub(crate) fn verify_proof(
        &self,
        key: &PublicKey,
        cookie: &[u8; COOKIE_LEN],
        got: &[u8; PROOF_LEN],
    ) -> bool {
        let shared = self.secret.diffie_hellman(&XPublicKey::from(*key));
        if !shared.was_contributory() {
            return false;
        }
        ct_eq(&proof(shared.as_bytes(), &self.public, cookie, key), got)
    }
}

/// The client's side: the proof for a challenge, from our own private key.
/// `None` if the relay's key is low-order (a broken or hostile relay).
pub(crate) fn answer(
    secret: &StaticSecret,
    relay_pub: &[u8; 32],
    cookie: &[u8; COOKIE_LEN],
) -> Option<(PublicKey, [u8; PROOF_LEN])> {
    let me = XPublicKey::from(secret).to_bytes();
    let shared = secret.diffie_hellman(&XPublicKey::from(*relay_pub));
    if !shared.was_contributory() {
        return None;
    }
    Some((me, proof(shared.as_bytes(), relay_pub, cookie, &me)))
}

/// One token bucket.
#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

/// Token-bucket rate limiter keyed by `K`, with a bounded table: once it holds
/// `max_tracked` keys, a new key makes room (see `make_room`: a rate-limited
/// sweep of idle buckets, else one eviction). A spoofed-source flood therefore
/// can't grow memory without bound, can't make each packet an O(n) scan, and
/// can't lock new legitimate sources out.
pub(crate) struct RateLimiter<K> {
    buckets: HashMap<K, Bucket>,
    capacity: f64,
    refill_per_sec: f64,
    max_tracked: usize,
    /// When the full-table sweep last ran (it's O(n), so it's rate-limited too).
    last_sweep: Option<Instant>,
}

/// Minimum spacing between full-table sweeps: a flood of never-seen sources
/// must not turn every packet into an O(n) scan of the table.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

impl<K: Eq + Hash + Copy> RateLimiter<K> {
    pub(crate) fn new(capacity: u32, refill_per_sec: f64, max_tracked: usize) -> Self {
        Self {
            buckets: HashMap::new(),
            capacity: capacity as f64,
            refill_per_sec,
            max_tracked,
            last_sweep: None,
        }
    }

    /// Make room for one new key in a full table. Sweeps idle (refilled)
    /// buckets at most once per [`SWEEP_INTERVAL`]; if the table is still full,
    /// evicts one arbitrary bucket rather than refusing the newcomer — refusing
    /// would let a spoofed-source flood that fills the table lock every *new*
    /// legitimate source out. (An attacker who evicts a bucket this way resets
    /// one random entry's limit per packet, far cheaper to tolerate than a
    /// lockout; the cookie check keeps the expensive work return-routable.)
    fn make_room(&mut self, now: Instant) {
        let due = self
            .last_sweep
            .is_none_or(|t| now.saturating_duration_since(t) >= SWEEP_INTERVAL);
        if due {
            self.last_sweep = Some(now);
            let (cap, rate) = (self.capacity, self.refill_per_sec);
            self.buckets.retain(|_, b| {
                (b.tokens + now.saturating_duration_since(b.at).as_secs_f64() * rate) < cap
            });
        }
        if self.buckets.len() >= self.max_tracked {
            if let Some(victim) = self.buckets.keys().next().copied() {
                self.buckets.remove(&victim);
            }
        }
    }

    fn refilled(&self, b: Bucket, now: Instant) -> f64 {
        (b.tokens + now.saturating_duration_since(b.at).as_secs_f64() * self.refill_per_sec)
            .min(self.capacity)
    }

    /// Take one token for `key` if available.
    pub(crate) fn allow(&mut self, key: K, now: Instant) -> bool {
        if self.buckets.len() >= self.max_tracked && !self.buckets.contains_key(&key) {
            self.make_room(now);
        }
        let tokens = match self.buckets.get(&key) {
            Some(b) => self.refilled(*b, now),
            None => self.capacity,
        };
        let allowed = tokens >= 1.0;
        let left = if allowed { tokens - 1.0 } else { tokens };
        self.buckets.insert(
            key,
            Bucket {
                tokens: left,
                at: now,
            },
        );
        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn honest_client_proof_verifies() {
        let relay = RegisterAuth::new();
        let client = StaticSecret::random();
        let key = XPublicKey::from(&client).to_bytes();
        let from = addr("192.0.2.1:4000");
        let now = Instant::now();

        let cookie = relay.issue(from, &key, now);
        assert!(relay.check_cookie(from, &key, &cookie, now));
        let (me, p) = answer(&client, &relay.public(), &cookie).unwrap();
        assert_eq!(me, key);
        assert!(relay.verify_proof(&key, &cookie, &p));
    }

    #[test]
    fn cookie_is_bound_to_source_and_key() {
        let relay = RegisterAuth::new();
        let now = Instant::now();
        let cookie = relay.issue(addr("192.0.2.1:4000"), &[7; 32], now);
        assert!(
            !relay.check_cookie(addr("192.0.2.1:4001"), &[7; 32], &cookie, now),
            "other port"
        );
        assert!(
            !relay.check_cookie(addr("192.0.2.2:4000"), &[7; 32], &cookie, now),
            "other ip"
        );
        assert!(
            !relay.check_cookie(addr("192.0.2.1:4000"), &[8; 32], &cookie, now),
            "other key"
        );
    }

    #[test]
    fn cookie_expires_after_two_epochs() {
        let relay = RegisterAuth::new();
        let from = addr("192.0.2.1:4000");
        let t0 = relay.started;
        let cookie = relay.issue(from, &[7; 32], t0);
        assert!(
            relay.check_cookie(from, &[7; 32], &cookie, t0 + COOKIE_EPOCH),
            "previous epoch ok"
        );
        assert!(
            !relay.check_cookie(from, &[7; 32], &cookie, t0 + COOKIE_EPOCH * 2),
            "expired"
        );
    }

    /// The hijack SEC-003 is about: knowing a victim's public key (and even
    /// receiving a valid cookie at your own address) isn't enough — the proof
    /// needs the victim's private key.
    #[test]
    fn proof_from_the_wrong_private_key_is_rejected() {
        let relay = RegisterAuth::new();
        let victim = XPublicKey::from(&StaticSecret::random()).to_bytes();
        let attacker = StaticSecret::random();
        let cookie = relay.issue(addr("198.51.100.9:1"), &victim, Instant::now());
        let (_, forged) = answer(&attacker, &relay.public(), &cookie).unwrap();
        assert!(!relay.verify_proof(&victim, &cookie, &forged));
    }

    #[test]
    fn low_order_keys_are_rejected() {
        let relay = RegisterAuth::new();
        let cookie = [0u8; COOKIE_LEN];
        // The all-zero point is low-order: X25519 with it yields all zeros, so
        // anyone could compute the "proof" — it must never verify.
        let zero = [0u8; 32];
        let forged = proof(&[0u8; 32], &relay.public(), &cookie, &zero);
        assert!(!relay.verify_proof(&zero, &cookie, &forged));
        assert!(answer(&StaticSecret::random(), &zero, &cookie).is_none());
    }

    #[test]
    fn rate_limiter_bursts_then_refills() {
        let mut rl = RateLimiter::new(3, 1.0, 16);
        let t0 = Instant::now();
        assert!(rl.allow(1u8, t0));
        assert!(rl.allow(1u8, t0));
        assert!(rl.allow(1u8, t0));
        assert!(!rl.allow(1u8, t0), "burst exhausted");
        assert!(rl.allow(2u8, t0), "other keys unaffected");
        assert!(
            rl.allow(1u8, t0 + Duration::from_secs(1)),
            "one token back after 1 s"
        );
        assert!(!rl.allow(1u8, t0 + Duration::from_secs(1)));
    }

    #[test]
    fn rate_limiter_table_stays_bounded() {
        let mut rl = RateLimiter::new(2, 10.0, 4);
        let t0 = Instant::now();
        for k in 0..4u32 {
            assert!(rl.allow(k, t0));
        }
        // Full of mid-burst keys: a newcomer is still admitted (never locked out
        // by a table a flood filled) and the table stays at the bound.
        assert!(rl.allow(99, t0));
        assert_eq!(rl.buckets.len(), 4);
        assert!(rl.buckets.contains_key(&99));
        // Once they've refilled, a sweep reclaims the idle buckets.
        assert!(rl.allow(100, t0 + Duration::from_secs(2)));
        assert!(
            rl.buckets.len() <= 2,
            "idle buckets swept: {}",
            rl.buckets.len()
        );
    }

    /// Review fix: a flood of never-seen keys into a full table sweeps at
    /// most once per interval instead of scanning the table on every packet.
    #[test]
    fn full_table_sweeps_are_rate_limited() {
        let mut rl = RateLimiter::new(2, 10.0, 4);
        let t0 = Instant::now();
        for k in 0..4u32 {
            rl.allow(k, t0);
        }
        rl.allow(1000, t0); // first overflow: sweeps
        let swept_at = rl.last_sweep;
        for k in 1001..1100u32 {
            rl.allow(k, t0 + Duration::from_millis(10));
        }
        assert_eq!(
            rl.last_sweep, swept_at,
            "no second sweep within the interval"
        );
        assert_eq!(rl.buckets.len(), 4);
        rl.allow(5000, t0 + SWEEP_INTERVAL);
        assert_ne!(rl.last_sweep, swept_at, "sweeps again after the interval");
    }
}
