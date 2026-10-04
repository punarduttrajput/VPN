//! Control-plane rate limits and stream quotas (PRD security-hardening.md
//! SEC-006 / FR6).
//!
//! Two primitives, both keyed by an opaque string and held only in memory:
//!
//! - [`KeyedLimiter`]: a token bucket per key, for request-rate limits on
//!   `RegisterDevice` and `RelayHeartbeat`.
//! - [`StreamQuota`]: a count of concurrently open `WatchNetworkMap` streams
//!   per key, plus a global total, released by a drop guard.
//!
//! Keys come from [`source_key`] (the peer's IP, IPv6 collapsed to its /64 so
//! one host can't mint unlimited keys) and from the authenticated identity
//! (`oidc:<sub>` / `mtls:<fp>`, SEC-002). **Privacy (NFR5):** keys never leave
//! this module. They aren't logged, traced or exported; only aggregate
//! throttle counts reach [`crate::Metrics`].

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A token-bucket shape: `burst` requests at once, refilled at `per_sec`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateSpec {
    /// Bucket capacity (and the starting balance for a new key).
    pub burst: u32,
    /// Sustained refill rate, in requests per second.
    pub per_sec: f64,
}

impl RateSpec {
    /// `burst` at once, then `per_sec` sustained.
    pub const fn new(burst: u32, per_sec: f64) -> Self {
        Self { burst, per_sec }
    }
}

/// Tunable coordinator limits. The defaults are sized so a normal fleet never
/// notices: a device registers once per connect, a relay heartbeats every
/// 15 s, and a device keeps one watch stream open (briefly two while
/// reconnecting). Per-source limits are looser than per-identity ones because
/// many devices can share one NAT'd address.
#[derive(Debug, Clone, PartialEq)]
pub struct LimitsConfig {
    /// `RegisterDevice` per authenticated identity.
    pub register_per_identity: RateSpec,
    /// `RegisterDevice` per source address (checked before authentication).
    pub register_per_source: RateSpec,
    /// `RelayHeartbeat` per authenticated identity.
    pub heartbeat_per_identity: RateSpec,
    /// `RelayHeartbeat` per source address (checked before authentication).
    pub heartbeat_per_source: RateSpec,
    /// Concurrent `WatchNetworkMap` streams per authenticated identity.
    pub watch_streams_per_identity: usize,
    /// Concurrent `WatchNetworkMap` streams per source address.
    pub watch_streams_per_source: usize,
    /// Concurrent `WatchNetworkMap` streams across the whole coordinator.
    pub watch_streams_total: usize,
    /// Most distinct keys a rate limiter tracks before refusing new ones
    /// (bounds memory against address-hopping floods).
    pub max_tracked_keys: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            // 10 at once, then one every 6 s (10/min).
            register_per_identity: RateSpec::new(10, 1.0 / 6.0),
            // An office behind one NAT: 60 at once, then 1/s.
            register_per_source: RateSpec::new(60, 1.0),
            // Heartbeats are due every 15 s: 10 at once, then one every 5 s.
            heartbeat_per_identity: RateSpec::new(10, 0.2),
            heartbeat_per_source: RateSpec::new(30, 1.0),
            watch_streams_per_identity: 4,
            watch_streams_per_source: 256,
            watch_streams_total: 10_000,
            max_tracked_keys: 65_536,
        }
    }
}

/// The per-RPC limiters and the watch-stream quota for one coordinator.
pub(crate) struct Limits {
    pub(crate) register_identity: KeyedLimiter,
    pub(crate) register_source: KeyedLimiter,
    pub(crate) heartbeat_identity: KeyedLimiter,
    pub(crate) heartbeat_source: KeyedLimiter,
    pub(crate) watch: Arc<StreamQuota>,
    pub(crate) watch_per_identity: usize,
    pub(crate) watch_per_source: usize,
}

impl Limits {
    pub(crate) fn new(cfg: &LimitsConfig) -> Self {
        let limiter = |spec| KeyedLimiter::new(spec, cfg.max_tracked_keys);
        Self {
            register_identity: limiter(cfg.register_per_identity),
            register_source: limiter(cfg.register_per_source),
            heartbeat_identity: limiter(cfg.heartbeat_per_identity),
            heartbeat_source: limiter(cfg.heartbeat_per_source),
            watch: Arc::new(StreamQuota::new(cfg.watch_streams_total)),
            watch_per_identity: cfg.watch_streams_per_identity,
            watch_per_source: cfg.watch_streams_per_source,
        }
    }
}

/// The rate-limit key for a peer address: the IPv4 address, or the /64 of an
/// IPv6 one (a single host typically controls a whole /64). IPv4-mapped IPv6
/// is treated as IPv4. `None` (no transport address, e.g. an in-process
/// channel) shares one `unknown` key.
pub fn source_key(addr: Option<SocketAddr>) -> String {
    let Some(addr) = addr else {
        return "src:unknown".to_string();
    };
    match addr.ip() {
        IpAddr::V4(v4) => format!("src:{v4}"),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => format!("src:{v4}"),
            None => {
                let s = v6.segments();
                format!("src:{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

/// Per-key token buckets with a bounded key set.
pub struct KeyedLimiter {
    spec: RateSpec,
    max_keys: usize,
    state: Mutex<LimiterState>,
}

struct LimiterState {
    buckets: HashMap<String, Bucket>,
    /// When the key table was last pruned of idle buckets.
    last_prune: Option<Instant>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    /// The balance at `now`, including refill since the last update.
    fn balance(&self, now: Instant, spec: RateSpec) -> f64 {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        (self.tokens + elapsed * spec.per_sec).min(f64::from(spec.burst))
    }
}

/// Minimum spacing between idle-bucket prunes. A full table otherwise costs
/// O(keys) per request from a new key.
const PRUNE_INTERVAL: Duration = Duration::from_secs(1);

impl KeyedLimiter {
    /// A limiter enforcing `spec` per key, tracking at most `max_keys` keys.
    pub fn new(spec: RateSpec, max_keys: usize) -> Self {
        Self {
            spec,
            max_keys,
            state: Mutex::new(LimiterState {
                buckets: HashMap::new(),
                last_prune: None,
            }),
        }
    }

    /// Take one token for `key` at `now`. `false` means throttled: the bucket
    /// is empty, or the key is new and the table is full of active keys.
    pub fn check(&self, key: &str, now: Instant) -> bool {
        let spec = self.spec;
        let mut st = self.state.lock().expect("limiter mutex poisoned");
        if !st.buckets.contains_key(key) && st.buckets.len() >= self.max_keys {
            let due = st
                .last_prune
                .is_none_or(|t| now.saturating_duration_since(t) >= PRUNE_INTERVAL);
            if due {
                // A fully refilled bucket is indistinguishable from a fresh one.
                let full = f64::from(spec.burst);
                st.buckets.retain(|_, b| b.balance(now, spec) < full);
                st.last_prune = Some(now);
            }
            if st.buckets.len() >= self.max_keys {
                return false;
            }
        }
        let bucket = st.buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: f64::from(spec.burst),
            last: now,
        });
        bucket.tokens = bucket.balance(now, spec);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Concurrent-stream accounting: per-key counts plus a global total. Entries
/// exist only while a stream is open, so the map is bounded by the total cap.
pub struct StreamQuota {
    max_total: usize,
    state: Mutex<QuotaState>,
}

#[derive(Default)]
struct QuotaState {
    per_key: HashMap<String, usize>,
    total: usize,
}

impl StreamQuota {
    /// A quota allowing at most `max_total` streams overall.
    pub fn new(max_total: usize) -> Self {
        Self {
            max_total,
            state: Mutex::new(QuotaState::default()),
        }
    }

    /// Reserve one stream against every `(key, cap)` in `keys` and the global
    /// cap, all or nothing. `None` means over quota. The returned permit
    /// releases the reservation on drop.
    pub fn try_acquire(self: &Arc<Self>, keys: Vec<(String, usize)>) -> Option<StreamPermit> {
        let mut st = self.state.lock().expect("quota mutex poisoned");
        if st.total >= self.max_total {
            return None;
        }
        let over = keys
            .iter()
            .any(|(k, cap)| st.per_key.get(k).copied().unwrap_or(0) >= *cap);
        if over {
            return None;
        }
        for (k, _) in &keys {
            *st.per_key.entry(k.clone()).or_insert(0) += 1;
        }
        st.total += 1;
        Some(StreamPermit {
            quota: self.clone(),
            keys: keys.into_iter().map(|(k, _)| k).collect(),
        })
    }

    #[cfg(test)]
    fn total(&self) -> usize {
        self.state.lock().unwrap().total
    }
}

/// A reserved watch-stream slot; dropping it releases the slot.
pub struct StreamPermit {
    quota: Arc<StreamQuota>,
    keys: Vec<String>,
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        let mut st = self.quota.state.lock().expect("quota mutex poisoned");
        for k in &self.keys {
            if let Some(n) = st.per_key.get_mut(k) {
                *n -= 1;
                if *n == 0 {
                    st.per_key.remove(k);
                }
            }
        }
        st.total -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_burst_then_refills_at_rate() {
        let l = KeyedLimiter::new(RateSpec::new(3, 2.0), 16);
        let t0 = Instant::now();
        assert!(l.check("a", t0) && l.check("a", t0) && l.check("a", t0));
        assert!(!l.check("a", t0), "burst exhausted");
        assert!(l.check("b", t0), "keys are independent");
        // 2/s: one token back after 0.5 s, not before.
        assert!(!l.check("a", t0 + Duration::from_millis(400)));
        assert!(l.check("a", t0 + Duration::from_millis(900)));
    }

    #[test]
    fn full_key_table_prunes_idle_keys_and_refuses_when_all_are_active() {
        let l = KeyedLimiter::new(RateSpec::new(1, 1.0), 2);
        let t0 = Instant::now();
        assert!(l.check("a", t0));
        assert!(l.check("b", t0));
        // Both keys are mid-refill: a new key can't displace them.
        assert!(!l.check("c", t0));
        // Once they've refilled, they're pruned and "c" gets a bucket.
        assert!(l.check("c", t0 + Duration::from_secs(2)));
    }

    #[test]
    fn source_key_collapses_ipv6_to_its_64_and_unmaps_ipv4() {
        let k = |s: &str| source_key(Some(s.parse().unwrap()));
        assert_eq!(k("203.0.113.7:4000"), "src:203.0.113.7");
        assert_eq!(k("[::ffff:203.0.113.7]:4000"), "src:203.0.113.7");
        assert_eq!(k("[2001:db8:1:2::1]:1"), k("[2001:db8:1:2:ffff::9]:2"));
        assert_ne!(k("[2001:db8:1:2::1]:1"), k("[2001:db8:1:3::1]:1"));
        assert_eq!(source_key(None), "src:unknown");
    }

    #[test]
    fn stream_quota_enforces_per_key_and_global_caps_and_releases_on_drop() {
        let q = Arc::new(StreamQuota::new(3));
        let key = |k: &str, cap| vec![(k.to_string(), cap)];
        let a1 = q.try_acquire(key("a", 2)).unwrap();
        let _a2 = q.try_acquire(key("a", 2)).unwrap();
        assert!(q.try_acquire(key("a", 2)).is_none(), "per-key cap");
        let _b1 = q.try_acquire(key("b", 2)).unwrap();
        assert!(q.try_acquire(key("c", 2)).is_none(), "global cap");
        drop(a1);
        assert_eq!(q.total(), 2);
        assert!(q.try_acquire(key("a", 2)).is_some(), "slot released");
    }

    #[test]
    fn stream_quota_is_all_or_nothing_across_keys() {
        let q = Arc::new(StreamQuota::new(10));
        let _held = q.try_acquire(vec![("id".into(), 1)]).unwrap();
        // The source has room but the identity doesn't: nothing is reserved.
        assert!(q
            .try_acquire(vec![("src".into(), 5), ("id".into(), 1)])
            .is_none());
        assert_eq!(q.total(), 1);
    }
}
