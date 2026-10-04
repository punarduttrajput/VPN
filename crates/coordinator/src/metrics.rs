//! Privacy-preserving coordinator metrics (PRD Phase 6, FR4 / NFR5).
//!
//! A tiny, dependency-free metrics registry in the Prometheus text exposition
//! format — hand-rolled to keep the crate lean, mirroring the in-tree STUN/relay/
//! OIDC code rather than pulling a metrics stack. The coordinator increments these
//! counters as it serves control-plane RPCs; the binary exposes them on a
//! `/metrics` endpoint (`--metrics-listen`).
//!
//! **Privacy boundary (NFR5):** every metric here is an aggregate *count* —
//! registrations, map fetches, active watch streams, auth rejections. There are
//! **no labels carrying public keys, tunnel IPs, endpoints, tags, or any per-user
//! identity**, and nothing here observes user *traffic* (the coordinator never
//! sees it). Keep it that way: a metric that could identify a device or a flow
//! does not belong in this file.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Upper bounds (`le`, seconds) of the request-duration histogram buckets — a
/// fixed ladder from 0.5 ms to 5 s, dense in the sub-100 ms range where a healthy
/// control-plane RPC lives. The latency SLO is measured at the `0.1` boundary, so
/// that value MUST stay in this ladder (the recording rule selects `le="0.1"`).
const REQUEST_DURATION_BUCKETS_SECONDS: [f64; 13] = [
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Aggregate counters/gauges for the coordinator. Cheap to update (relaxed
/// atomics) and safe to share across all request handlers via an [`Arc`].
#[derive(Default)]
pub struct Metrics {
    register_total: AtomicU64,
    rotate_key_total: AtomicU64,
    publish_candidates_total: AtomicU64,
    network_map_requests_total: AtomicU64,
    watch_streams_opened_total: AtomicU64,
    watch_streams_active: AtomicU64,
    unauthenticated_total: AtomicU64,
    register_throttled_total: AtomicU64,
    relay_heartbeat_throttled_total: AtomicU64,
    watch_streams_rejected_total: AtomicU64,
    request_duration: DurationHistogram,
}

/// A Prometheus-style histogram of RPC handler durations — the latency SLI
/// (PRD Phase 6 FR4). Each observation lands in exactly one bucket (the smallest
/// boundary `>=` the duration; observations past the largest boundary sit only in
/// the implicit `+Inf` bucket), plus a running sum and count. Aggregate only — no
/// per-user labels (NFR5).
struct DurationHistogram {
    /// Per-bucket observation counts, parallel to [`REQUEST_DURATION_BUCKETS_SECONDS`].
    /// Rendered cumulatively (Prometheus histogram buckets are `<= le`).
    buckets: [AtomicU64; REQUEST_DURATION_BUCKETS_SECONDS.len()],
    /// Sum of all observed durations, in nanoseconds (rendered as seconds).
    sum_nanos: AtomicU64,
    /// Total observations (the implicit `+Inf` bucket).
    count: AtomicU64,
}

impl Default for DurationHistogram {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            sum_nanos: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

impl DurationHistogram {
    /// Record one observed duration.
    fn observe(&self, d: Duration) {
        self.sum_nanos
            .fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        let secs = d.as_secs_f64();
        for (i, &le) in REQUEST_DURATION_BUCKETS_SECONDS.iter().enumerate() {
            if secs <= le {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // Past the largest finite bucket: counted only in `+Inf` (== count).
    }
}

impl Metrics {
    /// A fresh, shareable metrics registry.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A `RegisterDevice` RPC was handled.
    pub fn inc_register(&self) {
        self.register_total.fetch_add(1, Ordering::Relaxed);
    }

    /// A `RotateKey` RPC was handled.
    pub fn inc_rotate_key(&self) {
        self.rotate_key_total.fetch_add(1, Ordering::Relaxed);
    }

    /// A `PublishCandidates` RPC was handled.
    pub fn inc_publish_candidates(&self) {
        self.publish_candidates_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// A one-shot `GetNetworkMap` RPC was handled.
    pub fn inc_network_map_request(&self) {
        self.network_map_requests_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// An RPC was rejected for failing authentication (OIDC).
    pub fn inc_unauthenticated(&self) {
        self.unauthenticated_total.fetch_add(1, Ordering::Relaxed);
    }

    /// A `RegisterDevice` RPC was refused by a rate limit (SEC-006).
    pub fn inc_register_throttled(&self) {
        self.register_throttled_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// A `RelayHeartbeat` RPC was refused by a rate limit (SEC-006).
    pub fn inc_relay_heartbeat_throttled(&self) {
        self.relay_heartbeat_throttled_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// A `WatchNetworkMap` stream was refused by the stream quota (SEC-006).
    pub fn inc_watch_stream_rejected(&self) {
        self.watch_streams_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Start timing an RPC handler, returning a guard that records the elapsed
    /// duration into the latency histogram when it drops (PRD Phase 6 FR4). Drop
    /// covers every return path — including the `?` early-out on an auth failure —
    /// so the SLI reflects all served requests regardless of outcome.
    pub fn start_request(self: &Arc<Self>) -> RequestTimer {
        RequestTimer {
            metrics: self.clone(),
            start: Instant::now(),
        }
    }

    /// Record a new `WatchNetworkMap` stream opening, returning a guard that
    /// decrements the active-streams gauge when the stream ends (on drop).
    pub fn watch_started(self: &Arc<Self>) -> WatchGuard {
        self.watch_streams_opened_total
            .fetch_add(1, Ordering::Relaxed);
        self.watch_streams_active.fetch_add(1, Ordering::Relaxed);
        WatchGuard {
            metrics: self.clone(),
        }
    }

    /// Render all metrics in the Prometheus text exposition format. `device_count`
    /// is sampled at scrape time from the registry (the one gauge whose source of
    /// truth lives outside this struct).
    pub fn render(&self, device_count: usize) -> String {
        let mut out = String::with_capacity(1024);
        gauge(
            &mut out,
            "ferrum_devices_registered",
            "Devices currently registered with the coordinator.",
            device_count as u64,
        );
        gauge(
            &mut out,
            "ferrum_watch_streams_active",
            "WatchNetworkMap streams currently open.",
            self.watch_streams_active.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_register_total",
            "Total RegisterDevice RPCs handled.",
            self.register_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_rotate_key_total",
            "Total RotateKey RPCs handled.",
            self.rotate_key_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_publish_candidates_total",
            "Total PublishCandidates RPCs handled.",
            self.publish_candidates_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_network_map_requests_total",
            "Total one-shot GetNetworkMap RPCs handled.",
            self.network_map_requests_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_watch_streams_opened_total",
            "Total WatchNetworkMap streams opened.",
            self.watch_streams_opened_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_unauthenticated_total",
            "Total RPCs rejected for failing authentication.",
            self.unauthenticated_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_register_throttled_total",
            "Total RegisterDevice RPCs refused by a rate limit.",
            self.register_throttled_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_relay_heartbeat_throttled_total",
            "Total RelayHeartbeat RPCs refused by a rate limit.",
            self.relay_heartbeat_throttled_total.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "ferrum_watch_streams_rejected_total",
            "Total WatchNetworkMap streams refused by the concurrent-stream quota.",
            self.watch_streams_rejected_total.load(Ordering::Relaxed),
        );
        histogram(
            &mut out,
            "ferrum_request_duration_seconds",
            "Coordinator RPC handler duration in seconds (latency SLI).",
            &self.request_duration,
        );
        out
    }
}

/// RAII timer for an RPC handler: records the elapsed duration into the latency
/// histogram when it drops (covers every return path of the handler).
pub struct RequestTimer {
    metrics: Arc<Metrics>,
    start: Instant,
}

impl Drop for RequestTimer {
    fn drop(&mut self) {
        self.metrics.request_duration.observe(self.start.elapsed());
    }
}

/// RAII guard for an active `WatchNetworkMap` stream: decrements the
/// active-streams gauge when the stream's serving task ends (clean disconnect,
/// broadcast close, or error).
pub struct WatchGuard {
    metrics: Arc<Metrics>,
}

impl Drop for WatchGuard {
    fn drop(&mut self) {
        self.metrics
            .watch_streams_active
            .fetch_sub(1, Ordering::Relaxed);
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

/// Append one `histogram`-typed metric (HELP + TYPE + cumulative `_bucket` lines +
/// `_sum` + `_count`) to the exposition text. Bucket counts are accumulated here
/// because Prometheus buckets are cumulative (`<= le`); the `+Inf` bucket equals
/// the total count.
fn histogram(out: &mut String, name: &str, help: &str, hist: &DurationHistogram) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} histogram\n"));
    let mut cumulative = 0u64;
    for (i, le) in REQUEST_DURATION_BUCKETS_SECONDS.iter().enumerate() {
        cumulative += hist.buckets[i].load(Ordering::Relaxed);
        out.push_str(&format!("{name}_bucket{{le=\"{le}\"}} {cumulative}\n"));
    }
    let count = hist.count.load(Ordering::Relaxed);
    out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {count}\n"));
    let sum_seconds = hist.sum_nanos.load(Ordering::Relaxed) as f64 / 1e9;
    out.push_str(&format!("{name}_sum {sum_seconds}\n{name}_count {count}\n"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_reports_counts_in_prometheus_format() {
        let m = Metrics::new();
        m.inc_register();
        m.inc_register();
        m.inc_rotate_key();
        m.inc_network_map_request();

        let text = m.render(2);
        // Gauge sourced from the registry at scrape time.
        assert!(text.contains("# TYPE ferrum_devices_registered gauge"));
        assert!(text.contains("ferrum_devices_registered 2\n"));
        // Counters reflect the increments.
        assert!(text.contains("# TYPE ferrum_register_total counter"));
        assert!(text.contains("ferrum_register_total 2\n"));
        assert!(text.contains("ferrum_rotate_key_total 1\n"));
        assert!(text.contains("ferrum_network_map_requests_total 1\n"));
        assert!(text.contains("ferrum_publish_candidates_total 0\n"));
    }

    #[test]
    fn throttle_counters_render() {
        let m = Metrics::new();
        m.inc_register_throttled();
        m.inc_register_throttled();
        m.inc_relay_heartbeat_throttled();
        m.inc_watch_stream_rejected();
        let text = m.render(0);
        assert!(text.contains("# TYPE ferrum_register_throttled_total counter"));
        assert!(text.contains("ferrum_register_throttled_total 2\n"));
        assert!(text.contains("ferrum_relay_heartbeat_throttled_total 1\n"));
        assert!(text.contains("ferrum_watch_streams_rejected_total 1\n"));
    }

    #[test]
    fn request_histogram_buckets_are_cumulative() {
        let m = Metrics::new();
        // Three fast (<=1ms) requests, one slow (~200ms, exceeds the 0.1s SLO).
        m.request_duration.observe(Duration::from_micros(400));
        m.request_duration.observe(Duration::from_micros(900));
        m.request_duration.observe(Duration::from_micros(900));
        m.request_duration.observe(Duration::from_millis(200));

        let text = m.render(0);
        assert!(text.contains("# TYPE ferrum_request_duration_seconds histogram"));
        // 0.0005s bucket holds the one 400µs observation.
        assert!(
            text.contains("ferrum_request_duration_seconds_bucket{le=\"0.0005\"} 1\n"),
            "{text}"
        );
        // Cumulative: by le=0.001 all three fast requests are counted.
        assert!(
            text.contains("ferrum_request_duration_seconds_bucket{le=\"0.001\"} 3\n"),
            "{text}"
        );
        // The 200ms request is still excluded at the 0.1s SLO boundary...
        assert!(
            text.contains("ferrum_request_duration_seconds_bucket{le=\"0.1\"} 3\n"),
            "{text}"
        );
        // ...but included by le=0.25 and in +Inf / count.
        assert!(
            text.contains("ferrum_request_duration_seconds_bucket{le=\"0.25\"} 4\n"),
            "{text}"
        );
        assert!(
            text.contains("ferrum_request_duration_seconds_bucket{le=\"+Inf\"} 4\n"),
            "{text}"
        );
        assert!(
            text.contains("ferrum_request_duration_seconds_count 4\n"),
            "{text}"
        );
    }

    #[test]
    fn request_timer_records_on_drop() {
        let m = Metrics::new();
        {
            let _timer = m.start_request();
            // Dropped at end of scope -> one observation recorded.
        }
        assert!(
            m.render(0)
                .contains("ferrum_request_duration_seconds_count 1\n"),
            "timer drop should record exactly one observation"
        );
    }

    #[test]
    fn watch_guard_tracks_active_streams() {
        let m = Metrics::new();
        assert!(m.render(0).contains("ferrum_watch_streams_active 0\n"));

        let g1 = m.watch_started();
        let g2 = m.watch_started();
        assert!(m.render(0).contains("ferrum_watch_streams_active 2\n"));
        assert!(m
            .render(0)
            .contains("ferrum_watch_streams_opened_total 2\n"));

        drop(g1);
        assert!(m.render(0).contains("ferrum_watch_streams_active 1\n"));
        drop(g2);
        assert!(m.render(0).contains("ferrum_watch_streams_active 0\n"));
        // Opened-total is monotonic: it does not decrease when streams end.
        assert!(m
            .render(0)
            .contains("ferrum_watch_streams_opened_total 2\n"));
    }
}
