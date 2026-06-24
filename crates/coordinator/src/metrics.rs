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
        out
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
