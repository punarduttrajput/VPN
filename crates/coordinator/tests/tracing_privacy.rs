//! Tracing privacy regression test (PRD Phase 6, FR4 / NFR5).
//!
//! Verifies the coordinator's RPC handlers emit named `tracing` spans and that a
//! device public key never lands in any span or event field. It lives as its own
//! integration-test binary on purpose: `tracing` caches per-callsite interest
//! process-globally, so running this alongside the lib's other tests (which hit
//! the same instrumented handlers under the no-op default subscriber) makes a
//! thread-local `with_default` capture flaky. A dedicated binary is the only
//! exerciser of those callsites, so the capture is deterministic.

use std::sync::{Arc, Mutex};

use ferrum_control_proto::coordinator::coordinator_server::Coordinator;
use ferrum_control_proto::coordinator::{NetworkMapRequest, RegisterDeviceRequest};
use ferrum_coordinator::{CoordinatorService, Registry};
use tonic::Request;
use tracing_subscriber::layer::SubscriberExt;

/// A minimal tracing layer recording span names + event field values into a
/// shared buffer, so the test can assert spans fire *and* that no sensitive value
/// (a device public key) ever appears in a trace.
#[derive(Clone, Default)]
struct CaptureLayer {
    lines: Arc<Mutex<Vec<String>>>,
}

struct FieldCollector<'a>(&'a mut Vec<String>);
impl tracing::field::Visit for FieldCollector<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push(format!("{}={}", field.name(), value));
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push(format!("{}={:?}", field.name(), value));
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut lines = self.lines.lock().unwrap();
        lines.push(format!("span:{}", attrs.metadata().name()));
        let mut c = FieldCollector(&mut lines);
        attrs.record(&mut c);
    }
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut lines = self.lines.lock().unwrap();
        lines.push(format!("event:{}", event.metadata().name()));
        let mut c = FieldCollector(&mut lines);
        event.record(&mut c);
    }
}

/// RPC handlers emit named spans, and no device public key leaks into any
/// span/event field (NFR5). Driven on a current-thread runtime so the
/// thread-local default subscriber applies across the awaited handlers.
#[test]
fn rpc_tracing_spans_emit_without_leaking_keys() {
    let layer = CaptureLayer::default();
    let lines = layer.lines.clone();
    let subscriber = tracing_subscriber::registry().with(layer);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    tracing::subscriber::with_default(subscriber, || {
        rt.block_on(async {
            let registry = Arc::new(Mutex::new(Registry::new(
                std::net::Ipv4Addr::new(10, 8, 0, 0),
                24,
            )));
            let svc = CoordinatorService::new(registry);
            svc.register_device(Request::new(RegisterDeviceRequest {
                public_key: "SECRET_DEVICE_KEY".into(),
                name: "node".into(),
                endpoint: "1.1.1.1:51820".into(),
                tags: vec![],
                ..Default::default()
            }))
            .await
            .unwrap();
            svc.get_network_map(Request::new(NetworkMapRequest {
                public_key: "SECRET_DEVICE_KEY".into(),
            }))
            .await
            .unwrap();
        });
    });

    let captured = lines.lock().unwrap().join("\n");
    assert!(captured.contains("span:register_device"), "{captured}");
    assert!(captured.contains("span:get_network_map"), "{captured}");
    assert!(
        !captured.contains("SECRET_DEVICE_KEY"),
        "a device public key leaked into a trace: {captured}"
    );
}
