//! Tracing / telemetry initialization (PRD Phase 6, FR4 / NFR5).
//!
//! Always installs an env-filtered `fmt` subscriber (stderr logs). When the
//! `otlp` feature is built **and** an endpoint is supplied, it *also* exports the
//! coordinator's existing `#[tracing::instrument(skip_all)]` RPC-handler spans to
//! an OpenTelemetry collector over OTLP/gRPC (default `:4317`).
//!
//! **Privacy boundary (NFR5):** the handler spans are `skip_all`, so only span
//! *names* and *timing* cross the wire — never a device public key, tunnel IP,
//! endpoint, or tag. The same property the `tracing_privacy` test guards for the
//! local subscriber holds for the exported spans, because it is the *same* spans
//! that are exported. Do not add request fields to those spans.

#[cfg(feature = "otlp")]
use tracing_subscriber::layer::SubscriberExt;
#[cfg(feature = "otlp")]
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Guard returned by [`init`]. Keep it alive for the whole process: on drop it
/// flushes and shuts the OTLP exporter down so buffered spans aren't lost on exit.
/// Without the `otlp` feature (or without an endpoint) it is inert.
#[derive(Default)]
pub struct TelemetryGuard {
    #[cfg(feature = "otlp")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

#[cfg(feature = "otlp")]
impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            // Flush buffered spans to the collector before the process exits.
            let _ = provider.shutdown();
        }
    }
}

/// `RUST_LOG`-driven filter, defaulting to `info` like the rest of the binaries.
fn env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

/// Install only the env-filtered `fmt` subscriber (stderr logs, no export).
fn init_fmt_only() {
    tracing_subscriber::fmt()
        .with_env_filter(env_filter())
        .init();
}

/// Initialize tracing for `service_name`.
///
/// With the `otlp` feature and `otlp_endpoint = Some(url)`, spans are exported to
/// that collector *and* still logged to stderr. Otherwise only the `fmt`
/// subscriber is installed (a warning is logged if an endpoint was requested
/// without the feature, so the operator isn't left wondering why nothing exports).
pub fn init(otlp_endpoint: Option<&str>, service_name: &'static str) -> TelemetryGuard {
    #[cfg(feature = "otlp")]
    if let Some(endpoint) = otlp_endpoint {
        match init_otlp(endpoint, service_name) {
            Ok(guard) => return guard,
            Err(e) => {
                // Never fail to boot over telemetry: fall back to stderr-only.
                init_fmt_only();
                tracing::error!(error = %e, endpoint, "OTLP exporter init failed; logging to stderr only");
                return TelemetryGuard::default();
            }
        }
    }

    #[cfg(not(feature = "otlp"))]
    if otlp_endpoint.is_some() {
        init_fmt_only();
        tracing::warn!(
            "--otlp-endpoint was set but this binary was built without the `otlp` feature; ignoring"
        );
        return TelemetryGuard::default();
    }

    let _ = service_name;
    init_fmt_only();
    TelemetryGuard::default()
}

/// Build the OTLP/gRPC span exporter, wire it into a batch tracer provider, and
/// install a layered subscriber (env filter + stderr `fmt` + OTLP export).
#[cfg(feature = "otlp")]
fn init_otlp(
    endpoint: &str,
    service_name: &'static str,
) -> Result<TelemetryGuard, Box<dyn std::error::Error + Send + Sync>> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use opentelemetry_sdk::Resource;

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    let resource = Resource::builder().with_service_name(service_name).build();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();

    let tracer = provider.tracer(service_name);
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(env_filter())
        .with(tracing_subscriber::fmt::layer())
        .with(otel_layer)
        .init();

    tracing::info!(endpoint, service = service_name, "OTLP span export enabled");
    Ok(TelemetryGuard {
        provider: Some(provider),
    })
}
