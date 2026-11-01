//! Operational telemetry for the local proxy, API, and notary services.
//!
//! This module intentionally records metadata only. Never add HTTP headers,
//! request or response bodies, credentials, presigned URLs, or checkpoint paths to
//! a metric, span, or production log field.

use std::{env, sync::OnceLock, time::Duration};

use anyhow::Result;
use metrics::{describe_counter, describe_gauge, describe_histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use opentelemetry::{KeyValue, global, trace::TracerProvider as _};
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::{Resource, propagation::TraceContextPropagator, trace::SdkTracerProvider};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

static METRICS: OnceLock<PrometheusHandle> = OnceLock::new();

/// Holds the exporter open for the lifetime of the process and flushes it when
/// the process exits normally.
pub struct Telemetry {
    tracer_provider: Option<SdkTracerProvider>,
}

impl Drop for Telemetry {
    fn drop(&mut self) {
        if let Some(provider) = &self.tracer_provider {
            let _ = provider.shutdown_with_timeout(Duration::from_secs(5));
        }
    }
}

/// Installs JSON logging, a Prometheus metrics recorder, and—when a standard
/// OTLP trace endpoint is configured—an OTLP tracing layer.
pub fn init(service_name: &'static str) -> Result<Telemetry> {
    let service_name = env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| service_name.to_owned());
    let handle = PrometheusBuilder::new()
        .add_global_label("service", service_name.clone())
        .install_recorder()?;
    METRICS
        .set(handle)
        .map_err(|_| anyhow::anyhow!("metrics recorder was already initialized"))?;
    describe_metrics();

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info"));
    let fmt = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .with_writer(std::io::stderr);
    global::set_text_map_propagator(TraceContextPropagator::new());

    let tracer_provider = if otlp_traces_enabled() {
        let exporter = SpanExporter::builder().with_http().build()?;
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(
                Resource::builder()
                    .with_attributes([
                        KeyValue::new("service.name", service_name.clone()),
                        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                    ])
                    .build(),
            )
            .build();
        let tracer = provider.tracer(service_name.clone());
        global::set_tracer_provider(provider.clone());
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt)
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .init();
        Some(provider)
    } else {
        tracing_subscriber::registry().with(filter).with(fmt).init();
        None
    };

    tracing::info!(
        service = %service_name,
        otlp_traces = tracer_provider.is_some(),
        "operational telemetry initialized"
    );
    Ok(Telemetry { tracer_provider })
}

/// Renders the registered process metrics in Prometheus' text exposition
/// format. This is deliberately served only on internal service ports.
pub fn prometheus_metrics() -> String {
    METRICS
        .get()
        .map(PrometheusHandle::render)
        .unwrap_or_default()
}

fn otlp_traces_enabled() -> bool {
    env::var_os("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_some()
        || env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_some()
}

fn describe_metrics() {
    describe_gauge!(
        "capture_notary_active_sessions",
        "Currently active notary protocol sessions"
    );
    describe_gauge!(
        "capture_notary_pending_connections",
        "Sockets awaiting a valid notary protocol prelude"
    );
    describe_counter!(
        "capture_notary_sessions_total",
        "Notary protocol sessions by mode and outcome"
    );
    describe_histogram!(
        "capture_notary_session_duration_seconds",
        "Notary protocol session duration by mode and outcome"
    );
}
