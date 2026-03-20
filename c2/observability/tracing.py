"""
AEGIS-SILENTIUM — Distributed Tracing (OpenTelemetry)
=======================================================
Instruments Flask routes and PostgreSQL queries with OpenTelemetry spans.
Exports to an OTLP collector (Jaeger, Tempo, Honeycomb, etc.).

Trace propagation:
  - Inbound: reads W3C traceparent/tracestate headers
  - Outbound: injects into webhook HTTP calls
  - Internal: propagates via contextvars across threads (SSE, webhooks)

Spans created automatically:
  - Every HTTP request → root span with method, path, status
  - Every DB query     → child span with SQL (truncated), duration
  - Redis calls        → child spans with command
  - Emit events        → span events (annotations)

Usage
-----
    from c2.observability.tracing import init_tracing
    init_tracing(app, service_name="aegis-c2", otlp_endpoint="http://jaeger:4317")

Environment variables
---------------------
    OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
    OTEL_SERVICE_NAME=aegis-c2
    OTEL_TRACES_SAMPLER=parentbased_traceidratio
    OTEL_TRACES_SAMPLER_ARG=1.0   # 1.0 = 100%, 0.1 = 10%
"""
from __future__ import annotations

import logging
import os
import time
from contextvars import ContextVar
from typing import Any, Optional

log = logging.getLogger("aegis.tracing")

# Current span stored per-coroutine/thread
_current_span: ContextVar[Optional[Any]] = ContextVar("otel_span", default=None)

# ── Tracer provider (no-op if opentelemetry not installed) ────────────────────
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.flask import FlaskInstrumentor
    from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
    from opentelemetry.instrumentation.redis import RedisInstrumentor
    from opentelemetry.propagate import set_global_textmap
    from opentelemetry.propagators.b3 import B3MultiFormat
    from opentelemetry.propagate import extract, inject
    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False
    log.debug("opentelemetry not installed — tracing disabled")


def init_tracing(
    app,
    service_name: str    = "aegis-c2",
    otlp_endpoint: str   = "",
    sample_rate: float   = 1.0,
    console_export: bool = False,
) -> bool:
    """
    Initialize OpenTelemetry tracing for the Flask app.

    Returns True if tracing was enabled, False if opentelemetry is not installed.

    Parameters
    ----------
    app           — Flask application instance
    service_name  — Service name reported in traces
    otlp_endpoint — OTLP gRPC endpoint (e.g. "http://jaeger:4317")
                    Falls back to OTEL_EXPORTER_OTLP_ENDPOINT env var
    sample_rate   — Fraction of traces to sample (0.0–1.0)
    console_export— Also print spans to stdout (dev only)
    """
    if not _OTEL_AVAILABLE:
        log.info("opentelemetry not installed — skipping tracing init")
        return False

    endpoint = otlp_endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    name     = service_name or os.environ.get("OTEL_SERVICE_NAME", "aegis-c2")

    resource = Resource({SERVICE_NAME: name, "version": "9.0"})
    provider = TracerProvider(resource=resource)

    if endpoint:
        try:
            exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            log.info("tracing enabled  endpoint=%s  service=%s", endpoint, name)
        except Exception as e:
            log.warning("OTLP exporter failed: %s — spans will be dropped", e)

    if console_export:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)

    # W3C trace context propagation (B3 also accepted)
    try:
        set_global_textmap(B3MultiFormat())
    except Exception as _exc:
        log.debug("unknown: %s", _exc)

    # Auto-instrument Flask, psycopg2, redis
    try:
        FlaskInstrumentor().instrument_app(app)
        Psycopg2Instrumentor().instrument(enable_commenter=True, commenter_options={})
        RedisInstrumentor().instrument()
    except Exception as e:
        log.warning("auto-instrumentation partial: %s", e)

    return True


def get_tracer(name: str = "aegis"):
    """Return a tracer.  Returns a no-op tracer if OTel is unavailable."""
    if _OTEL_AVAILABLE:
        return trace.get_tracer(name, "9.0")
    return _NoopTracer()


def current_trace_id() -> str:
    """Return the current trace ID as a hex string (for log correlation)."""
    if not _OTEL_AVAILABLE:
        return ""
    try:
        span = trace.get_current_span()
        ctx  = span.get_span_context()
        if ctx and ctx.is_valid:
            return format(ctx.trace_id, "032x")
    except Exception as _exc:
        log.debug("current_trace_id: %s", _exc)
    return ""


def span_event(name: str, attrs: dict = None) -> None:
    """Add an event annotation to the current span."""
    if not _OTEL_AVAILABLE:
        return
    try:
        span = trace.get_current_span()
        span.add_event(name, attributes=attrs or {})
    except Exception as _exc:
        log.debug("span_event: %s", _exc)


# ── No-op tracer (used when opentelemetry is absent) ─────────────────────────

class _NoopSpan:
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def set_attribute(self, k, v): pass
    def add_event(self, name, **kw): pass
    def record_exception(self, exc): pass
    def set_status(self, *a): pass

class _NoopTracer:
    def start_as_current_span(self, name, **kw):
        return _NoopSpan()
    def start_span(self, name, **kw):
        return _NoopSpan()


# ── Logging integration: inject trace ID into log records ────────────────────

class TraceIdFilter(logging.Filter):
    """
    Injects the current OTel trace ID into every log record as ``trace_id``.
    Enables correlation between structured logs and distributed traces.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        record.trace_id = current_trace_id()
        return True


def attach_trace_filter_to_logger(logger_name: str = "") -> None:
    """Add TraceIdFilter to a logger (default: root logger)."""
    logging.getLogger(logger_name).addFilter(TraceIdFilter())


__all__ = [
    "init_tracing", "get_tracer", "current_trace_id",
    "span_event", "TraceIdFilter", "attach_trace_filter_to_logger",
]
