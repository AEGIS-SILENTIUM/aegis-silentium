"""
AEGIS-SILENTIUM — Prometheus Metrics
=====================================
Exposes a /metrics endpoint compatible with Prometheus scraping.

Counters & gauges tracked:
  aegis_http_requests_total          {method, path, status}
  aegis_http_request_duration_ms     {method, path}  — histogram
  aegis_active_nodes                 Gauge
  aegis_tasks_total                  {status}
  aegis_vulns_total                  {severity}
  aegis_events_total                 {kind, severity}
  aegis_auth_attempts_total          {result}  — ok / fail
  aegis_payload_builds_total         {status}
  aegis_chat_messages_total          {channel}
  aegis_db_pool_connections          {state}  — active / idle / wait
  aegis_beacon_requests_total        Gauge
  aegis_sse_clients                  Gauge
  aegis_listener_status              {name, type, status}  — 1/0
  aegis_exploit_deployments_total

This module is a pure-Python Prometheus client (no prometheus_client
library required) that formats the /metrics text exposition correctly.

If you prefer prometheus_client, replace MetricsRegistry with
prometheus_client.start_http_server and use Counter/Gauge directly.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any, Optional

_lock = threading.Lock()


class Counter:
    """Thread-safe monotonically increasing counter."""

    def __init__(self, name: str, help_text: str, label_names: list[str]) -> None:
        self.name        = name
        self.help_text   = help_text
        self.label_names = label_names
        self._data: dict[tuple, float] = defaultdict(float)

    def inc(self, labels: dict, amount: float = 1.0) -> None:
        key = tuple(labels.get(k, "") for k in self.label_names)
        with _lock:
            self._data[key] += amount

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} counter",
        ]
        with _lock:
            for key, val in self._data.items():
                label_str = ",".join(
                    f'{n}="{v}"'
                    for n, v in zip(self.label_names, key)
                )
                suffix = "{" + label_str + "}" if label_str else ""
                lines.append(f"{self.name}{suffix} {val}")
        return "\n".join(lines)


class Gauge:
    """Thread-safe gauge (can go up and down)."""

    def __init__(self, name: str, help_text: str, label_names: list[str] = None) -> None:
        self.name        = name
        self.help_text   = help_text
        self.label_names = label_names or []
        self._data: dict[tuple, float] = defaultdict(float)

    def set(self, value: float, labels: dict = None) -> None:
        key = tuple((labels or {}).get(k, "") for k in self.label_names)
        with _lock:
            self._data[key] = value

    def inc(self, labels: dict = None, amount: float = 1.0) -> None:
        key = tuple((labels or {}).get(k, "") for k in self.label_names)
        with _lock:
            self._data[key] += amount

    def dec(self, labels: dict = None, amount: float = 1.0) -> None:
        self.inc(labels, -amount)

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} gauge",
        ]
        with _lock:
            for key, val in self._data.items():
                label_str = ",".join(
                    f'{n}="{v}"' for n, v in zip(self.label_names, key)
                )
                suffix = "{" + label_str + "}" if label_str else ""
                lines.append(f"{self.name}{suffix} {val}")
        return "\n".join(lines)


class Histogram:
    """
    Simple fixed-bucket histogram.
    Buckets are defined at creation time (in milliseconds).
    """

    DEFAULT_BUCKETS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, float("inf")]

    def __init__(
        self,
        name:       str,
        help_text:  str,
        label_names: list[str],
        buckets:    list[float] = None,
    ) -> None:
        self.name        = name
        self.help_text   = help_text
        self.label_names = label_names
        self.buckets     = sorted(buckets or self.DEFAULT_BUCKETS)
        self._counts:  dict[tuple, list[int]]  = {}
        self._sums:    dict[tuple, float]       = defaultdict(float)
        self._totals:  dict[tuple, int]         = defaultdict(int)

    def observe(self, value: float, labels: dict) -> None:
        key = tuple(labels.get(k, "") for k in self.label_names)
        with _lock:
            if key not in self._counts:
                self._counts[key] = [0] * len(self.buckets)
            for i, b in enumerate(self.buckets):
                if value <= b:
                    self._counts[key][i] += 1
            self._sums[key]   += value
            self._totals[key] += 1

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} histogram",
        ]
        with _lock:
            for key in self._counts:
                label_base = ",".join(
                    f'{n}="{v}"' for n, v in zip(self.label_names, key)
                )
                for i, b in enumerate(self.buckets):
                    le     = "+Inf" if b == float("inf") else str(b)
                    lstr   = (label_base + "," if label_base else "") + f'le="{le}"'
                    lines.append(f"{self.name}_bucket{{{lstr}}} {self._counts[key][i]}")
                pfx = "{" + label_base + "}" if label_base else ""
                lines.append(f"{self.name}_sum{pfx} {self._sums[key]:.3f}")
                lines.append(f"{self.name}_count{pfx} {self._totals[key]}")
        return "\n".join(lines)


# ── Registry & global instances ───────────────────────────────────────────────

class MetricsRegistry:
    def __init__(self) -> None:
        self._collectors: list[Any] = []

    def register(self, collector: Any) -> Any:
        self._collectors.append(collector)
        return collector

    def render_all(self) -> str:
        return "\n\n".join(c.render() for c in self._collectors) + "\n"


REGISTRY = MetricsRegistry()

# ── Metric definitions ────────────────────────────────────────────────────────

http_requests_total = REGISTRY.register(Counter(
    "aegis_http_requests_total",
    "Total HTTP requests handled",
    ["method", "path", "status"],
))

http_request_duration_ms = REGISTRY.register(Histogram(
    "aegis_http_request_duration_ms",
    "HTTP request latency in milliseconds",
    ["method", "path"],
))

active_nodes = REGISTRY.register(Gauge(
    "aegis_active_nodes",
    "Number of active nodes (beaconed within 5 minutes)",
))

tasks_total = REGISTRY.register(Gauge(
    "aegis_tasks_total",
    "Task counts by status",
    ["status"],
))

vulns_total = REGISTRY.register(Gauge(
    "aegis_vulns_total",
    "Vulnerability counts by severity",
    ["severity"],
))

events_published = REGISTRY.register(Counter(
    "aegis_events_total",
    "SSE events emitted",
    ["kind", "severity"],
))

auth_attempts_total = REGISTRY.register(Counter(
    "aegis_auth_attempts_total",
    "Authentication attempts",
    ["result"],
))

payload_builds_total = REGISTRY.register(Counter(
    "aegis_payload_builds_total",
    "Payload builds by status",
    ["payload_type"],
))

chat_messages_total = REGISTRY.register(Counter(
    "aegis_chat_messages_total",
    "Chat messages posted by channel",
    ["channel"],
))

db_pool_wait = REGISTRY.register(Gauge(
    "aegis_db_pool_wait",
    "Requests waiting for a DB connection",
))

sse_clients = REGISTRY.register(Gauge(
    "aegis_sse_clients",
    "Currently connected SSE clients",
))

beacon_requests_total = REGISTRY.register(Counter(
    "aegis_beacon_requests_total",
    "Beacon HTTP requests received",
    ["method"],
))

listener_status = REGISTRY.register(Gauge(
    "aegis_listener_status",
    "1 if listener is running, 0 otherwise",
    ["name", "type"],
))

exploit_deployments_total = REGISTRY.register(Counter(
    "aegis_exploit_deployments_total",
    "Exploits deployed",
    ["severity"],
))

rate_limited_total = REGISTRY.register(Counter(
    "aegis_rate_limited_total",
    "Requests rate-limited by operator or IP",
    ["scope"],
))

circuit_breaker_trips = REGISTRY.register(Counter(
    "aegis_circuit_breaker_trips_total",
    "Circuit breaker trip events",
    ["service"],
))

# Build info (static metadata)
build_info = REGISTRY.register(Gauge(
    "aegis_build_info",
    "Static build information",
    ["version", "python"],
))

import sys as _sys
build_info.set(1, {"version": "9.0", "python": _sys.version.split()[0]})

__all__ = [
    "REGISTRY",
    "http_requests_total", "http_request_duration_ms",
    "active_nodes", "tasks_total", "vulns_total",
    "events_published", "auth_attempts_total",
    "payload_builds_total", "chat_messages_total",
    "db_pool_wait", "sse_clients", "beacon_requests_total",
    "listener_status", "exploit_deployments_total",
    "rate_limited_total", "circuit_breaker_trips",
]
