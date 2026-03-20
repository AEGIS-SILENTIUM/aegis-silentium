"""
c2/distributed/dead_letter.py
AEGIS-SILENTIUM v12 — Dead Letter Queue (DLQ)

Failed tasks and webhook deliveries that exceed their retry budget are
moved to the DLQ instead of being silently dropped.  Operators can
inspect, replay, or discard DLQ entries via the admin API.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("aegis.dlq")


@dataclass
class DLQEntry:
    entry_id:   str   = field(default_factory=lambda: str(uuid.uuid4()))
    source:     str   = ""       # "webhook" | "task" | "sync" | ...
    payload:    Any   = None
    reason:     str   = ""
    attempts:   int   = 0
    first_fail: float = field(default_factory=time.time)
    last_fail:  float = field(default_factory=time.time)
    resolved:   bool  = False

    def to_dict(self) -> dict:
        return {
            "entry_id":   self.entry_id,
            "source":     self.source,
            "payload":    self.payload,
            "reason":     self.reason,
            "attempts":   self.attempts,
            "first_fail": self.first_fail,
            "last_fail":  self.last_fail,
            "resolved":   self.resolved,
        }


class DeadLetterQueue:
    """
    In-memory DLQ with optional persistence callback.

    Parameters
    ----------
    persist_fn : optional callable(DLQEntry) to persist to DB
    max_size   : maximum DLQ size before oldest entries are evicted
    """

    def __init__(
        self,
        persist_fn: Optional[Callable[[DLQEntry], None]] = None,
        max_size:   int = 10_000,
    ) -> None:
        self._entries:   Dict[str, DLQEntry] = {}
        self._persist    = persist_fn
        self._max_size   = max_size
        self._lock       = threading.Lock()
        self._stats      = {"total_received": 0, "total_resolved": 0, "total_replayed": 0}

    def push(self, source: str, payload: Any, reason: str, attempts: int = 1) -> DLQEntry:
        entry = DLQEntry(source=source, payload=payload, reason=reason, attempts=attempts)
        with self._lock:
            if len(self._entries) >= self._max_size:
                oldest = min(self._entries.values(), key=lambda e: e.first_fail)
                del self._entries[oldest.entry_id]
                log.warning("DLQ full — evicted oldest entry %s", oldest.entry_id)
            self._entries[entry.entry_id] = entry
            self._stats["total_received"] += 1
        if self._persist:
            try:
                self._persist(entry)
            except Exception as exc:
                log.warning("DLQ persist failed: %s", exc)
        log.warning("DLQ: %s entry %s reason='%s'", source, entry.entry_id, reason)
        return entry

    def resolve(self, entry_id: str) -> bool:
        with self._lock:
            entry = self._entries.get(entry_id)
            if entry:
                entry.resolved = True
                self._stats["total_resolved"] += 1
                return True
            return False

    def replay(self, entry_id: str, replay_fn: Callable[[DLQEntry], bool]) -> bool:
        with self._lock:
            entry = self._entries.get(entry_id)
        if not entry:
            return False
        try:
            success = replay_fn(entry)
            if success:
                self.resolve(entry_id)
                with self._lock:
                    self._stats["total_replayed"] += 1
            return success
        except Exception as exc:
            log.error("DLQ replay failed entry=%s: %s", entry_id, exc)
            return False

    def list_entries(
        self,
        source:   Optional[str] = None,
        resolved: Optional[bool] = None,
        limit:    int = 100,
    ) -> List[DLQEntry]:
        with self._lock:
            entries = list(self._entries.values())
        if source is not None:
            entries = [e for e in entries if e.source == source]
        if resolved is not None:
            entries = [e for e in entries if e.resolved == resolved]
        return sorted(entries, key=lambda e: e.last_fail, reverse=True)[:limit]

    def stats(self) -> dict:
        with self._lock:
            unresolved = sum(1 for e in self._entries.values() if not e.resolved)
            return {**self._stats, "current_depth": unresolved}


# ── Adaptive Load Balancer ────────────────────────────────────────────────────

"""
c2/distributed/load_balancer.py (appended to dead_letter.py for brevity)
AEGIS-SILENTIUM v10 — Adaptive Load Balancer

Selects backend C2 nodes using:
  - Weighted Round Robin (static weights)
  - Least Connections (dynamic — prefer least loaded)
  - Latency-aware P2C (Power of Two Choices with latency weights)
  - Health-aware: removes unhealthy backends automatically
"""

import statistics


class Backend:
    """Represents one C2 backend node."""

    def __init__(self, node_id: str, address: str, weight: int = 1) -> None:
        self.node_id      = node_id
        self.address      = address
        self.weight       = weight
        self.active_conns = 0
        self.total_reqs   = 0
        self.errors       = 0
        self.healthy      = True
        self._latencies: List[float] = []
        self._lock        = threading.Lock()

    def record_latency(self, latency_ms: float) -> None:
        with self._lock:
            self._latencies.append(latency_ms)
            if len(self._latencies) > 100:
                self._latencies.pop(0)

    def p95_latency(self) -> float:
        with self._lock:
            if not self._latencies:
                return 0.0
            return sorted(self._latencies)[int(len(self._latencies) * 0.95)]

    def to_dict(self) -> dict:
        return {
            "node_id":      self.node_id,
            "address":      self.address,
            "healthy":      self.healthy,
            "active_conns": self.active_conns,
            "total_reqs":   self.total_reqs,
            "errors":       self.errors,
            "p95_latency":  self.p95_latency(),
        }


class AdaptiveLoadBalancer:
    """
    Adaptive load balancer supporting multiple selection strategies.

    Strategies
    ----------
    "round_robin"       – weighted round robin
    "least_connections" – route to node with fewest active connections
    "p2c"               – power-of-two-choices based on p95 latency
    """

    def __init__(self, strategy: str = "least_connections") -> None:
        self._strategy  = strategy
        self._backends: List[Backend] = []
        self._rr_index  = 0
        self._lock      = threading.Lock()

    def add_backend(self, backend: Backend) -> None:
        with self._lock:
            self._backends.append(backend)

    def remove_backend(self, node_id: str) -> None:
        with self._lock:
            self._backends = [b for b in self._backends if b.node_id != node_id]

    def mark_unhealthy(self, node_id: str) -> None:
        with self._lock:
            for b in self._backends:
                if b.node_id == node_id:
                    b.healthy = False

    def mark_healthy(self, node_id: str) -> None:
        with self._lock:
            for b in self._backends:
                if b.node_id == node_id:
                    b.healthy = True

    def select(self) -> Optional[Backend]:
        with self._lock:
            healthy = [b for b in self._backends if b.healthy]
        if not healthy:
            return None
        if self._strategy == "round_robin":
            return self._round_robin(healthy)
        if self._strategy == "least_connections":
            return min(healthy, key=lambda b: b.active_conns)
        if self._strategy == "p2c":
            return self._p2c(healthy)
        return healthy[0]

    def record_request(self, node_id: str, latency_ms: float, error: bool = False) -> None:
        with self._lock:
            for b in self._backends:
                if b.node_id == node_id:
                    b.active_conns = max(0, b.active_conns - 1)
                    b.total_reqs  += 1
                    if error:
                        b.errors += 1
                    b.record_latency(latency_ms)
                    break

    def stats(self) -> List[dict]:
        with self._lock:
            return [b.to_dict() for b in self._backends]

    def _round_robin(self, healthy: List[Backend]) -> Backend:
        with self._lock:
            b = healthy[self._rr_index % len(healthy)]
            self._rr_index += 1
            b.active_conns += 1
        return b

    def _p2c(self, healthy: List[Backend]) -> Backend:
        if len(healthy) < 2:
            return healthy[0]
        a, b = random.sample(healthy, 2)
        chosen = a if a.p95_latency() <= b.p95_latency() else b
        chosen.active_conns += 1
        return chosen
