"""
AEGIS-SILENTIUM — Circuit Breaker
===================================
Implements the classic three-state circuit breaker pattern:

  CLOSED  → calls pass through normally
  OPEN    → calls fail immediately (fast-fail) after trip threshold
  HALF_OPEN → probe call allowed; success → CLOSED, failure → OPEN

Usage
-----
    from c2.resilience.circuit_breaker import CircuitBreaker

    redis_cb = CircuitBreaker("redis", failure_threshold=5, recovery_timeout=30)

    try:
        with redis_cb:
            result = redis_client.get("key")
    except CircuitOpenError:
        # Fast-fail path — use cached value / degrade gracefully
        result = None

Also usable as a decorator::

    @redis_cb.protect
    def read_from_redis(key):
        return redis_client.get(key)

Design decisions
----------------
* State is stored in memory (per-process).  In multi-process deployments
  each process has its own breaker state.  Cross-process coordination
  requires Redis — not added here to keep this module zero-dependency.
* Thread-safe via threading.Lock.
* All state transitions are logged at appropriate levels.
"""
from __future__ import annotations

import functools
import logging
import threading
import time
from enum import Enum
from typing import Callable, Optional, Type

log = logging.getLogger("aegis.circuit_breaker")


class CircuitState(Enum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when a call is attempted on an OPEN circuit."""

    def __init__(self, service: str, retry_after: float) -> None:
        self.service     = service
        self.retry_after = retry_after
        super().__init__(
            f"Circuit '{service}' is OPEN.  "
            f"Retry after {retry_after:.0f}s."
        )


class CircuitBreaker:
    """
    Thread-safe circuit breaker.

    Parameters
    ----------
    name              — Human-readable name (used in logs and metrics)
    failure_threshold — Consecutive failures before tripping (default 5)
    recovery_timeout  — Seconds to wait before attempting a probe (default 30)
    half_open_probes  — Successful probes needed to close the circuit (default 1)
    expected_errors   — Exception types that count as failures.
                        None → all exceptions count.
    """

    def __init__(
        self,
        name:              str,
        failure_threshold: int = 5,
        recovery_timeout:  float = 30.0,
        half_open_probes:  int = 1,
        expected_errors:   Optional[tuple[Type[Exception], ...]] = None,
    ) -> None:
        self.name              = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout  = recovery_timeout
        self.half_open_probes  = half_open_probes
        self.expected_errors   = expected_errors

        self._state            = CircuitState.CLOSED
        self._failure_count    = 0
        self._success_count    = 0   # in HALF_OPEN
        self._last_failure_at  = 0.0
        self._lock             = threading.Lock()

        # Stats
        self.total_calls       = 0
        self.total_failures    = 0
        self.total_trips       = 0

    # ── Public interface ──────────────────────────────────────────────────────

    @property
    def state(self) -> CircuitState:
        with self._lock:
            return self._get_state_locked()

    def __enter__(self):
        with self._lock:
            state = self._get_state_locked()
            if state == CircuitState.OPEN:
                retry_in = (
                    self._last_failure_at + self.recovery_timeout - time.monotonic()
                )
                raise CircuitOpenError(self.name, max(0.0, retry_in))
            self.total_calls += 1
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        is_failure = (
            exc_type is not None
            and (
                self.expected_errors is None
                or issubclass(exc_type, self.expected_errors)
            )
            and not issubclass(exc_type, CircuitOpenError)
        )
        with self._lock:
            if is_failure:
                self._on_failure_locked()
            else:
                self._on_success_locked()
        return False   # Don't suppress the exception

    def protect(self, fn: Callable) -> Callable:
        """Decorator: wrap a function in this circuit breaker."""
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            with self:
                return fn(*args, **kwargs)
        return wrapper

    def reset(self) -> None:
        """Manually close the circuit (e.g. after infrastructure fix)."""
        with self._lock:
            self._state         = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
        log.info("circuit_breaker reset  name=%s", self.name)

    @property
    def info(self) -> dict:
        with self._lock:
            return {
                "name":            self.name,
                "state":           self._get_state_locked().value,
                "failure_count":   self._failure_count,
                "total_calls":     self.total_calls,
                "total_failures":  self.total_failures,
                "total_trips":     self.total_trips,
            }

    # ── State transitions ─────────────────────────────────────────────────────

    def _get_state_locked(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._last_failure_at >= self.recovery_timeout:
                log.info("circuit_breaker probe  name=%s  → HALF_OPEN", self.name)
                self._state         = CircuitState.HALF_OPEN
                self._success_count = 0
        return self._state

    def _on_failure_locked(self) -> None:
        self._failure_count   += 1
        self._success_count    = 0
        self.total_failures   += 1
        self._last_failure_at  = time.monotonic()

        if self._state == CircuitState.HALF_OPEN or \
                self._failure_count >= self.failure_threshold:
            self._trip_locked()

    def _on_success_locked(self) -> None:
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.half_open_probes:
                self._close_locked()
        else:
            self._failure_count = 0

    def _trip_locked(self) -> None:
        self._state         = CircuitState.OPEN
        self._failure_count = 0
        self.total_trips   += 1
        log.error(
            "circuit_breaker TRIPPED  name=%s  failures=%d  → OPEN",
            self.name, self.total_failures,
        )
        # Publish to metrics if available
        try:
            from c2.observability.metrics import circuit_breaker_trips
            circuit_breaker_trips.inc({"service": self.name})
        except ImportError:
            pass

    def _close_locked(self) -> None:
        self._state         = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        log.info("circuit_breaker CLOSED  name=%s  probes=%d", self.name, self.half_open_probes)


# ── Global breakers for shared services ──────────────────────────────────────

redis_breaker    = CircuitBreaker("redis",    failure_threshold=3, recovery_timeout=15)
postgres_breaker = CircuitBreaker("postgres", failure_threshold=3, recovery_timeout=20)
nvd_breaker      = CircuitBreaker("nvd_api",  failure_threshold=2, recovery_timeout=60)

__all__ = [
    "CircuitBreaker", "CircuitOpenError", "CircuitState",
    "redis_breaker", "postgres_breaker", "nvd_breaker",
]
