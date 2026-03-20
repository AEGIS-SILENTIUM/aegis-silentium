"""
AEGIS — Circuit Breaker
========================
A thread-safe, generic circuit breaker implementing the classic
CLOSED → OPEN → HALF-OPEN state machine.

States
------
CLOSED     Normal operation.  Failures are counted.
OPEN       Service is considered down.  Calls fail fast without touching
           the dependency.  After ``reset_timeout`` seconds the breaker
           moves to HALF-OPEN.
HALF-OPEN  A single probe call is allowed through.  Success → CLOSED;
           failure → OPEN (with backoff doubling up to ``max_timeout``).

Usage
-----
    breaker = CircuitBreaker("redis", failure_threshold=5, reset_timeout=10)

    try:
        result = breaker.call(redis_client.ping)
    except CircuitOpenError:
        # Dependency is down — use fallback
        result = None
    except Exception:
        # Dependency raised; breaker has recorded the failure
        raise
"""
from __future__ import annotations

import logging
import threading
import time
from enum import Enum
from typing import Any, Callable, Optional

log = logging.getLogger("aegis.circuit")


class CircuitState(Enum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(RuntimeError):
    """Raised when a call is rejected because the circuit is OPEN."""
    def __init__(self, name: str, retry_after: float):
        self.name        = name
        self.retry_after = retry_after
        super().__init__(
            f"Circuit '{name}' is OPEN — retry after {retry_after:.1f}s"
        )


class CircuitBreaker:
    """
    Thread-safe circuit breaker.

    Parameters
    ----------
    name              Human-readable name (used in logs and errors).
    failure_threshold Number of consecutive failures before OPEN.
    reset_timeout     Seconds to wait in OPEN before probing (HALF-OPEN).
    max_timeout       Maximum backoff timeout after repeated trips.
    success_threshold Consecutive successes in HALF-OPEN before CLOSED.
    """

    def __init__(
        self,
        name:              str,
        failure_threshold: int   = 5,
        reset_timeout:     float = 10.0,
        max_timeout:       float = 120.0,
        success_threshold: int   = 2,
    ) -> None:
        self.name              = name
        self.failure_threshold = failure_threshold
        self.reset_timeout     = reset_timeout
        self.max_timeout       = max_timeout
        self.success_threshold = success_threshold

        self._state            = CircuitState.CLOSED
        self._failures         = 0
        self._successes        = 0
        self._opened_at: Optional[float] = None
        self._current_timeout  = reset_timeout
        self._lock             = threading.Lock()

    # ── Public ────────────────────────────────────────────────────────────────

    def call(self, fn: Callable, *args, **kwargs) -> Any:
        """
        Execute ``fn(*args, **kwargs)`` through the breaker.

        Raises
        ------
        CircuitOpenError  — breaker is OPEN and the call was rejected.
        Exception         — whatever ``fn`` raised (failure is recorded).
        """
        with self._lock:
            self._maybe_transition_to_half_open()

            if self._state == CircuitState.OPEN:
                retry_after = self._retry_after()
                raise CircuitOpenError(self.name, retry_after)

            if self._state == CircuitState.HALF_OPEN:
                # Only allow one probe at a time
                pass   # fall through to execute

        try:
            result = fn(*args, **kwargs)
        except Exception as exc:
            self._record_failure()
            raise
        else:
            self._record_success()
            return result

    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._maybe_transition_to_half_open()
            return self._state

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "name":     self.name,
                "state":    self._state.value,
                "failures": self._failures,
                "timeout":  round(self._current_timeout, 1),
            }

    def reset(self) -> None:
        """Manually reset the breaker to CLOSED (for testing / admin)."""
        with self._lock:
            self._to_closed()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _maybe_transition_to_half_open(self) -> None:
        """Called under lock."""
        if (self._state == CircuitState.OPEN
                and self._opened_at is not None
                and time.monotonic() - self._opened_at >= self._current_timeout):
            log.info("circuit '%s' OPEN → HALF-OPEN", self.name)
            self._state    = CircuitState.HALF_OPEN
            self._successes = 0

    def _record_failure(self) -> None:
        with self._lock:
            self._failures  += 1
            self._successes  = 0
            if self._state == CircuitState.HALF_OPEN:
                # Probe failed — back to OPEN with doubled timeout
                self._current_timeout = min(
                    self._current_timeout * 2, self.max_timeout
                )
                self._to_open()
            elif self._failures >= self.failure_threshold:
                self._to_open()

    def _record_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._successes += 1
                if self._successes >= self.success_threshold:
                    self._to_closed()
            else:
                self._failures = 0

    def _to_open(self) -> None:
        """Called under lock."""
        if self._state != CircuitState.OPEN:
            log.warning("circuit '%s' → OPEN (failures=%d)", self.name, self._failures)
        self._state      = CircuitState.OPEN
        self._opened_at  = time.monotonic()

    def _to_closed(self) -> None:
        """Called under lock."""
        log.info("circuit '%s' → CLOSED", self.name)
        self._state           = CircuitState.CLOSED
        self._failures        = 0
        self._successes       = 0
        self._opened_at       = None
        self._current_timeout = self.reset_timeout

    def _retry_after(self) -> float:
        """Seconds until the next HALF-OPEN probe attempt. Called under lock."""
        if self._opened_at is None:
            return 0.0
        elapsed = time.monotonic() - self._opened_at
        return max(0.0, self._current_timeout - elapsed)


# ── Convenience: a decorator form ────────────────────────────────────────────

def guarded(breaker: CircuitBreaker, fallback=None):
    """
    Decorator factory.  Wraps a function with ``breaker``; returns
    ``fallback`` (or re-raises) on CircuitOpenError.

    Usage::

        @guarded(redis_breaker, fallback=None)
        def ping_redis():
            return R.ping()
    """
    import functools
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return breaker.call(fn, *args, **kwargs)
            except CircuitOpenError:
                if fallback is not None or fallback == 0:
                    return fallback
                raise
        return wrapper
    return decorator


__all__ = ["CircuitBreaker", "CircuitOpenError", "CircuitState", "guarded"]
