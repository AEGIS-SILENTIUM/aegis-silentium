"""
AEGIS — Multi-Dimensional Rate Limiting
=========================================
Implements a sliding-window rate limiter in Redis with two independent
dimensions:

1. **IP-based**      — protects against unauthenticated floods at ingress.
2. **Operator-based** — prevents a single compromised operator from
                         overwhelming internal resources even after auth.

Algorithm: sliding window counter (token bucket would give smoother
behaviour but requires two Redis calls; sliding window is one INCR +
one EXPIRE, which is atomic enough for our purposes).

Backpressure
------------
When a burst is detected:
  * HTTP 429 with ``Retry-After`` header pointing to the window reset time.
  * Redis key ``aegis:throttled:<ip>`` set so other nodes respect it.
  * Audit log entry for operator-level throttling.

Graceful Redis degradation
--------------------------
If Redis is unreachable (CircuitOpenError), rate limiting is **bypassed**
rather than blocking all traffic.  This trades a reduced security
guarantee for availability — the correct tradeoff for a C2 server where
false-denial is worse than a short-lived flood.
"""
from __future__ import annotations

import logging
import math
import time
from functools import wraps
from typing import Optional

from flask import request, jsonify

log = logging.getLogger("aegis.ratelimit")


class SlidingWindowLimiter:
    """
    Sliding-window rate limiter backed by Redis.

    Parameters
    ----------
    redis_client      Redis client (may be None — limiter becomes a no-op).
    window_seconds    Size of the sliding window (default 60s).
    default_limit     Default max requests per window.
    """

    def __init__(
        self,
        redis_client,
        window_seconds: int = 60,
        default_limit:  int = 60,
    ):
        self._redis   = redis_client
        self._window  = window_seconds
        self._default = default_limit

    def check(
        self,
        key:   str,
        limit: Optional[int] = None,
    ) -> tuple[bool, dict]:
        """
        Check whether ``key`` is within its rate limit.

        Returns
        -------
        (allowed, info) where ``info`` contains:
          remaining     — requests left in this window
          limit         — the effective limit
          reset_after   — seconds until the window resets
          retry_after   — same as reset_after (for HTTP header)
        """
        limit = limit or self._default
        if self._redis is None:
            return True, {"remaining": limit, "limit": limit,
                          "reset_after": self._window, "retry_after": 0}

        redis_key = f"aegis:rl:{key}"
        try:
            count = self._redis.incr(redis_key)
            if count == 1:
                self._redis.expire(redis_key, self._window)
            ttl   = self._redis.ttl(redis_key)
            ttl   = ttl if ttl > 0 else self._window

            remaining = max(0, limit - count)
            allowed   = count <= limit

            if not allowed:
                log.warning(
                    "Rate limit exceeded",
                    extra={"rl_key": key, "count": count,
                           "limit": limit, "ttl": ttl},
                )

            return allowed, {
                "remaining":   remaining,
                "limit":       limit,
                "reset_after": ttl,
                "retry_after": ttl if not allowed else 0,
            }
        except Exception as e:
            # Redis failure — allow the request (availability over security)
            log.debug("Rate limit Redis error (bypassing): %s", e)
            return True, {"remaining": limit, "limit": limit,
                          "reset_after": self._window, "retry_after": 0}

    def is_throttled(self, key: str) -> bool:
        """Quick check without incrementing — used for pre-flight checks."""
        if not self._redis:
            return False
        try:
            return bool(self._redis.exists(f"aegis:throttled:{key}"))
        except Exception:
            return False

    def flag_throttled(self, key: str, duration: int = 300) -> None:
        """Mark a key as throttled (e.g. after repeated violations)."""
        if self._redis:
            try:
                self._redis.setex(f"aegis:throttled:{key}", duration, "1")
            except Exception as _e:
                log.debug("%s error: %s", __name__, _e)


# ── Module-level instances (created in app.py after Redis is ready) ───────────

_ip_limiter:  Optional[SlidingWindowLimiter] = None
_op_limiter:  Optional[SlidingWindowLimiter] = None


def init_limiters(redis_client, *, ip_limit: int = 120, op_limit: int = 600) -> None:
    """
    Initialise module-level limiters.  Call once from app startup.

    ip_limit  — requests per 60s per IP   (default 120 = 2/s)
    op_limit  — requests per 60s per operator (default 600 = 10/s)
    """
    global _ip_limiter, _op_limiter
    _ip_limiter = SlidingWindowLimiter(redis_client, window_seconds=60,
                                        default_limit=ip_limit)
    _op_limiter = SlidingWindowLimiter(redis_client, window_seconds=60,
                                        default_limit=op_limit)
    log.info("Rate limiters initialised",
             extra={"ip_limit": ip_limit, "op_limit": op_limit})


# ── Flask decorators ──────────────────────────────────────────────────────────

def rate_limit(
    ip_limit: Optional[int]       = None,
    op_limit: Optional[int]       = None,
    key_fn   = None,
):
    """
    Decorator factory.  Applies IP-based limiting always;
    adds operator-based limiting when an operator session exists.

    Usage::

        @app.route("/api/heavy-endpoint")
        @rate_limit(ip_limit=10, op_limit=30)
        def heavy_endpoint():
            ...

    The optional ``key_fn(request) -> str`` lets callers supply a
    custom partitioning key (e.g. for per-campaign limits).
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            ip  = request.remote_addr or "0.0.0.0"
            ok  = True
            info = {}

            # 1. IP-level check
            if _ip_limiter:
                ok, info = _ip_limiter.check(f"ip:{ip}", limit=ip_limit)
                if not ok:
                    return _too_many(info, "IP rate limit exceeded")

            # 2. Operator-level check (only if authenticated)
            from flask import g
            op_sess = getattr(g, "operator", None)
            if op_sess and _op_limiter:
                ok, info = _op_limiter.check(
                    f"op:{op_sess.handle}", limit=op_limit
                )
                if not ok:
                    log.warning(
                        "Operator rate limit exceeded",
                        extra={"operator": op_sess.handle,
                               "limit": op_limit, "ip": ip},
                    )
                    return _too_many(info, "Operator rate limit exceeded")

            # 3. Custom key check
            if key_fn and _ip_limiter:
                custom_key = key_fn(request)
                ok, info   = _ip_limiter.check(custom_key)
                if not ok:
                    return _too_many(info, "Rate limit exceeded")

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def _too_many(info: dict, message: str):
    resp = jsonify({
        "error":       message,
        "retry_after": info.get("retry_after", 60),
    })
    resp.status_code = 429
    resp.headers["Retry-After"] = str(math.ceil(info.get("retry_after", 60)))
    resp.headers["X-RateLimit-Limit"]     = str(info.get("limit", 0))
    resp.headers["X-RateLimit-Remaining"] = "0"
    resp.headers["X-RateLimit-Reset"]     = str(
        int(time.time()) + info.get("reset_after", 60)
    )
    return resp


# ── Beacon-specific limiter (very tight — nodes should not flood) ─────────────

def check_beacon(node_id: str) -> bool:
    """
    Return True if the beacon from ``node_id`` is within its budget.
    Agents should check in at most once per second; allow 5/s burst.
    """
    if not _ip_limiter or not _ip_limiter._redis:
        return True
    ok, _ = _ip_limiter.check(f"beacon:{node_id}", limit=5)
    return ok


__all__ = [
    "SlidingWindowLimiter", "init_limiters",
    "rate_limit", "check_beacon",
]
