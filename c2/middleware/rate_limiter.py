"""
AEGIS-SILENTIUM — Sliding-Window Per-Operator Rate Limiter
===========================================================
Improvements over v8's per-IP token bucket:
  * Keyed by operator handle (authenticated) + IP (unauthenticated)
  * Sliding window (not fixed bucket) — fairer and harder to game
  * Per-route configurable limits (beacon vs operator API vs admin)
  * Automatic burst allowance (2× for seniors/leads/admins)
  * Redis-backed for multi-process correctness; memory fallback if Redis down
  * Returns ``Retry-After`` header value on 429

Algorithm
---------
Uses a Redis sorted set: key = rate:{scope}:{key}, member = timestamp,
score = timestamp.  On each request:
  1. Remove members older than the window.
  2. Count remaining members.
  3. If count >= limit → 429.
  4. Add current timestamp as a new member.
  5. Set key TTL to window + 1s.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Optional

log = logging.getLogger("aegis.rate_limiter")


@dataclass
class RateLimit:
    limit:       int    # max requests per window
    window_secs: int    # sliding window size in seconds
    scope:       str    # label for metrics / logs


# ── Preset limits ─────────────────────────────────────────────────────────────

LIMITS = {
    "beacon":          RateLimit(limit=120,  window_secs=60,  scope="beacon"),
    "operator_api":    RateLimit(limit=200,  window_secs=60,  scope="api"),
    "auth":            RateLimit(limit=10,   window_secs=60,  scope="auth"),
    "generate_payload":RateLimit(limit=20,   window_secs=60,  scope="payload"),
    "ingest_data":     RateLimit(limit=500,  window_secs=60,  scope="ingest"),
    "default":         RateLimit(limit=300,  window_secs=60,  scope="default"),
}

_ROLE_MULTIPLIERS = {
    "ghost":    1.0,
    "operator": 1.0,
    "senior":   2.0,
    "lead":     3.0,
    "admin":    0,       # 0 = no limit
}


class RateLimiter:

    def __init__(
        self,
        redis_client: Optional[Any] = None,
        fallback_to_memory: bool = True,
    ) -> None:
        self._redis   = redis_client
        self._fallback = fallback_to_memory
        self._mem:    dict[str, list[float]] = {}   # in-memory fallback

    def check(
        self,
        key:        str,
        preset:     str = "default",
        role:       str = "operator",
    ) -> tuple[bool, dict]:
        """
        Check whether ``key`` is within the rate limit for ``preset``.

        Returns
        -------
        (allowed: bool, headers: dict)
        ``headers`` contains X-RateLimit-* and Retry-After for HTTP responses.
        """
        limit_cfg  = LIMITS.get(preset, LIMITS["default"])
        multiplier = _ROLE_MULTIPLIERS.get(role, 1.0)

        if multiplier == 0:
            # Unlimited
            return True, {"X-RateLimit-Limit": "unlimited"}

        effective_limit = max(1, int(limit_cfg.limit * multiplier))
        window          = limit_cfg.window_secs

        if self._redis:
            try:
                return self._check_redis(key, preset, effective_limit, window)
            except Exception as e:
                log.warning("rate_limiter redis error — using in-memory fallback: %s", e)
                # Fall through to memory fallback when Redis is temporarily unavailable

        if self._fallback:
            return self._check_memory(key, effective_limit, window)

        # Fail CLOSED: when no rate-limiting backend is available,
        # block all requests to prevent abuse during degraded state.
        # This is safer than fail-open (allowing unlimited requests).
        log.warning(
            "rate_limiter: no backend available (redis=%s, memory=%s) — "
            "failing CLOSED for key=%s preset=%s",
            bool(self._redis), bool(self._fallback), key[:32], preset
        )
        retry_after = effective_limit
        return False, {
            "X-RateLimit-Limit":     str(effective_limit),
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset":     str(int(time.time()) + window),
            "Retry-After":           str(retry_after),
            "X-RateLimit-Error":     "backend-unavailable",
        }

    def _check_redis(
        self, key: str, scope: str, limit: int, window: int
    ) -> tuple[bool, dict]:
        rkey = f"aegis:rl:{scope}:{key}"
        now  = time.time()
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(rkey, 0, now - window)
        pipe.zcard(rkey)
        pipe.zadd(rkey, {str(now): now})
        pipe.expire(rkey, window + 1)
        _, count, _, _ = pipe.execute()

        remaining   = max(0, limit - count)
        reset_at    = int(now) + window
        retry_after = window if count >= limit else 0
        allowed     = count < limit

        if not allowed:
            # Don't add the request we just added
            self._redis.zrem(rkey, str(now))
            from c2.observability.metrics import rate_limited_total
            rate_limited_total.inc({"scope": scope})

        return allowed, {
            "X-RateLimit-Limit":     str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset":     str(reset_at),
            **({"Retry-After": str(retry_after)} if not allowed else {}),
        }

    def _check_memory(
        self, key: str, limit: int, window: int
    ) -> tuple[bool, dict]:
        now  = time.time()
        hist = self._mem.get(key, [])
        hist = [t for t in hist if now - t < window]

        allowed = len(hist) < limit
        if allowed:
            hist.append(now)
        self._mem[key] = hist

        remaining = max(0, limit - len(hist))
        return allowed, {
            "X-RateLimit-Limit":     str(limit),
            "X-RateLimit-Remaining": str(remaining),
        }


__all__ = ["RateLimiter", "RateLimit", "LIMITS"]
