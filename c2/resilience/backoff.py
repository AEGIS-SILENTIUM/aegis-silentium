"""
AEGIS-SILENTIUM — Retry with Exponential Backoff + Jitter
===========================================================
Usage
-----
    from c2.resilience.backoff import retry, with_backoff

    # Decorator:
    @retry(max_attempts=3, base_delay=0.5, exceptions=(psycopg2.Error,))
    def query_db():
        ...

    # Context manager / inline:
    result = with_backoff(lambda: redis.get("key"), max_attempts=3)
"""
from __future__ import annotations

import functools
import logging
import random
import time
from typing import Callable, Optional, Type

log = logging.getLogger("aegis.backoff")


def _compute_delay(
    attempt:    int,
    base_delay: float,
    max_delay:  float,
    jitter:     bool,
) -> float:
    delay = min(base_delay * (2 ** attempt), max_delay)
    if jitter:
        delay *= (0.5 + random.random() * 0.5)
    return delay


def retry(
    max_attempts: int = 3,
    base_delay:   float = 0.25,
    max_delay:    float = 30.0,
    jitter:       bool = True,
    exceptions:   tuple[Type[Exception], ...] = (Exception,),
    on_retry:     Optional[Callable[[Exception, int], None]] = None,
):
    """
    Decorator: retry the wrapped function up to ``max_attempts`` times
    using exponential backoff with optional jitter.

    The final attempt re-raises the last exception.
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            last_err: Optional[Exception] = None
            for attempt in range(max_attempts):
                try:
                    return fn(*args, **kwargs)
                except exceptions as e:
                    last_err = e
                    if attempt < max_attempts - 1:
                        delay = _compute_delay(attempt, base_delay, max_delay, jitter)
                        log.warning(
                            "retry  fn=%s  attempt=%d/%d  delay=%.2fs  err=%s",
                            fn.__name__, attempt + 1, max_attempts, delay, e,
                        )
                        if on_retry:
                            on_retry(e, attempt)
                        time.sleep(delay)
            raise last_err
        return wrapper
    return decorator


def with_backoff(
    fn:           Callable,
    max_attempts: int = 3,
    base_delay:   float = 0.25,
    exceptions:   tuple[Type[Exception], ...] = (Exception,),
) -> object:
    """Inline retry helper (no decorator syntax needed)."""
    return retry(
        max_attempts=max_attempts,
        base_delay=base_delay,
        exceptions=exceptions,
    )(fn)()


__all__ = ["retry", "with_backoff"]
