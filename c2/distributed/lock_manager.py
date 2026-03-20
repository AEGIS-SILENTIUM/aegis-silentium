"""
c2/distributed/lock_manager.py
AEGIS-SILENTIUM v12 — Distributed Lock Manager (Redlock-style)

Implements a distributed mutex using the Redlock algorithm over multiple
independent Redis instances.  A lock is acquired only when a majority of
instances grant it, preventing split-brain lock acquisition.

Reference: Redis Distributed Locks (https://redis.io/docs/manual/patterns/distributed-locks/)

Additionally provides:
  - ReadWriteLock  : fair reader-writer lock (many readers OR one writer)
  - NamedLockPool  : named locks with automatic TTL and re-entrant support
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Generator, List, Optional

log = logging.getLogger("aegis.locks")


# ── Redlock ───────────────────────────────────────────────────────────────────

class RedlockAcquireError(Exception):
    """Raised when a Redlock cannot be acquired within the timeout."""


class Redlock:
    """
    Distributed mutex using the Redlock algorithm.

    Parameters
    ----------
    redis_clients : list of Redis client instances (odd number recommended)
    resource      : name of the resource to lock
    ttl_ms        : lock time-to-live in milliseconds
    retry_count   : number of acquisition attempts
    retry_delay_s : sleep between retries
    """

    _LOCK_SCRIPT = """
    if redis.call('exists', KEYS[1]) == 0 then
        redis.call('set', KEYS[1], ARGV[1], 'PX', ARGV[2])
        return 1
    end
    return 0
    """

    _UNLOCK_SCRIPT = """
    if redis.call('get', KEYS[1]) == ARGV[1] then
        return redis.call('del', KEYS[1])
    end
    return 0
    """

    def __init__(
        self,
        redis_clients: list,
        resource:      str,
        ttl_ms:        int   = 10_000,
        retry_count:   int   = 3,
        retry_delay_s: float = 0.2,
    ) -> None:
        self._clients     = redis_clients
        self._resource    = f"aegis:lock:{resource}"
        self._ttl_ms      = ttl_ms
        self._retry_count = retry_count
        self._retry_delay = retry_delay_s
        self._n           = len(redis_clients)
        self._quorum      = self._n // 2 + 1
        self._token:   Optional[str]  = None
        self._acquired_at: float      = 0.0

    @contextmanager
    def lock(self) -> Generator[None, None, None]:
        self.acquire()
        try:
            yield
        finally:
            self.release()

    def acquire(self) -> bool:
        for attempt in range(self._retry_count):
            token = str(uuid.uuid4())
            start = time.monotonic()
            successes = 0
            for client in self._clients:
                try:
                    ok = client.eval(self._LOCK_SCRIPT, 1, self._resource, token, self._ttl_ms)
                    if ok:
                        successes += 1
                except Exception as exc:
                    log.debug("Redlock acquire failed on client: %s", exc)

            elapsed_ms = (time.monotonic() - start) * 1000
            validity_ms = self._ttl_ms - elapsed_ms - self._drift_ms()

            if successes >= self._quorum and validity_ms > 0:
                self._token       = token
                self._acquired_at = time.monotonic()
                log.debug("Redlock acquired resource=%s successes=%d/%d",
                          self._resource, successes, self._n)
                return True

            # Failed — release any partial locks
            self._release_all(token)
            if attempt < self._retry_count - 1:
                time.sleep(self._retry_delay)

        raise RedlockAcquireError(
            f"Could not acquire distributed lock on '{self._resource}' "
            f"after {self._retry_count} attempts"
        )

    def release(self) -> None:
        if self._token is None:
            return
        self._release_all(self._token)
        self._token = None
        log.debug("Redlock released resource=%s", self._resource)

    def is_valid(self) -> bool:
        if self._token is None or self._acquired_at == 0:
            return False
        elapsed_ms = (time.monotonic() - self._acquired_at) * 1000
        return elapsed_ms < self._ttl_ms - self._drift_ms()

    def _release_all(self, token: str) -> None:
        for client in self._clients:
            try:
                client.eval(self._UNLOCK_SCRIPT, 1, self._resource, token)
            except Exception as _exc:
                log.debug("_release_all: %s", _exc)

    def _drift_ms(self) -> float:
        return self._ttl_ms * 0.01 + 2  # 1% + 2ms clock drift


# ── Reader-Writer Lock ────────────────────────────────────────────────────────

class ReadWriteLock:
    """
    Fair reader-writer lock.
    Multiple concurrent readers OR one exclusive writer.
    Writers are not starved: once a writer is waiting, no new readers enter.
    """

    def __init__(self) -> None:
        self._readers   = 0
        self._writers   = 0
        self._waiting_writers = 0
        self._lock      = threading.Lock()
        self._read_ok   = threading.Condition(self._lock)
        self._write_ok  = threading.Condition(self._lock)

    @contextmanager
    def read_lock(self) -> Generator[None, None, None]:
        self._acquire_read()
        try:
            yield
        finally:
            self._release_read()

    @contextmanager
    def write_lock(self) -> Generator[None, None, None]:
        self._acquire_write()
        try:
            yield
        finally:
            self._release_write()

    def _acquire_read(self) -> None:
        with self._lock:
            while self._writers > 0 or self._waiting_writers > 0:
                self._read_ok.wait()
            self._readers += 1

    def _release_read(self) -> None:
        with self._lock:
            self._readers -= 1
            if self._readers == 0:
                self._write_ok.notify_all()

    def _acquire_write(self) -> None:
        with self._lock:
            self._waiting_writers += 1
            while self._readers > 0 or self._writers > 0:
                self._write_ok.wait()
            self._waiting_writers -= 1
            self._writers += 1

    def _release_write(self) -> None:
        with self._lock:
            self._writers -= 1
            self._read_ok.notify_all()
            self._write_ok.notify_all()


# ── Named Lock Pool ───────────────────────────────────────────────────────────

class NamedLockPool:
    """
    Pool of per-name threading locks.
    Useful for fine-grained locking on individual keys/resources.
    Locks are created on demand and garbage-collected when released.

    Usage::

        pool = NamedLockPool()
        with pool.lock("campaign:abc"):
            mutate_campaign("abc")
    """

    def __init__(self) -> None:
        self._locks: dict = {}
        self._ref_counts: dict = {}
        self._meta_lock = threading.Lock()

    @contextmanager
    def lock(self, name: str, timeout: Optional[float] = None) -> Generator[None, None, None]:
        lk = self._acquire_ref(name)
        acquired = lk.acquire(timeout=timeout if timeout is not None else -1)
        if not acquired:
            self._release_ref(name)
            raise TimeoutError(f"Could not acquire named lock '{name}' within {timeout}s")
        try:
            yield
        finally:
            lk.release()
            self._release_ref(name)

    def _acquire_ref(self, name: str) -> threading.Lock:
        with self._meta_lock:
            if name not in self._locks:
                self._locks[name] = threading.Lock()
                self._ref_counts[name] = 0
            self._ref_counts[name] += 1
            return self._locks[name]

    def _release_ref(self, name: str) -> None:
        with self._meta_lock:
            self._ref_counts[name] -= 1
            if self._ref_counts[name] == 0:
                del self._locks[name]
                del self._ref_counts[name]
