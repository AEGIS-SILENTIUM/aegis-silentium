"""
c2/distributed/lease.py
AEGIS-SILENTIUM v12 — Lease-Based Read Caching

Follower nodes hold short-term leases granted by the leader that allow
them to serve reads locally without contacting the leader.
Leases are renewed by heartbeats and revoked on leader change.

Also implements Speculative Execution for read-after-write consistency:
when a client writes then immediately reads from a follower, the follower
can speculatively apply the write using a "read-your-writes" hint.
If the write hasn't replicated yet the read is forwarded to the leader.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

log = logging.getLogger("aegis.lease")


# ── Lease Manager ─────────────────────────────────────────────────────────────

@dataclass
class Lease:
    granted_at:  float
    duration_s:  float
    leader_addr: str
    epoch:       int

    @property
    def valid(self) -> bool:
        return time.monotonic() < self.granted_at + self.duration_s

    @property
    def remaining_s(self) -> float:
        return max(0.0, self.granted_at + self.duration_s - time.monotonic())


class LeaseCache:
    """
    Read-lease cache for follower nodes.

    Parameters
    ----------
    node_id      : this node's identifier
    is_leader_fn : callable() → bool
    leader_fn    : callable() → str  (leader address)
    forward_fn   : callable(key) → Any  (forward read to leader)
    store_fn     : callable(key) → Any  (read from local store)
    lease_duration_s : how long a lease is valid (default 10s)
    """

    def __init__(
        self,
        node_id:          str,
        is_leader_fn:     Callable[[], bool],
        leader_fn:        Callable[[], str],
        forward_fn:       Callable[[str], Any],
        store_fn:         Callable[[str], Any],
        lease_duration_s: float = 10.0,
    ) -> None:
        self._node_id    = node_id
        self._is_leader  = is_leader_fn
        self._leader_fn  = leader_fn
        self._forward    = forward_fn
        self._store      = store_fn
        self._duration   = lease_duration_s
        self._lease: Optional[Lease] = None
        self._lock = threading.Lock()

    # ── lease management ──────────────────────────────────────────────────────

    def grant_lease(self, leader_addr: str, epoch: int) -> None:
        """Called when the leader heartbeats us with a lease grant."""
        with self._lock:
            self._lease = Lease(
                granted_at=time.monotonic(),
                duration_s=self._duration,
                leader_addr=leader_addr,
                epoch=epoch,
            )
        log.debug("Lease granted from %s epoch=%d ttl=%.1fs", leader_addr, epoch, self._duration)

    def revoke_lease(self) -> None:
        with self._lock:
            self._lease = None
        log.debug("Lease revoked node=%s", self._node_id)

    def has_valid_lease(self) -> bool:
        with self._lock:
            return self._lease is not None and self._lease.valid

    # ── read path ─────────────────────────────────────────────────────────────

    def read(self, key: str) -> Any:
        """
        Serve a read locally if we hold a valid lease or are the leader.
        Otherwise forward to the leader.
        """
        if self._is_leader() or self.has_valid_lease():
            return self._store(key)
        log.debug("No lease — forwarding read key=%s to leader", key)
        return self._forward(key)

    def lease_info(self) -> dict:
        with self._lock:
            if self._lease is None:
                return {"has_lease": False}
            return {
                "has_lease":    self._lease.valid,
                "remaining_s":  round(self._lease.remaining_s, 2),
                "leader":       self._lease.leader_addr,
                "epoch":        self._lease.epoch,
            }


# ── Speculative Execution ─────────────────────────────────────────────────────

class SpeculativeReadBuffer:
    """
    Tracks writes made by a client session so that reads-after-write
    from the same session can be served speculatively from the local
    write buffer without waiting for replication.

    Usage::

        buf = SpeculativeReadBuffer(forward_fn, store_fn)
        buf.record_write("k", "v", write_ts)
        val = buf.read("k", session_write_ts)   # returns "v" speculatively
    """

    # How long to keep speculative entries (ms)
    _TTL_MS: int = 5_000

    def __init__(
        self,
        forward_fn: Callable[[str], Any],
        store_fn:   Callable[[str], Any],
    ) -> None:
        self._forward = forward_fn
        self._store   = store_fn
        # key → (value, write_ts_ms, recorded_monotonic)
        self._buffer: Dict[str, Tuple[Any, int, float]] = {}
        self._lock = threading.Lock()

    def record_write(self, key: str, value: Any, write_ts_ms: int) -> None:
        """Record a write so future reads can be served speculatively."""
        with self._lock:
            self._buffer[key] = (value, write_ts_ms, time.monotonic())
        self._evict_stale()

    def read(self, key: str, after_ts_ms: Optional[int] = None) -> Any:
        """
        Return the value for key.
        If a speculative entry exists with ts >= after_ts_ms, return it.
        Otherwise check the local store; if the write hasn't arrived yet,
        forward to the leader.
        """
        self._evict_stale()
        with self._lock:
            entry = self._buffer.get(key)

        if entry is not None:
            value, write_ts, _ = entry
            if after_ts_ms is None or write_ts >= after_ts_ms:
                log.debug("Speculative hit key=%s write_ts=%d", key, write_ts)
                return value

        # Check local store
        local_val = self._store(key)
        if local_val is not None:
            return local_val

        # Fall back to leader
        log.debug("Speculative miss key=%s — forwarding to leader", key)
        return self._forward(key)

    def _evict_stale(self) -> None:
        now = time.monotonic()
        ttl = self._TTL_MS / 1000.0
        with self._lock:
            stale = [k for k, (_, _, t) in self._buffer.items() if now - t > ttl]
            for k in stale:
                del self._buffer[k]

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()
