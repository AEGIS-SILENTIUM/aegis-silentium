"""
c2/distributed/hlc.py
AEGIS-SILENTIUM v12 — Hybrid Logical Clocks (HLC)

Provides causally consistent ordering across distributed nodes without
relying on synchronised NTP.  Each state mutation carries an HLC that
is used for conflict resolution and snapshot isolation.

Reference: Kulkarni et al., "Logical Physical Clocks and Consistent
Snapshots in Globally Distributed Databases" (HotDep 2014).

Algorithm
---------
  An HLC timestamp is a pair (l, c) where:
    l  – the maximum physical time seen so far (milliseconds)
    c  – a logical counter used to break ties when l is the same

  On send / local event:
    l' = max(l, pt)
    c' = c+1 if l'==l else 0
    (l, c) = (l', c')

  On receive (m.l, m.c):
    l' = max(l, m.l, pt)
    c' depends on which terms are equal (see _recv below)

All operations are thread-safe via a single lock.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass(order=True, frozen=True)
class HLCTimestamp:
    """Immutable HLC timestamp.  Comparable via standard operators."""
    l: int   # physical component (ms since epoch)
    c: int   # logical counter

    def to_dict(self) -> dict:
        return {"l": self.l, "c": self.c}

    @staticmethod
    def from_dict(d: dict) -> "HLCTimestamp":
        return HLCTimestamp(l=int(d["l"]), c=int(d["c"]))

    def __str__(self) -> str:
        return f"{self.l}.{self.c:04d}"


class HybridLogicalClock:
    """
    Thread-safe Hybrid Logical Clock.

    Usage::

        hlc = HybridLogicalClock()
        ts  = hlc.now()          # local tick
        ts2 = hlc.recv(peer_ts)  # update on message receipt
    """

    _MAX_DRIFT_MS: int = 60_000  # reject clocks >60 s ahead of wall

    def __init__(self, node_id: str = "") -> None:
        self._node_id = node_id
        self._l: int = self._wall_ms()
        self._c: int = 0
        self._lock = threading.Lock()

    # ── public API ────────────────────────────────────────────────────────────

    def now(self) -> HLCTimestamp:
        """Advance the clock by one local event and return the new timestamp."""
        with self._lock:
            pt = self._wall_ms()
            if pt > self._l:
                self._l = pt
                self._c = 0
            else:
                self._c += 1
            return HLCTimestamp(self._l, self._c)

    def recv(self, msg_ts: HLCTimestamp) -> HLCTimestamp:
        """
        Merge a remote timestamp received in a message.
        Returns the new local timestamp (also advances the clock).
        Raises ValueError if the remote clock is suspiciously far ahead.
        """
        with self._lock:
            pt = self._wall_ms()
            m_l, m_c = msg_ts.l, msg_ts.c

            if m_l - pt > self._MAX_DRIFT_MS:
                raise ValueError(
                    f"HLC drift too large: peer={m_l} local_wall={pt} "
                    f"diff={m_l - pt}ms (max {self._MAX_DRIFT_MS}ms)"
                )

            old_l = self._l
            self._l = max(old_l, m_l, pt)

            if self._l == old_l == m_l:
                self._c = max(self._c, m_c) + 1
            elif self._l == old_l:
                self._c += 1
            elif self._l == m_l:
                self._c = m_c + 1
            else:
                self._c = 0

            return HLCTimestamp(self._l, self._c)

    def peek(self) -> HLCTimestamp:
        """Return the current timestamp without advancing the clock."""
        with self._lock:
            return HLCTimestamp(self._l, self._c)

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _wall_ms() -> int:
        return int(time.time() * 1000)
