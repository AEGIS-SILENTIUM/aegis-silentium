"""
c2/distributed/mvcc.py
AEGIS-SILENTIUM v12 — Snapshot Isolation via MVCC

Each read sees a consistent snapshot of state at a given HLC timestamp.
Writes do not block reads; reads do not block writes.
Implemented as a copy-on-write versioned store.

Design
------
  Every write appends a new version record (key, value, ts).
  A snapshot is taken by recording the current HLC timestamp;
  reads in that snapshot see only versions committed before the timestamp.
  Old versions are garbage-collected when no snapshot references them.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .hlc import HLCTimestamp, HybridLogicalClock


class _Version:
    __slots__ = ("value", "ts", "deleted")

    def __init__(self, value: Any, ts: HLCTimestamp, deleted: bool = False) -> None:
        self.value   = value
        self.ts      = ts
        self.deleted = deleted


class MVCCStore:
    """
    Multi-version key-value store.

    Usage::

        store = MVCCStore(hlc)
        store.write("k", "v")

        snap_ts = store.begin_snapshot()
        val     = store.read("k", snap_ts)   # sees all writes before snap_ts
        store.release_snapshot(snap_ts)
    """

    def __init__(self, hlc: HybridLogicalClock) -> None:
        self._hlc = hlc
        # key → list of versions, oldest first
        self._versions: Dict[str, List[_Version]] = {}
        self._snapshots: List[HLCTimestamp] = []
        self._lock = threading.RLock()

    # ── write ─────────────────────────────────────────────────────────────────

    def write(self, key: str, value: Any) -> HLCTimestamp:
        ts = self._hlc.now()
        with self._lock:
            self._versions.setdefault(key, []).append(_Version(value, ts))
        return ts

    def delete(self, key: str) -> Optional[HLCTimestamp]:
        with self._lock:
            if key not in self._versions:
                return None
            ts = self._hlc.now()
            self._versions[key].append(_Version(None, ts, deleted=True))
        return ts

    # ── snapshot ──────────────────────────────────────────────────────────────

    def begin_snapshot(self) -> HLCTimestamp:
        ts = self._hlc.now()
        with self._lock:
            self._snapshots.append(ts)
        return ts

    def release_snapshot(self, ts: HLCTimestamp) -> None:
        with self._lock:
            try:
                self._snapshots.remove(ts)
            except ValueError:
                pass
        self._gc()

    def read(self, key: str, snapshot_ts: HLCTimestamp) -> Optional[Any]:
        """
        Return the value of key as of snapshot_ts.
        Returns None if the key did not exist at that point.
        """
        with self._lock:
            versions = self._versions.get(key, [])
        visible = [v for v in versions if v.ts <= snapshot_ts]
        if not visible:
            return None
        latest = max(visible, key=lambda v: v.ts)
        return None if latest.deleted else latest.value

    def read_latest(self, key: str) -> Optional[Any]:
        with self._lock:
            versions = self._versions.get(key, [])
            if not versions:
                return None
            latest = versions[-1]
            return None if latest.deleted else latest.value

    def keys_at(self, snapshot_ts: HLCTimestamp) -> List[str]:
        result = []
        with self._lock:
            for key, versions in self._versions.items():
                visible = [v for v in versions if v.ts <= snapshot_ts]
                if visible and not max(visible, key=lambda v: v.ts).deleted:
                    result.append(key)
        return result

    # ── GC ────────────────────────────────────────────────────────────────────

    def _gc(self) -> None:
        """Remove versions that are no longer visible to any active snapshot."""
        with self._lock:
            if not self._snapshots:
                min_snap = None
            else:
                min_snap = min(self._snapshots)
            for key in list(self._versions.keys()):
                versions = self._versions[key]
                if min_snap is None:
                    # keep only the last version
                    self._versions[key] = versions[-1:]
                else:
                    # keep any version that might be visible to the oldest snapshot
                    cutoff = next(
                        (i for i, v in enumerate(versions) if v.ts >= min_snap), len(versions)
                    )
                    keep_from = max(0, cutoff - 1)
                    self._versions[key] = versions[keep_from:]
