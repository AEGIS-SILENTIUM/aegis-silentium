"""
c2/distributed/quorum.py
AEGIS-SILENTIUM v12 — Quorum-based Read/Write with Tunable Consistency

Clients may specify one of three consistency levels:
  ONE    – any single replica suffices
  QUORUM – majority of replicas must respond
  ALL    – every replica must respond

Write path: broadcast to all replicas; wait for the required quorum.
Read path:  broadcast to all replicas; return value from the required quorum;
            optionally repair stale replicas in the background.
"""

from __future__ import annotations

import concurrent.futures
import logging
import threading
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("aegis.quorum")


class ConsistencyLevel(str, Enum):
    ONE    = "ONE"
    QUORUM = "QUORUM"
    ALL    = "ALL"


class QuorumError(Exception):
    """Raised when the required quorum cannot be reached."""


class QuorumManager:
    """
    Manages quorum reads and writes across a set of replica nodes.

    Parameters
    ----------
    replicas  : list of replica addresses (strings)
    read_fn   : callable(addr, key) → (value, version_ts)
    write_fn  : callable(addr, key, value, version_ts) → bool
    repair_fn : callable(addr, key, value, version_ts) → None (background)
    timeout   : per-replica timeout in seconds
    """

    def __init__(
        self,
        replicas:  List[str],
        read_fn:   Callable[[str, str], Tuple[Any, int]],
        write_fn:  Callable[[str, str, Any, int], bool],
        repair_fn: Optional[Callable[[str, str, Any, int], None]] = None,
        timeout:   float = 2.0,
    ) -> None:
        self._replicas  = list(replicas)
        self._read_fn   = read_fn
        self._write_fn  = write_fn
        self._repair_fn = repair_fn
        self._timeout   = timeout
        self._n         = len(replicas)

    # ── public API ────────────────────────────────────────────────────────────

    def write(
        self,
        key:   str,
        value: Any,
        version_ts: int,
        level: ConsistencyLevel = ConsistencyLevel.QUORUM,
    ) -> int:
        """
        Write key=value to replicas.
        Returns the count of successful writes.
        Raises QuorumError if required quorum not reached.
        """
        required = self._required(level)
        successes = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self._n) as ex:
            futs = {
                ex.submit(self._safe_write, addr, key, value, version_ts): addr
                for addr in self._replicas
            }
            for fut in concurrent.futures.as_completed(futs, timeout=self._timeout * 2):
                if fut.result():
                    successes += 1
                if successes >= required:
                    break
        if successes < required:
            raise QuorumError(
                f"Write quorum not reached: got {successes}/{required} "
                f"(level={level}, n={self._n})"
            )
        return successes

    def read(
        self,
        key:   str,
        level: ConsistencyLevel = ConsistencyLevel.QUORUM,
    ) -> Any:
        """
        Read key from replicas.
        Returns the value with the highest version_ts from the required quorum.
        Stale replicas are repaired in the background if repair_fn is set.
        Raises QuorumError if required quorum not reached.
        """
        required = self._required(level)
        results: List[Tuple[Any, int, str]] = []  # (value, ts, addr)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self._n) as ex:
            futs = {
                ex.submit(self._safe_read, addr, key): addr
                for addr in self._replicas
            }
            for fut in concurrent.futures.as_completed(futs, timeout=self._timeout * 2):
                r = fut.result()
                if r is not None:
                    results.append(r)
                if len(results) >= required:
                    break

        if len(results) < required:
            raise QuorumError(
                f"Read quorum not reached: got {len(results)}/{required} "
                f"(level={level}, n={self._n})"
            )

        # pick winner = highest version timestamp
        winner_val, winner_ts, _ = max(results, key=lambda r: r[1])

        # background read-repair for stale replicas
        if self._repair_fn:
            stale = [(val, ts, addr) for val, ts, addr in results if ts < winner_ts]
            if stale:
                t = threading.Thread(
                    target=self._repair_stale,
                    args=(key, winner_val, winner_ts, [addr for _, _, addr in stale]),
                    daemon=True,
                )
                t.start()

        return winner_val

    # ── helpers ───────────────────────────────────────────────────────────────

    def _required(self, level: ConsistencyLevel) -> int:
        if level == ConsistencyLevel.ONE:
            return 1
        if level == ConsistencyLevel.ALL:
            return self._n
        return self._n // 2 + 1  # QUORUM = majority

    def _safe_read(self, addr: str, key: str) -> Optional[Tuple[Any, int, str]]:
        try:
            val, ts = self._read_fn(addr, key)
            return (val, ts, addr)
        except Exception as exc:
            log.debug("Read failed addr=%s key=%s: %s", addr, key, exc)
            return None

    def _safe_write(self, addr: str, key: str, value: Any, ts: int) -> bool:
        try:
            return bool(self._write_fn(addr, key, value, ts))
        except Exception as exc:
            log.debug("Write failed addr=%s key=%s: %s", addr, key, exc)
            return False

    def _repair_stale(self, key: str, value: Any, ts: int, addrs: List[str]) -> None:
        for addr in addrs:
            try:
                self._repair_fn(addr, key, value, ts)  # type: ignore[misc]
                log.debug("Read-repaired addr=%s key=%s ts=%d", addr, key, ts)
            except Exception as exc:
                log.debug("Repair failed addr=%s: %s", addr, exc)
