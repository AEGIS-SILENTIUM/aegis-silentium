"""
c2/distributed/consistent_hash.py
AEGIS-SILENTIUM v12 — Consistent Hashing Ring

Maps keys to nodes using a consistent hash ring so that adding or
removing a node only remaps ~1/N of the keys.
Each node is replicated onto the ring with virtual_nodes replicas
to improve load distribution.
"""

from __future__ import annotations

import bisect
import hashlib
import threading
from typing import Dict, List, Optional, Tuple


class ConsistentHashRing:
    """
    Consistent hash ring for request routing.

    Usage::

        ring = ConsistentHashRing(virtual_nodes=150)
        ring.add_node("node-1")
        ring.add_node("node-2")
        target = ring.get_node("some_key")
    """

    def __init__(self, virtual_nodes: int = 150) -> None:
        self._vn     = virtual_nodes
        self._ring:  Dict[int, str] = {}
        self._sorted_keys: List[int] = []
        self._lock   = threading.RLock()

    def add_node(self, node_id: str) -> None:
        with self._lock:
            for i in range(self._vn):
                key = self._hash(f"{node_id}:vn{i}")
                self._ring[key] = node_id
            self._sorted_keys = sorted(self._ring.keys())

    def remove_node(self, node_id: str) -> None:
        with self._lock:
            for i in range(self._vn):
                key = self._hash(f"{node_id}:vn{i}")
                self._ring.pop(key, None)
            self._sorted_keys = sorted(self._ring.keys())

    def get_node(self, key: str) -> Optional[str]:
        with self._lock:
            if not self._ring:
                return None
            h = self._hash(key)
            idx = bisect.bisect(self._sorted_keys, h) % len(self._sorted_keys)
            return self._ring[self._sorted_keys[idx]]

    def get_nodes(self, key: str, n: int) -> List[str]:
        """Return up to n distinct nodes responsible for key (for replication)."""
        with self._lock:
            if not self._ring:
                return []
            h = self._hash(key)
            idx = bisect.bisect(self._sorted_keys, h) % len(self._sorted_keys)
            seen: set = set()
            result: List[str] = []
            for i in range(len(self._sorted_keys)):
                node = self._ring[self._sorted_keys[(idx + i) % len(self._sorted_keys)]]
                if node not in seen:
                    seen.add(node)
                    result.append(node)
                    if len(result) >= n:
                        break
            return result

    def nodes(self) -> List[str]:
        with self._lock:
            return list(set(self._ring.values()))

    @staticmethod
    def _hash(key: str) -> int:
        return int(hashlib.md5(key.encode()).hexdigest(), 16)


# ── Bloom Filter ──────────────────────────────────────────────────────────────

class BloomFilter:
    """
    Space-efficient probabilistic set membership test.
    False positives possible; false negatives impossible.

    Parameters
    ----------
    capacity      : expected number of elements
    error_rate    : acceptable false-positive rate (default 0.01 = 1%)
    """

    def __init__(self, capacity: int = 10_000, error_rate: float = 0.01) -> None:
        import math
        self._capacity   = capacity
        self._error_rate = error_rate
        # Optimal bit array size and number of hash functions
        self._size  = self._optimal_size(capacity, error_rate)
        self._k     = self._optimal_k(self._size, capacity)
        self._bits  = bytearray(self._size)
        self._count = 0
        self._lock  = threading.Lock()

    def add(self, item: str) -> None:
        with self._lock:
            for pos in self._positions(item):
                self._bits[pos >> 3] |= 1 << (pos & 7)
            self._count += 1

    def __contains__(self, item: str) -> bool:
        with self._lock:
            return all(
                self._bits[pos >> 3] & (1 << (pos & 7))
                for pos in self._positions(item)
            )

    def estimated_count(self) -> int:
        with self._lock:
            return self._count

    def _positions(self, item: str) -> List[int]:
        positions = []
        h1 = int(hashlib.md5(item.encode()).hexdigest(),  16)
        h2 = int(hashlib.sha1(item.encode()).hexdigest(), 16)
        for i in range(self._k):
            positions.append((h1 + i * h2) % self._size)
        return positions

    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        import math
        return int(-n * math.log(p) / (math.log(2) ** 2))

    @staticmethod
    def _optimal_k(m: int, n: int) -> int:
        import math
        return max(1, int((m / n) * math.log(2)))


# ── Priority Task Queue ───────────────────────────────────────────────────────

import heapq
import time as _time
from dataclasses import dataclass, field
from typing import Any


@dataclass(order=True)
class PriorityTask:
    priority:   int          # lower = higher priority
    task_id:    str   = field(compare=False, default="")
    created_at: float = field(default_factory=_time.time)
    payload:    Any   = field(compare=False, default=None)


class PriorityTaskQueue:
    """
    Thread-safe min-heap priority queue for task scheduling.
    Tasks with lower priority values are dequeued first.
    Supports delayed tasks (scheduled for a future time).

    Usage::

        q = PriorityTaskQueue()
        q.push(PriorityTask(priority=1, task_id="urgent", payload={...}))
        q.push(PriorityTask(priority=5, task_id="background", payload={...}))
        task = q.pop()   # returns the priority=1 task
    """

    def __init__(self) -> None:
        self._heap: List[Tuple[int, float, PriorityTask]] = []
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._counter   = 0   # tie-breaker for equal priority

    def push(self, task: PriorityTask, delay_s: float = 0.0) -> None:
        run_at = _time.monotonic() + delay_s
        with self._not_empty:
            heapq.heappush(self._heap, (task.priority, run_at, task))
            self._counter += 1
            self._not_empty.notify()

    def pop(self, timeout: Optional[float] = None) -> Optional[PriorityTask]:
        """Block until a task is available or timeout expires."""
        deadline = _time.monotonic() + (timeout or 1e9)
        with self._not_empty:
            while True:
                now = _time.monotonic()
                if self._heap:
                    _, run_at, task = self._heap[0]
                    if run_at <= now:
                        heapq.heappop(self._heap)
                        return task
                    wait = min(run_at - now, deadline - now)
                else:
                    wait = deadline - now
                if wait <= 0:
                    return None
                self._not_empty.wait(timeout=wait)

    def peek(self) -> Optional[PriorityTask]:
        with self._lock:
            return self._heap[0][2] if self._heap else None

    def __len__(self) -> int:
        with self._lock:
            return len(self._heap)

    def stats(self) -> dict:
        with self._lock:
            by_priority: Dict[int, int] = {}
            for p, _, _ in self._heap:
                by_priority[p] = by_priority.get(p, 0) + 1
            return {"depth": len(self._heap), "by_priority": by_priority}
