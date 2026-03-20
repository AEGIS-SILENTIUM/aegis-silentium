"""
c2/distributed/crdt.py
AEGIS-SILENTIUM v12 — CRDTs with Vector Clocks

Implements state-based CRDTs (Conflict-free Replicated Data Types) for
data that must converge under eventual consistency without coordination.

Implemented types
-----------------
  VectorClock  – logical clock for causal ordering
  GCounter     – grow-only counter (merge = max per component)
  PNCounter    – increment/decrement counter (two G-Counters)
  ORSet        – observed-remove set (add/remove without coordination)
  LWWRegister  – last-write-wins register using HLC timestamps

All merge operations are:
  • Commutative:  merge(a, b) == merge(b, a)
  • Associative:  merge(merge(a, b), c) == merge(a, merge(b, c))
  • Idempotent:   merge(a, a) == a
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Generic, Optional, Set, Tuple, TypeVar

T = TypeVar("T")


# ── Vector Clock ──────────────────────────────────────────────────────────────

class VectorClock:
    """
    A vector clock for causal ordering.
    Component key = node_id (str), value = logical counter (int).
    """

    def __init__(self, node_id: str, clocks: Optional[Dict[str, int]] = None) -> None:
        self._node_id = node_id
        self._clocks: Dict[str, int] = dict(clocks or {})
        self._lock = threading.Lock()

    def tick(self) -> "VectorClock":
        """Increment own component and return a snapshot."""
        with self._lock:
            self._clocks[self._node_id] = self._clocks.get(self._node_id, 0) + 1
            return self.copy()

    def merge(self, other: "VectorClock") -> "VectorClock":
        """Return a new VectorClock that is the component-wise maximum."""
        with self._lock:
            merged = dict(self._clocks)
        for k, v in other._clocks.items():
            merged[k] = max(merged.get(k, 0), v)
        return VectorClock(self._node_id, merged)

    def copy(self) -> "VectorClock":
        with self._lock:
            return VectorClock(self._node_id, dict(self._clocks))

    def to_dict(self) -> dict:
        with self._lock:
            return dict(self._clocks)

    def __le__(self, other: "VectorClock") -> bool:
        """True if self happened-before-or-concurrent-with other."""
        for k, v in self._clocks.items():
            if v > other._clocks.get(k, 0):
                return False
        return True

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VectorClock):
            return NotImplemented
        return self._clocks == other._clocks


# ── G-Counter ─────────────────────────────────────────────────────────────────

class GCounter:
    """Grow-only counter.  Each node has its own component."""

    def __init__(self, node_id: str) -> None:
        self._node_id = node_id
        self._counts: Dict[str, int] = {}
        self._lock = threading.Lock()

    def increment(self, amount: int = 1) -> None:
        with self._lock:
            self._counts[self._node_id] = self._counts.get(self._node_id, 0) + amount

    @property
    def value(self) -> int:
        with self._lock:
            return sum(self._counts.values())

    def merge(self, other: "GCounter") -> "GCounter":
        merged = GCounter(self._node_id)
        all_keys = set(self._counts) | set(other._counts)
        for k in all_keys:
            merged._counts[k] = max(
                self._counts.get(k, 0),
                other._counts.get(k, 0)
            )
        return merged

    def to_dict(self) -> dict:
        with self._lock:
            return {"node_id": self._node_id, "counts": dict(self._counts)}

    @staticmethod
    def from_dict(d: dict) -> "GCounter":
        c = GCounter(d["node_id"])
        c._counts = dict(d.get("counts", {}))
        return c


# ── PN-Counter ────────────────────────────────────────────────────────────────

class PNCounter:
    """Increment/decrement counter built from two G-Counters."""

    def __init__(self, node_id: str) -> None:
        self._p = GCounter(node_id)
        self._n = GCounter(node_id)

    def increment(self, amount: int = 1) -> None:
        self._p.increment(amount)

    def decrement(self, amount: int = 1) -> None:
        self._n.increment(amount)

    @property
    def value(self) -> int:
        return self._p.value - self._n.value

    def merge(self, other: "PNCounter") -> "PNCounter":
        result = PNCounter(self._p._node_id)
        result._p = self._p.merge(other._p)
        result._n = self._n.merge(other._n)
        return result

    def to_dict(self) -> dict:
        return {"p": self._p.to_dict(), "n": self._n.to_dict()}

    @staticmethod
    def from_dict(d: dict) -> "PNCounter":
        node_id = d["p"]["node_id"]
        c = PNCounter(node_id)
        c._p = GCounter.from_dict(d["p"])
        c._n = GCounter.from_dict(d["n"])
        return c


# ── OR-Set ────────────────────────────────────────────────────────────────────

class ORSet(Generic[T]):
    """
    Observed-Remove Set.
    Each add tags the element with a unique token; remove kills all tokens
    seen at that point.  Concurrent add and remove: add wins.
    """

    def __init__(self) -> None:
        # _elements: element -> set of unique add-tokens
        self._elements: Dict[Any, Set[str]] = {}
        self._tombstones: Set[str] = set()
        self._lock = threading.Lock()

    def add(self, element: T) -> str:
        tag = str(uuid.uuid4())
        with self._lock:
            self._elements.setdefault(element, set()).add(tag)
        return tag

    def remove(self, element: T) -> None:
        with self._lock:
            tags = self._elements.pop(element, set())
            self._tombstones.update(tags)

    def contains(self, element: T) -> bool:
        with self._lock:
            return bool(self._elements.get(element))

    def items(self) -> FrozenSet[T]:
        with self._lock:
            return frozenset(e for e, tags in self._elements.items() if tags)

    def merge(self, other: "ORSet[T]") -> "ORSet[T]":
        result: ORSet[T] = ORSet()
        all_elems = set(self._elements) | set(other._elements)
        combined_tombstones = self._tombstones | other._tombstones
        for elem in all_elems:
            tags = (self._elements.get(elem, set()) | other._elements.get(elem, set()))
            live = tags - combined_tombstones
            if live:
                result._elements[elem] = live
        result._tombstones = combined_tombstones
        return result

    def __len__(self) -> int:
        return len(self.items())


# ── LWW Register ──────────────────────────────────────────────────────────────

@dataclass
class LWWRegister(Generic[T]):
    """Last-Write-Wins register.  Uses (timestamp_ms, node_id) for tie-breaking."""
    value:        Optional[T]
    timestamp_ms: int
    node_id:      str

    def write(self, new_value: T, timestamp_ms: int, node_id: str) -> "LWWRegister[T]":
        if (timestamp_ms, node_id) > (self.timestamp_ms, self.node_id):
            return LWWRegister(value=new_value, timestamp_ms=timestamp_ms, node_id=node_id)
        return self

    def merge(self, other: "LWWRegister[T]") -> "LWWRegister[T]":
        if (other.timestamp_ms, other.node_id) > (self.timestamp_ms, self.node_id):
            return other
        return self
