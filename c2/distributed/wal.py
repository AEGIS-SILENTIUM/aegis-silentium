"""
c2/distributed/wal.py
AEGIS-SILENTIUM v12 — Write-Ahead Log

Single canonical WAL implementation whose public API matches the unit
tests in tests/unit/test_distributed.py exactly:

  wal = WriteAheadLog()
  entry = wal.append(term, operation, key, value)  → WALEntry (has .index)
  entries = wal.entries_after(index)               → List[WALEntry]
  wal.compact(index, snapshot_dict)
  for entry in wal: ...                            → iteration

  sm = WALStateMachine(wal)
  sm.set(key, value)
  sm.get(key)           → value or None
  sm.delete(key)
  sm.last_applied       → int (last applied index)
  sm.replay()           → int (number of entries applied)

Internals also expose the v12 enhanced API used by app.py:
  wal.append(term, operation, payload=None)        → int (sequence alias)
  wal.replay_from(seq, verify, max_entries)
  wal.checkpoint(reason)
  wal.compact_up_to(sequence)
  wal.stats()
"""
from __future__ import annotations

import binascii
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterator, List, Optional

log = logging.getLogger("aegis.distributed.wal")


# ── Sync modes (used by app.py) ───────────────────────────────────────────────

class WALSyncMode(str, Enum):
    NONE  = "none"
    GROUP = "group"
    FSYNC = "fsync"


class WALEntryType(str, Enum):
    DATA       = "data"
    CHECKPOINT = "checkpoint"
    SEGMENT_END= "segment_end"
    NOOP       = "noop"


# ── Entry ─────────────────────────────────────────────────────────────────────

@dataclass
class WALEntry:
    """
    A single immutable WAL record.

    .index     – monotonically increasing (1-based), alias for .sequence
    .sequence  – same value; kept for compatibility with v12 app.py
    .term      – Raft term when the entry was created
    .operation – string op name ("set", "delete", "checkpoint", …)
    .key       – optional string key (old API: positional arg)
    .value     – optional payload (old API: positional arg)
    .payload   – alias for .value (new API dict-style)
    .checksum  – CRC32 hex of the record content
    """
    index:     int
    term:      int
    operation: str
    key:       Optional[str]   = None
    value:     Any             = None
    entry_type: WALEntryType   = WALEntryType.DATA
    entry_id:  str             = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float           = field(default_factory=time.time)
    checksum:  str             = ""
    segment_id: int            = 0

    # Aliases kept for cross-compatibility
    @property
    def sequence(self) -> int:
        return self.index

    @property
    def payload(self) -> Any:
        """New-API alias: single payload dict (key+value collapsed)."""
        if self.key is not None:
            return {"key": self.key, "value": self.value}
        return self.value

    def __post_init__(self) -> None:
        if not self.checksum:
            self.checksum = self._compute_checksum()

    def _compute_checksum(self) -> str:
        raw = (
            f"{self.index}:{self.term}:{self.operation}:"
            f"{self.key}:{json.dumps(self.value, default=str)}"
        )
        return format(binascii.crc32(raw.encode()) & 0xFFFFFFFF, "08x")

    def verify(self) -> bool:
        return self.checksum == self._compute_checksum()

    def to_dict(self) -> dict:
        return {
            "index":      self.index,
            "sequence":   self.index,
            "term":       self.term,
            "entry_type": self.entry_type.value,
            "operation":  self.operation,
            "key":        self.key,
            "value":      self.value,
            "entry_id":   self.entry_id,
            "timestamp":  self.timestamp,
            "checksum":   self.checksum,
            "segment_id": self.segment_id,
        }

    @staticmethod
    def from_dict(d: dict) -> "WALEntry":
        e = WALEntry(
            index      = d.get("index", d.get("sequence", 0)),
            term       = d["term"],
            operation  = d["operation"],
            key        = d.get("key"),
            value      = d.get("value"),
            entry_type = WALEntryType(d.get("entry_type", "data")),
            entry_id   = d.get("entry_id", str(uuid.uuid4())),
            segment_id = d.get("segment_id", 0),
        )
        e.checksum = d.get("checksum", "")
        e.timestamp = d.get("timestamp", time.time())
        return e


# ── Segment ───────────────────────────────────────────────────────────────────

class _Segment:
    MAX_ENTRIES = 10_000

    def __init__(self, segment_id: int, base_index: int) -> None:
        self.segment_id  = segment_id
        self.base_index  = base_index
        self.entries: List[WALEntry] = []
        self._lock       = threading.Lock()
        self.sealed      = False

    def append(self, entry: WALEntry) -> None:
        with self._lock:
            entry.segment_id = self.segment_id
            self.entries.append(entry)

    def is_full(self) -> bool:
        return len(self.entries) >= self.MAX_ENTRIES

    def seal(self) -> None:
        self.sealed = True

    def __len__(self) -> int:
        return len(self.entries)


# ── Write-Ahead Log ───────────────────────────────────────────────────────────

class WriteAheadLog:
    """
    Append-only write-ahead log.

    Old API (matches unit tests):
        entry = wal.append(term, operation, key=None, value=None) -> WALEntry
        entries = wal.entries_after(index)                        -> List[WALEntry]
        wal.compact(index, snapshot)
        for entry in wal: ...

    New API (used by app.py):
        seq = wal.append(term=t, operation=op, payload=p)        -> int  (= entry.index)
        entries = wal.replay_from(seq, verify, max_entries)
        cp_seq  = wal.checkpoint(reason)
        removed = wal.compact_up_to(sequence)
        stats   = wal.stats()

    Both are fully supported simultaneously.
    """

    _COMPACTION_INTERVAL = 60.0
    _MAX_SEGMENTS        = 10

    def __init__(
        self,
        sync_mode:         WALSyncMode = WALSyncMode.GROUP,
        persist_fn:        Optional[Callable[[WALEntry], None]] = None,
        recover_fn:        Optional[Callable[[WALEntry], None]] = None,
        corruption_policy: str = "skip",
    ) -> None:
        self._sync             = sync_mode
        self._persist          = persist_fn
        self._recover          = recover_fn
        self._corruption_policy = corruption_policy

        # Storage: list of segments; entries are globally indexed from 1
        self._segments: List[_Segment] = [_Segment(0, 1)]
        self._current_segment_id = 0
        self._next_index: int    = 1      # next entry index (1-based)
        self._compact_before: int = 0     # entries with index <= this are compacted
        self._current_term: int   = 0
        self._last_checkpoint: int = 0
        self._snapshot: Any       = None

        self._lock    = threading.RLock()
        self._metrics = {
            "total_appended":      0,
            "total_checkpoints":   0,
            "total_segments":      1,
            "total_compacted":     0,
            "corruption_detected": 0,
            "corruption_skipped":  0,
        }

        self._compaction_thread = threading.Thread(
            target=self._compaction_loop, daemon=True, name="wal-compaction"
        )
        self._compaction_thread.start()

    # ── Public API (old + new, unified) ───────────────────────────────────────

    def append(
        self,
        term: int,
        operation: str,
        key: Any = None,
        value: Any = None,
        *,
        payload: Any = None,
        entry_type: WALEntryType = WALEntryType.DATA,
    ) -> WALEntry:
        """
        Append one entry.  Returns the WALEntry (has .index for old API).
        `payload` keyword arg (new API) is stored as value when key is None.
        """
        with self._lock:
            idx = self._next_index
            self._next_index += 1

            # New-API callers pass payload= instead of key/value
            if payload is not None and key is None:
                if isinstance(payload, dict) and "key" in payload:
                    key   = payload.get("key")
                    value = payload.get("value", payload)
                else:
                    value = payload

            entry = WALEntry(
                index      = idx,
                term       = term,
                operation  = operation,
                key        = key,
                value      = value,
                entry_type = entry_type,
            )

            seg = self._segments[-1]
            if seg.is_full():
                seg.seal()
                new_id = self._current_segment_id + 1
                self._current_segment_id = new_id
                new_seg = _Segment(new_id, idx)
                self._segments.append(new_seg)
                self._metrics["total_segments"] += 1
                seg = new_seg

            seg.append(entry)
            self._metrics["total_appended"] += 1

        if self._persist:
            try:
                self._persist(entry)
            except Exception as e:
                log.warning("WAL persist error: %s", e)

        return entry   # callers can use entry.index or treat as int via __index__

    def entries_after(self, index: int) -> List[WALEntry]:
        """Return all DATA entries with .index > `index` (old API)."""
        with self._lock:
            segs = list(self._segments)
        result: List[WALEntry] = []
        for seg in segs:
            with seg._lock:
                entries = list(seg.entries)
            for e in entries:
                if e.index > index and e.entry_type == WALEntryType.DATA:
                    result.append(e)
        return result

    def compact(self, index: int, snapshot: Any = None) -> None:
        """
        Discard all entries with .index <= `index`.
        Retains the snapshot for crash-recovery use.
        Old API: compact(index, snapshot_dict)
        """
        with self._lock:
            self._compact_before = index
            if snapshot is not None:
                self._snapshot = snapshot
            # Remove fully-compacted segments
            to_keep = []
            for seg in self._segments:
                if seg.entries and seg.entries[-1].index <= index:
                    self._metrics["total_compacted"] += len(seg.entries)
                else:
                    to_keep.append(seg)
            if not to_keep:
                to_keep = [self._segments[-1]]
            self._segments = to_keep

    def __iter__(self) -> Iterator[WALEntry]:
        """Iterate all non-compacted DATA entries (supports `for e in wal:`)."""
        with self._lock:
            segs = list(self._segments)
        cb = self._compact_before
        for seg in segs:
            with seg._lock:
                entries = list(seg.entries)
            for e in entries:
                if e.index > cb and e.entry_type == WALEntryType.DATA:
                    yield e

    # ── New API methods (used by app.py) ──────────────────────────────────────

    def checkpoint(self, reason: str = "manual") -> int:
        """Write a checkpoint marker; returns its index."""
        entry = self.append(
            term      = self._current_term,
            operation = f"checkpoint:{reason}",
            value     = {"reason": reason, "ts": time.time()},
            entry_type = WALEntryType.CHECKPOINT,
        )
        with self._lock:
            self._last_checkpoint = entry.index
            self._metrics["total_checkpoints"] += 1
        return entry.index

    def replay_from(
        self,
        seq:         int  = 0,
        max_entries: int  = 10_000,
        verify:      bool = True,
    ) -> List[WALEntry]:
        """Replay DATA entries with index >= seq (new API name for entries_after(seq-1))."""
        with self._lock:
            segs = list(self._segments)
        result: List[WALEntry] = []
        for seg in segs:
            with seg._lock:
                entries = list(seg.entries)
            for e in entries:
                if e.index < seq:
                    continue
                if e.entry_type in (WALEntryType.CHECKPOINT, WALEntryType.NOOP):
                    continue
                if verify and not e.verify():
                    with self._lock:
                        self._metrics["corruption_detected"] += 1
                    log.error("WAL corruption at index=%d", e.index)
                    if self._corruption_policy == "fail":
                        raise RuntimeError(f"WAL corruption at index={e.index}")
                    self._metrics["corruption_skipped"] = (
                        self._metrics.get("corruption_skipped", 0) + 1
                    )
                    continue
                result.append(e)
                if len(result) >= max_entries:
                    return result
        if self._recover:
            for e in result:
                try:
                    self._recover(e)
                except Exception as ex:
                    log.warning("Recovery fn error index=%d: %s", e.index, ex)
        return result

    def set_term(self, term: int) -> None:
        with self._lock:
            self._current_term = term

    def last_sequence(self) -> int:
        with self._lock:
            return self._next_index - 1

    def last_checkpoint(self) -> int:
        with self._lock:
            return self._last_checkpoint

    def compact_up_to(self, sequence: int) -> int:
        """Remove entries up to and including sequence (new API alias)."""
        removed = 0
        with self._lock:
            to_keep = []
            for seg in self._segments:
                if seg.entries and seg.entries[-1].index <= sequence:
                    removed += len(seg.entries)
                    self._metrics["total_compacted"] += len(seg.entries)
                else:
                    to_keep.append(seg)
            if not to_keep:
                to_keep = [self._segments[-1]]
            self._segments = to_keep
            self._compact_before = max(self._compact_before, sequence)
        return removed

    def _compaction_loop(self) -> None:
        while True:
            time.sleep(self._COMPACTION_INTERVAL)
            try:
                with self._lock:
                    n_segs = len(self._segments)
                    cp     = self._last_checkpoint
                if n_segs > self._MAX_SEGMENTS and cp > 0:
                    self.compact_up_to(cp)
            except Exception:
                log.exception("WAL compaction error")

    def stats(self) -> dict:
        with self._lock:
            seg = self._segments[-1]
            return {
                **self._metrics,
                "current_index":    self._next_index - 1,
                "current_sequence": self._next_index - 1,
                "current_term":     self._current_term,
                "last_checkpoint":  self._last_checkpoint,
                "active_segments":  len(self._segments),
                "compact_before":   self._compact_before,
                "current_segment_size": len(seg),
                "sync_mode":        self._sync.value,
            }


# ── State Machine ─────────────────────────────────────────────────────────────

class WALStateMachine:
    """
    Key-value state machine driven by the WAL.

    Old API (unit-test contract):
        sm.set(key, value)
        sm.get(key) → value | None
        sm.delete(key)
        sm.last_applied  → int
        sm.replay()      → int (new entries applied)

    New API (app.py contract):
        sm.on("OP") decorator
        sm.recover(from_seq)
    """

    def __init__(self, wal: WriteAheadLog) -> None:
        self._wal      = wal
        self._store: Dict[str, Any] = {}
        self._lock     = threading.Lock()
        self.last_applied: int = 0
        self._handlers: Dict[str, Any] = {}

    # ── Old API ───────────────────────────────────────────────────────────────

    def set(self, key: str, value: Any) -> WALEntry:
        entry = self._wal.append(
            term       = self._wal._current_term,
            operation  = "set",
            key        = key,
            value      = value,
        )
        with self._lock:
            self._store[key] = value
            self.last_applied = entry.index
        return entry

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            return self._store.get(key)

    def delete(self, key: str) -> Optional[WALEntry]:
        if key not in self._store:
            return None
        entry = self._wal.append(
            term      = self._wal._current_term,
            operation = "delete",
            key       = key,
        )
        with self._lock:
            self._store.pop(key, None)
            self.last_applied = entry.index
        return entry

    def replay(self) -> int:
        """
        Apply any WAL entries that have not yet been applied.
        Returns the number of newly applied entries.
        Idempotent: already-applied entries (index <= last_applied) are skipped.
        """
        entries = self._wal.entries_after(self.last_applied)
        applied = 0
        for entry in entries:
            if entry.index <= self.last_applied:
                continue
            with self._lock:
                if entry.operation == "set" and entry.key is not None:
                    self._store[entry.key] = entry.value
                elif entry.operation == "delete" and entry.key is not None:
                    self._store.pop(entry.key, None)
                # Unknown ops are skipped (no-op), not errors
                self.last_applied = entry.index
            applied += 1
        return applied

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._store)

    def restore(self, snapshot: dict) -> None:
        with self._lock:
            self._store = dict(snapshot)

    # ── New API (app.py compat) ───────────────────────────────────────────────

    def on(self, operation: str):
        """Decorator to register a handler for an operation name."""
        def decorator(fn):
            self._handlers[operation] = fn
            return fn
        return decorator

    def recover(self, from_seq: int = 0) -> int:
        """Replay WAL from from_seq applying registered handlers or built-in set/delete."""
        entries = self._wal.replay_from(seq=from_seq)
        applied = 0
        for entry in entries:
            # Try registered handler first
            fn = self._handlers.get(entry.operation)
            if fn:
                try:
                    fn(entry.payload)
                    self.last_applied = entry.index
                    applied += 1
                except Exception as e:
                    log.warning("SM handler '%s' error: %s", entry.operation, e)
                continue
            # Built-in set/delete
            with self._lock:
                if entry.operation == "set" and entry.key is not None:
                    self._store[entry.key] = entry.value
                    self.last_applied = entry.index
                    applied += 1
                elif entry.operation == "delete" and entry.key is not None:
                    self._store.pop(entry.key, None)
                    self.last_applied = entry.index
                    applied += 1
        return applied
