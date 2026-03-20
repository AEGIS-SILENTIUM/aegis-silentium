"""
c2/consensus/state_machine.py
AEGIS-SILENTIUM v12 — Raft State Machine Implementations

Pluggable state machines driven by the Raft log.

CommandStateMachine — generic command dispatcher (register handlers per op)
KVStateMachine      — distributed key-value store (GET/SET/DEL/CAS/INCR)
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Dict, Optional

from .raft import LogEntry

log = logging.getLogger("aegis.consensus.state_machine")


class CommandStateMachine:
    """
    Generic state machine that dispatches LogEntry.command dicts
    to registered handler functions.

    Usage::

        sm = CommandStateMachine()

        @sm.handler("SET")
        def handle_set(cmd): store[cmd["key"]] = cmd["value"]

        # Wire into RaftNode
        node = RaftNode(config, apply_fn=sm.apply, send_rpc=...)
    """

    def __init__(self) -> None:
        self._handlers: Dict[str, Callable[[dict], Any]] = {}
        self._applied_count = 0
        self._last_index    = 0
        self._lock = threading.RLock()

    def handler(self, op: str) -> Callable:
        """Decorator — register a handler for a command op."""
        def decorator(fn: Callable) -> Callable:
            self._handlers[op] = fn
            return fn
        return decorator

    def register(self, op: str, fn: Callable[[dict], Any]) -> None:
        with self._lock:
            self._handlers[op] = fn

    def apply(self, entry: LogEntry) -> Any:
        """Called by RaftNode for each committed log entry."""
        with self._lock:
            cmd = entry.command
            if not isinstance(cmd, dict):
                return None

            op = cmd.get("op") or cmd.get("__type__")

            # Skip infrastructure no-ops
            if cmd.get("__noop__") or cmd.get("__snapshot__"):
                self._last_index = entry.index
                return None

            handler = self._handlers.get(op)
            if handler is None:
                log.warning("No handler for op=%s index=%d", op, entry.index)
                return None

            try:
                result = handler(cmd)
                self._applied_count += 1
                self._last_index = entry.index
                return result
            except Exception:
                log.exception("Handler error op=%s index=%d", op, entry.index)
                return None

    def stats(self) -> dict:
        with self._lock:
            return {
                "applied_count": self._applied_count,
                "last_index":    self._last_index,
                "ops_registered": list(self._handlers.keys()),
            }


class KVStateMachine(CommandStateMachine):
    """
    Distributed key-value store state machine.

    Supported ops: SET, GET, DEL, CAS (compare-and-swap), INCR, KEYS
    """

    def __init__(self) -> None:
        super().__init__()
        self._store: Dict[str, Any] = {}
        self._store_lock = threading.RLock()

        self.register("SET",  self._op_set)
        self.register("DEL",  self._op_del)
        self.register("CAS",  self._op_cas)
        self.register("INCR", self._op_incr)
        self.register("MSET", self._op_mset)

    # ── Read (non-replicated, safe after apply) ───────────────────────────────

    def get(self, key: str) -> Optional[Any]:
        with self._store_lock:
            return self._store.get(key)

    def mget(self, keys: list) -> dict:
        with self._store_lock:
            return {k: self._store.get(k) for k in keys}

    def keys(self, prefix: str = "") -> list:
        with self._store_lock:
            return [k for k in self._store if k.startswith(prefix)]

    def snapshot(self) -> dict:
        with self._store_lock:
            return dict(self._store)

    def restore(self, data: dict) -> None:
        with self._store_lock:
            self._store = dict(data)

    # ── Write ops (applied through Raft log) ──────────────────────────────────

    def _op_set(self, cmd: dict) -> bool:
        with self._store_lock:
            self._store[cmd["key"]] = cmd["value"]
        return True

    def _op_del(self, cmd: dict) -> bool:
        with self._store_lock:
            existed = cmd["key"] in self._store
            self._store.pop(cmd["key"], None)
        return existed

    def _op_cas(self, cmd: dict) -> bool:
        """Atomic compare-and-swap. Returns True if swap occurred."""
        with self._store_lock:
            key      = cmd["key"]
            expected = cmd["expected"]
            new_val  = cmd["value"]
            if self._store.get(key) == expected:
                self._store[key] = new_val
                return True
            return False

    def _op_incr(self, cmd: dict) -> int:
        with self._store_lock:
            key    = cmd["key"]
            delta  = cmd.get("delta", 1)
            current = self._store.get(key, 0)
            new_val = int(current) + int(delta)
            self._store[key] = new_val
        return new_val

    def _op_mset(self, cmd: dict) -> int:
        with self._store_lock:
            pairs = cmd.get("pairs", {})
            self._store.update(pairs)
        return len(pairs)

    def apply(self, entry: LogEntry) -> Any:
        """Override to handle snapshot restores."""
        cmd = entry.command
        if isinstance(cmd, dict) and cmd.get("__snapshot__"):
            data = cmd.get("data", {})
            if data:
                self.restore(data)
            return None
        return super().apply(entry)
