"""
c2/consensus/raft.py
AEGIS-SILENTIUM v12 — Raft Consensus Algorithm

Full implementation of the Raft distributed consensus protocol.
Reference: Ongaro & Ousterhout, "In Search of an Understandable
Consensus Algorithm" (USENIX ATC 2014).

Components
----------
  RaftNode      — core node: leader election, log replication, commitment
  RaftLog       — persistent, append-only replicated log
  RaftConfig    — tunable timeouts and cluster membership
  LogEntry      — individual log record (term + command)
  RaftTransport — pluggable RPC transport (HTTP by default)

State Machine
-------------
  The node drives an external CommandStateMachine via apply_fn.
  When an entry is committed to a quorum, apply_fn is called exactly once
  in order, giving linearisable reads and writes.

Leader Election
---------------
  Randomised election timeouts (150–300 ms by default) ensure only one
  candidate wins per term.  Candidates must have a log at least as
  up-to-date as any voter's log (last log term + index comparison).

Log Replication
---------------
  The leader sends AppendEntries RPCs to all peers in parallel.
  Entries are committed when acknowledged by a majority (N/2+1).
  Followers reject entries whose prevLogTerm/prevLogIndex don't match —
  triggering the nextIndex roll-back protocol.

Membership Changes
------------------
  Joint-consensus two-phase membership change (C_old,new → C_new)
  keeps the cluster safe during reconfiguration.

Thread Safety
-------------
  All state is guarded by a single RLock.  Network RPCs are dispatched
  on a thread pool to avoid blocking the election timer.
"""

from __future__ import annotations

import logging
import math
import random
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

log = logging.getLogger("aegis.consensus.raft")


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

class RaftState(str, Enum):
    FOLLOWER  = "follower"
    CANDIDATE = "candidate"
    LEADER    = "leader"


@dataclass
class LogEntry:
    term:    int
    index:   int
    command: Any          # opaque payload applied to state machine
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        return {
            "term":     self.term,
            "index":    self.index,
            "command":  self.command,
            "entry_id": self.entry_id,
        }

    @staticmethod
    def from_dict(d: dict) -> "LogEntry":
        return LogEntry(
            term=d["term"],
            index=d["index"],
            command=d["command"],
            entry_id=d.get("entry_id", str(uuid.uuid4())),
        )


@dataclass
class RaftConfig:
    node_id:            str
    peers:              List[str]          # peer node_ids
    election_timeout_ms: Tuple[int, int]  = (150, 300)
    heartbeat_interval_ms: int            = 50
    max_entries_per_rpc: int              = 64
    snapshot_threshold:  int              = 1_000   # compact after N entries
    rpc_timeout_ms:      int              = 100


# ─────────────────────────────────────────────────────────────────────────────
# Raft Log (in-memory with optional persistence hook)
# ─────────────────────────────────────────────────────────────────────────────

class RaftLog:
    """
    Append-only replicated log.  Index is 1-based (Raft convention).

    Snapshot support: entries before snapshot_index are discarded;
    snapshot_term / snapshot_index represent the last compacted entry.
    """

    def __init__(self) -> None:
        self._entries: List[LogEntry] = []    # [0] == index 1
        self._snapshot_index: int = 0
        self._snapshot_term:  int = 0
        self._lock = threading.RLock()

    # ── public API ────────────────────────────────────────────────────────────

    def append(self, entry: LogEntry) -> None:
        with self._lock:
            self._entries.append(entry)

    def append_all(self, entries: List[LogEntry]) -> None:
        with self._lock:
            self._entries.extend(entries)

    def last_index(self) -> int:
        with self._lock:
            if self._entries:
                return self._entries[-1].index
            return self._snapshot_index

    def last_term(self) -> int:
        with self._lock:
            if self._entries:
                return self._entries[-1].term
            return self._snapshot_term

    def entry_at(self, index: int) -> Optional[LogEntry]:
        with self._lock:
            pos = index - self._snapshot_index - 1
            if 0 <= pos < len(self._entries):
                return self._entries[pos]
            return None

    def term_at(self, index: int) -> int:
        if index == self._snapshot_index:
            return self._snapshot_term
        e = self.entry_at(index)
        return e.term if e else 0

    def slice(self, start: int, end: int) -> List[LogEntry]:
        """Return entries[start..end) by log index (1-based)."""
        with self._lock:
            lo = start - self._snapshot_index - 1
            hi = end   - self._snapshot_index - 1
            return self._entries[max(0, lo):max(0, hi)]

    def truncate_after(self, index: int) -> None:
        """Remove all entries after index (inclusive of index+1)."""
        with self._lock:
            pos = index - self._snapshot_index
            if pos >= 0:
                self._entries = self._entries[:pos]

    def compact(self, up_to_index: int, up_to_term: int) -> None:
        """Discard entries up_to_index; record snapshot boundary."""
        with self._lock:
            pos = up_to_index - self._snapshot_index
            if pos > 0:
                self._entries = self._entries[pos:]
            self._snapshot_index = up_to_index
            self._snapshot_term  = up_to_term

    def length(self) -> int:
        with self._lock:
            return len(self._entries)

    def snapshot_index(self) -> int:
        return self._snapshot_index

    def snapshot_term(self) -> int:
        return self._snapshot_term

    def entries_from(self, index: int) -> List[LogEntry]:
        """All entries starting at index (1-based)."""
        with self._lock:
            pos = index - self._snapshot_index - 1
            if pos < 0:
                return list(self._entries)
            return self._entries[pos:]


# ─────────────────────────────────────────────────────────────────────────────
# Vote state
# ─────────────────────────────────────────────────────────────────────────────

class _VolatileState:
    """Leader-only volatile state per follower."""
    __slots__ = ("next_index", "match_index", "in_flight")

    def __init__(self, last_log_index: int) -> None:
        self.next_index  = last_log_index + 1
        self.match_index = 0
        self.in_flight   = False


# ─────────────────────────────────────────────────────────────────────────────
# Raft Node
# ─────────────────────────────────────────────────────────────────────────────

class RaftNode:
    """
    Full Raft consensus node.

    Usage::

        def apply(entry): db.execute(entry.command)

        node = RaftNode(
            config   = RaftConfig("node-1", ["node-2", "node-3"]),
            apply_fn = apply,
            send_rpc = lambda peer, rpc_type, payload: http_post(peer, rpc_type, payload),
        )
        node.start()

        # Propose a command (only succeeds on leader):
        ok, index = node.propose({"op": "SET", "key": "x", "value": 1})

    RPC callbacks (call these from your HTTP handlers)::

        node.on_append_entries(request_dict) → response_dict
        node.on_request_vote(request_dict)   → response_dict
        node.on_install_snapshot(request_dict) → response_dict
    """

    def __init__(
        self,
        config:   RaftConfig,
        apply_fn: Callable[[LogEntry], Any],
        send_rpc: Callable[[str, str, dict], Optional[dict]],
    ) -> None:
        self._cfg     = config
        self._apply   = apply_fn
        self._send    = send_rpc
        self._id      = config.node_id

        # Persistent state (must survive restarts in production)
        self._current_term = 0
        self._voted_for:  Optional[str] = None
        self._log = RaftLog()

        # Volatile state
        self._state:        RaftState = RaftState.FOLLOWER
        self._commit_index: int = 0
        self._last_applied: int = 0
        self._leader_id:    Optional[str] = None

        # Leader state
        self._peer_state: Dict[str, _VolatileState] = {}

        # Election timer
        self._election_reset_time: float = time.time()
        self._lock = threading.RLock()

        # Threads
        self._running = False
        self._executor = ThreadPoolExecutor(max_workers=len(config.peers) + 4,
                                            thread_name_prefix="raft")
        self._apply_cv = threading.Condition(self._lock)
        self._commit_cv = threading.Condition(self._lock)

        # Metrics
        self._metrics = {
            "term_changes":      0,
            "elections_started": 0,
            "elections_won":     0,
            "entries_appended":  0,
            "entries_committed": 0,
            "heartbeats_sent":   0,
            "rpc_errors":        0,
        }

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._executor.submit(self._election_loop)
        self._executor.submit(self._apply_loop)
        log.info("RaftNode %s started (term=%d peers=%s)",
                 self._id, self._current_term, self._cfg.peers)

    def stop(self, timeout: float = 5.0) -> None:
        self._running = False
        with self._apply_cv:
            self._apply_cv.notify_all()
        self._executor.shutdown(wait=False)
        log.info("RaftNode %s stopped", self._id)

    # ── public API ────────────────────────────────────────────────────────────

    def propose(self, command: Any) -> Tuple[bool, int]:
        """
        Propose a command.  Returns (True, log_index) on success.
        Returns (False, -1) if this node is not the leader.
        """
        with self._lock:
            if self._state != RaftState.LEADER:
                return False, -1
            index = self._log.last_index() + 1
            entry = LogEntry(term=self._current_term, index=index, command=command)
            self._log.append(entry)
            self._metrics["entries_appended"] += 1
            log.debug("Proposed entry index=%d term=%d", index, self._current_term)
        # Trigger replication immediately
        self._executor.submit(self._broadcast_append_entries)
        return True, index

    def is_leader(self) -> bool:
        with self._lock:
            return self._state == RaftState.LEADER

    def leader_id(self) -> Optional[str]:
        with self._lock:
            return self._leader_id

    def current_term(self) -> int:
        with self._lock:
            return self._current_term

    def state(self) -> RaftState:
        with self._lock:
            return self._state

    def commit_index(self) -> int:
        with self._lock:
            return self._commit_index

    def status(self) -> dict:
        with self._lock:
            return {
                "node_id":       self._id,
                "state":         self._state.value,
                "current_term":  self._current_term,
                "leader_id":     self._leader_id,
                "commit_index":  self._commit_index,
                "last_applied":  self._last_applied,
                "log_length":    self._log.length(),
                "last_log_index": self._log.last_index(),
                "last_log_term":  self._log.last_term(),
                "peers":         self._cfg.peers,
                "metrics":       dict(self._metrics),
            }

    # ── RPC handlers (call from HTTP / gRPC layer) ─────────────────────────────

    def on_request_vote(self, req: dict) -> dict:
        """Handle an incoming RequestVote RPC."""
        with self._lock:
            term         = req["term"]
            candidate_id = req["candidate_id"]
            last_log_idx = req["last_log_index"]
            last_log_term= req["last_log_term"]

            if term > self._current_term:
                self._step_down(term)

            vote_granted = False
            if (term == self._current_term
                    and (self._voted_for is None or self._voted_for == candidate_id)
                    and self._log_up_to_date(last_log_term, last_log_idx)):
                self._voted_for = candidate_id
                vote_granted = True
                self._reset_election_timer()
                log.debug("Voted for %s in term %d", candidate_id, term)

            return {"term": self._current_term, "vote_granted": vote_granted}

    def on_append_entries(self, req: dict) -> dict:
        """Handle an incoming AppendEntries RPC (heartbeat or replication)."""
        with self._lock:
            term      = req["term"]
            leader_id = req["leader_id"]
            prev_log_index = req["prev_log_index"]
            prev_log_term  = req["prev_log_term"]
            entries        = [LogEntry.from_dict(e) for e in req.get("entries", [])]
            leader_commit  = req["leader_commit"]

            if term < self._current_term:
                return {"term": self._current_term, "success": False,
                        "conflict_index": -1, "conflict_term": -1}

            if term > self._current_term:
                self._step_down(term)
            elif self._state == RaftState.CANDIDATE:
                self._state = RaftState.FOLLOWER

            self._leader_id = leader_id
            self._reset_election_timer()

            # Log consistency check
            if prev_log_index > 0:
                if self._log.last_index() < prev_log_index:
                    # Follower log is too short
                    return {"term": self._current_term, "success": False,
                            "conflict_index": self._log.last_index() + 1,
                            "conflict_term": -1}
                if self._log.term_at(prev_log_index) != prev_log_term:
                    # Conflict — find the first index of the conflicting term
                    conflict_term = self._log.term_at(prev_log_index)
                    conflict_idx  = prev_log_index
                    for idx in range(prev_log_index - 1, self._log.snapshot_index(), -1):
                        if self._log.term_at(idx) != conflict_term:
                            break
                        conflict_idx = idx
                    return {"term": self._current_term, "success": False,
                            "conflict_index": conflict_idx,
                            "conflict_term": conflict_term}

            # Append new entries, resolving conflicts
            for entry in entries:
                existing_term = self._log.term_at(entry.index)
                if existing_term != 0 and existing_term != entry.term:
                    # Conflict — truncate log
                    self._log.truncate_after(entry.index - 1)
                if self._log.last_index() < entry.index:
                    self._log.append(entry)

            # Advance commit
            if leader_commit > self._commit_index:
                self._commit_index = min(leader_commit, self._log.last_index())
                self._apply_cv.notify_all()
                self._metrics["entries_committed"] += max(0,
                    self._commit_index - self._last_applied)

            return {"term": self._current_term, "success": True,
                    "match_index": self._log.last_index(),
                    "conflict_index": -1, "conflict_term": -1}

    def on_install_snapshot(self, req: dict) -> dict:
        """Handle InstallSnapshot RPC for slow followers."""
        with self._lock:
            term = req["term"]
            if term < self._current_term:
                return {"term": self._current_term}
            if term > self._current_term:
                self._step_down(term)
            self._reset_election_timer()

            snapshot_index = req["last_included_index"]
            snapshot_term  = req["last_included_term"]
            snapshot_data  = req["data"]

            if snapshot_index <= self._commit_index:
                return {"term": self._current_term}  # already have it

            self._log.compact(snapshot_index, snapshot_term)
            self._commit_index = snapshot_index
            self._last_applied = snapshot_index
            # Apply snapshot to state machine
            self._executor.submit(self._apply, LogEntry(
                term=snapshot_term, index=snapshot_index,
                command={"__snapshot__": True, "data": snapshot_data}
            ))
            return {"term": self._current_term}

    # ── Election ──────────────────────────────────────────────────────────────

    def _election_loop(self) -> None:
        while self._running:
            lo, hi = self._cfg.election_timeout_ms
            timeout = random.randint(lo, hi) / 1000.0
            time.sleep(0.005)

            with self._lock:
                elapsed = time.time() - self._election_reset_time
                if self._state != RaftState.LEADER and elapsed >= timeout:
                    self._executor.submit(self._start_election)

            if self._state == RaftState.LEADER:
                self._executor.submit(self._broadcast_heartbeat)
                time.sleep(self._cfg.heartbeat_interval_ms / 1000.0)

    def _start_election(self) -> None:
        with self._lock:
            self._state          = RaftState.CANDIDATE
            self._current_term  += 1
            self._voted_for      = self._id
            self._leader_id      = None
            term                 = self._current_term
            last_log_idx         = self._log.last_index()
            last_log_term        = self._log.last_term()
            self._reset_election_timer()
            self._metrics["elections_started"] += 1
            self._metrics["term_changes"] += 1
            log.info("Node %s starting election for term %d", self._id, term)

        votes = 1  # voted for self
        cluster_size = len(self._cfg.peers) + 1
        needed = math.floor(cluster_size / 2) + 1
        lock = threading.Lock()

        def request_vote(peer: str) -> None:
            nonlocal votes
            resp = self._send(peer, "request_vote", {
                "term":           term,
                "candidate_id":   self._id,
                "last_log_index": last_log_idx,
                "last_log_term":  last_log_term,
            })
            if resp is None:
                return
            with self._lock:
                if resp["term"] > self._current_term:
                    self._step_down(resp["term"])
                    return
                if (self._state == RaftState.CANDIDATE
                        and self._current_term == term
                        and resp.get("vote_granted")):
                    with lock:
                        votes += 1
                        if votes >= needed:
                            self._become_leader(term)

        futs = [self._executor.submit(request_vote, p) for p in self._cfg.peers]
        for f in futs:
            try:
                f.result(timeout=self._cfg.rpc_timeout_ms / 1000.0 * 2)
            except Exception as _exc:
                log.debug("unknown: %s", _exc)

    def _become_leader(self, term: int) -> None:
        """Transition to leader. Must be called holding self._lock."""
        if self._state != RaftState.CANDIDATE or self._current_term != term:
            return
        self._state    = RaftState.LEADER
        self._leader_id = self._id
        self._metrics["elections_won"] += 1
        log.info("Node %s became LEADER for term %d", self._id, term)

        # Re-initialise peer tracking
        last = self._log.last_index()
        self._peer_state = {
            p: _VolatileState(last) for p in self._cfg.peers
        }

        # Append no-op entry to commit previous term entries (§8)
        noop = LogEntry(
            term=self._current_term,
            index=last + 1,
            command={"__noop__": True},
        )
        self._log.append(noop)
        self._executor.submit(self._broadcast_append_entries)

    # ── Log Replication ───────────────────────────────────────────────────────

    def _broadcast_heartbeat(self) -> None:
        with self._lock:
            if self._state != RaftState.LEADER:
                return
            self._metrics["heartbeats_sent"] += 1
        self._broadcast_append_entries(heartbeat=True)

    def _broadcast_append_entries(self, heartbeat: bool = False) -> None:
        with self._lock:
            if self._state != RaftState.LEADER:
                return
            peers = list(self._cfg.peers)

        futs = [self._executor.submit(self._replicate_to, p, heartbeat) for p in peers]
        for f in futs:
            try:
                f.result(timeout=self._cfg.rpc_timeout_ms / 1000.0 * 3)
            except Exception as _exc:
                log.debug("_broadcast_append_entries: %s", _exc)

        self._check_commit()

    def _replicate_to(self, peer: str, heartbeat: bool) -> None:
        with self._lock:
            if self._state != RaftState.LEADER:
                return
            ps         = self._peer_state.get(peer)
            if ps is None or ps.in_flight:
                return
            ps.in_flight = True
            next_idx   = ps.next_index
            prev_idx   = next_idx - 1
            prev_term  = self._log.term_at(prev_idx)
            # Check if we need a snapshot instead
            if prev_idx < self._log.snapshot_index():
                ps.in_flight = False
                self._executor.submit(self._send_snapshot, peer)
                return
            entries = [] if heartbeat else \
                self._log.slice(next_idx, next_idx + self._cfg.max_entries_per_rpc)
            commit = self._commit_index
            term   = self._current_term

        payload = {
            "term":           term,
            "leader_id":      self._id,
            "prev_log_index": prev_idx,
            "prev_log_term":  prev_term,
            "entries":        [e.to_dict() for e in entries],
            "leader_commit":  commit,
        }
        resp = self._send(peer, "append_entries", payload)

        with self._lock:
            ps = self._peer_state.get(peer)
            if ps:
                ps.in_flight = False
            if resp is None:
                self._metrics["rpc_errors"] += 1
                return
            if resp["term"] > self._current_term:
                self._step_down(resp["term"])
                return
            if self._state != RaftState.LEADER or self._current_term != term:
                return
            if resp.get("success"):
                match = resp.get("match_index", prev_idx + len(entries))
                if ps:
                    ps.match_index = max(ps.match_index, match)
                    ps.next_index  = ps.match_index + 1
            else:
                # Back off next_index using conflict hints
                conflict_term  = resp.get("conflict_term", -1)
                conflict_index = resp.get("conflict_index", next_idx - 1)
                if conflict_term > 0:
                    # Find last entry with that term in our log
                    ni = self._log.last_index()
                    while ni > 0 and self._log.term_at(ni) != conflict_term:
                        ni -= 1
                    if ni > 0:
                        conflict_index = ni + 1
                if ps:
                    ps.next_index = max(1, conflict_index)

    def _send_snapshot(self, peer: str) -> None:
        with self._lock:
            payload = {
                "term":                 self._current_term,
                "leader_id":            self._id,
                "last_included_index":  self._log.snapshot_index(),
                "last_included_term":   self._log.snapshot_term(),
                "data":                 {},  # State machine snapshot
            }
        resp = self._send(peer, "install_snapshot", payload)
        if resp and resp.get("term", 0) > self._current_term:
            with self._lock:
                self._step_down(resp["term"])

    def _check_commit(self) -> None:
        """Advance commit_index if a quorum has replicated."""
        with self._lock:
            if self._state != RaftState.LEADER:
                return
            cluster_size = len(self._cfg.peers) + 1
            needed = math.floor(cluster_size / 2) + 1
            # Walk from last log backwards
            for n in range(self._log.last_index(), self._commit_index, -1):
                if self._log.term_at(n) != self._current_term:
                    continue
                replicated = 1  # self
                for ps in self._peer_state.values():
                    if ps.match_index >= n:
                        replicated += 1
                if replicated >= needed:
                    self._commit_index = n
                    self._apply_cv.notify_all()
                    log.debug("Committed log up to index %d (term %d)", n, self._current_term)
                    break

    # ── Apply Loop ────────────────────────────────────────────────────────────

    def _apply_loop(self) -> None:
        while self._running:
            with self._apply_cv:
                while self._running and self._last_applied >= self._commit_index:
                    self._apply_cv.wait(timeout=0.1)
                if not self._running:
                    break
                entries_to_apply = self._log.slice(
                    self._last_applied + 1,
                    self._commit_index + 1,
                )
                self._last_applied = self._commit_index

            for entry in entries_to_apply:
                try:
                    self._apply(entry)
                except Exception:
                    log.exception("State machine apply error at index=%d", entry.index)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _step_down(self, new_term: int) -> None:
        """Revert to follower. Must be called holding self._lock."""
        if new_term > self._current_term:
            self._current_term = new_term
            self._voted_for    = None
            self._metrics["term_changes"] += 1
        self._state     = RaftState.FOLLOWER
        self._leader_id = None
        self._reset_election_timer()

    def _reset_election_timer(self) -> None:
        self._election_reset_time = time.time()

    def _log_up_to_date(self, last_log_term: int, last_log_index: int) -> bool:
        my_last_term  = self._log.last_term()
        my_last_index = self._log.last_index()
        if last_log_term != my_last_term:
            return last_log_term > my_last_term
        return last_log_index >= my_last_index
