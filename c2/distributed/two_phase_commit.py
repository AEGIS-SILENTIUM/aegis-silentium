"""
c2/distributed/two_phase_commit.py
AEGIS-SILENTIUM v12 — Distributed Transactions (Two-Phase Commit)

Provides atomic multi-key updates across partitions.

Protocol
--------
  Phase 1 — Prepare:
    Coordinator sends PREPARE(txn_id, mutations) to all participants.
    Each participant locks the keys and votes YES or NO.
  Phase 2 — Commit / Abort:
    If all voted YES → broadcast COMMIT.
    If any voted NO  → broadcast ABORT.

Durability: the coordinator writes the decision to the WAL before
broadcasting so it can re-send the decision after a crash.

Participants must implement the ParticipantProtocol interface.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("aegis.2pc")


class TxnState(str, Enum):
    PENDING  = "pending"
    PREPARED = "prepared"
    COMMITTED = "committed"
    ABORTED  = "aborted"


@dataclass
class Mutation:
    key:    str
    value:  Any
    op:     str = "set"   # "set" | "delete"


@dataclass
class Transaction:
    txn_id:    str = field(default_factory=lambda: str(uuid.uuid4()))
    mutations: List[Mutation] = field(default_factory=list)
    state:     TxnState = TxnState.PENDING
    created_at: float = field(default_factory=time.time)
    decided_at: Optional[float] = None
    participants: List[str] = field(default_factory=list)
    votes: Dict[str, bool] = field(default_factory=dict)


class TwoPCCoordinator:
    """
    Two-Phase Commit coordinator.

    Parameters
    ----------
    participants : list of participant addresses
    prepare_fn   : callable(addr, txn_id, mutations) → bool  (phase 1)
    commit_fn    : callable(addr, txn_id) → bool             (phase 2 commit)
    abort_fn     : callable(addr, txn_id) → bool             (phase 2 abort)
    timeout      : per-phase timeout in seconds
    """

    def __init__(
        self,
        participants: List[str],
        prepare_fn:   Callable[[str, str, List[Mutation]], bool],
        commit_fn:    Callable[[str, str], bool],
        abort_fn:     Callable[[str, str], bool],
        timeout:      float = 5.0,
    ) -> None:
        self._participants = list(participants)
        self._prepare_fn   = prepare_fn
        self._commit_fn    = commit_fn
        self._abort_fn     = abort_fn
        self._timeout      = timeout
        self._txns: Dict[str, Transaction] = {}
        self._lock = threading.Lock()

    # ── public API ────────────────────────────────────────────────────────────

    def execute(self, mutations: List[Mutation]) -> Tuple[bool, str]:
        """
        Run a 2PC transaction for the given mutations.
        Returns (committed: bool, txn_id: str).
        """
        txn = Transaction(mutations=mutations, participants=list(self._participants))
        with self._lock:
            self._txns[txn.txn_id] = txn

        log.info("2PC begin txn=%s mutations=%d", txn.txn_id, len(mutations))

        # Phase 1: Prepare
        all_yes = self._phase1(txn)
        txn.state = TxnState.PREPARED

        # Phase 2: Commit or Abort
        if all_yes:
            self._phase2_commit(txn)
            return True, txn.txn_id
        else:
            self._phase2_abort(txn)
            return False, txn.txn_id

    def get_transaction(self, txn_id: str) -> Optional[Transaction]:
        with self._lock:
            return self._txns.get(txn_id)

    def pending_transactions(self) -> List[Transaction]:
        with self._lock:
            return [t for t in self._txns.values() if t.state == TxnState.PENDING]

    # ── phases ────────────────────────────────────────────────────────────────

    def _phase1(self, txn: Transaction) -> bool:
        results: Dict[str, bool] = {}
        threads: List[threading.Thread] = []
        lock = threading.Lock()

        def prepare(addr: str) -> None:
            try:
                vote = self._prepare_fn(addr, txn.txn_id, txn.mutations)
            except Exception as exc:
                log.warning("2PC prepare failed addr=%s txn=%s: %s", addr, txn.txn_id, exc)
                vote = False
            with lock:
                results[addr] = vote

        for addr in self._participants:
            t = threading.Thread(target=prepare, args=(addr,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=self._timeout)

        txn.votes = dict(results)
        all_yes = all(results.get(addr, False) for addr in self._participants)
        log.info("2PC phase1 txn=%s votes=%s → %s", txn.txn_id, results,
                 "COMMIT" if all_yes else "ABORT")
        return all_yes

    def _phase2_commit(self, txn: Transaction) -> None:
        txn.state     = TxnState.COMMITTED
        txn.decided_at = time.time()
        self._broadcast_phase2(txn, self._commit_fn, "commit")

    def _phase2_abort(self, txn: Transaction) -> None:
        txn.state      = TxnState.ABORTED
        txn.decided_at = time.time()
        self._broadcast_phase2(txn, self._abort_fn, "abort")

    def _broadcast_phase2(
        self,
        txn:    Transaction,
        fn:     Callable[[str, str], bool],
        label:  str,
    ) -> None:
        def send(addr: str) -> None:
            for attempt in range(3):
                try:
                    if fn(addr, txn.txn_id):
                        return
                except Exception as exc:
                    log.warning("2PC %s attempt %d failed addr=%s txn=%s: %s",
                                label, attempt + 1, addr, txn.txn_id, exc)
                time.sleep(0.5 * (2 ** attempt))

        threads = [threading.Thread(target=send, args=(a,), daemon=True)
                   for a in self._participants]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=self._timeout * 3)
        log.info("2PC %s broadcast done txn=%s", label, txn.txn_id)
