"""
c2/distributed/gossip.py
AEGIS-SILENTIUM v12 — Gossip Protocol (SWIM-style)

Nodes use a SWIM-style gossip protocol to disseminate membership changes
and detect failures.  Each node maintains a list of live members and
periodically gossips to a randomly selected peer.

Failure detection
-----------------
  1. Probe a random peer directly (ping).
  2. If no ack within PROBE_TIMEOUT, ask k indirect peers (ping-req).
  3. If still no ack, mark peer as SUSPECT.
  4. If SUSPECT for > SUSPECT_TIMEOUT seconds, mark as DEAD and disseminate.

Membership dissemination
------------------------
  Each gossip round piggybacks membership deltas (JOIN, LEAVE, SUSPECT,
  DEAD) onto normal probe messages, spreading changes in O(log N) rounds.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional

log = logging.getLogger("aegis.gossip")


class MemberState(str, Enum):
    ALIVE   = "alive"
    SUSPECT = "suspect"
    DEAD    = "dead"
    LEFT    = "left"


@dataclass
class Member:
    node_id:      str
    address:      str          # "host:port"
    state:        MemberState = MemberState.ALIVE
    incarnation:  int = 0     # bumped when node refutes suspicion
    last_seen_ms: int = field(default_factory=lambda: int(time.time() * 1000))

    def to_dict(self) -> dict:
        return {
            "node_id":      self.node_id,
            "address":      self.address,
            "state":        self.state.value,
            "incarnation":  self.incarnation,
            "last_seen_ms": self.last_seen_ms,
        }

    @staticmethod
    def from_dict(d: dict) -> "Member":
        m = Member(
            node_id=d["node_id"],
            address=d["address"],
            state=MemberState(d.get("state", "alive")),
            incarnation=d.get("incarnation", 0),
        )
        m.last_seen_ms = d.get("last_seen_ms", m.last_seen_ms)
        return m


class GossipProtocol:
    """
    SWIM-style gossip membership protocol.

    Parameters
    ----------
    node_id       : unique ID of this node
    address       : "host:port" for this node
    probe_fn      : callable(target_address, message) → ack: bool
                    (the network layer; can be mocked in tests)
    gossip_fn     : callable(target_address, delta_list) → None
    probe_interval: seconds between probe rounds (default 1.0)
    suspect_timeout: seconds before SUSPECT → DEAD (default 5.0)
    fanout        : number of indirect probers (default 3)
    """

    def __init__(
        self,
        node_id: str,
        address: str,
        probe_fn:  Callable[[str, dict], bool],
        gossip_fn: Callable[[str, List[dict]], None],
        probe_interval:  float = 1.0,
        suspect_timeout: float = 5.0,
        fanout: int = 3,
    ) -> None:
        self._id       = node_id
        self._addr     = address
        self._probe    = probe_fn
        self._gossip   = gossip_fn
        self._interval = probe_interval
        self._sus_ttl  = suspect_timeout
        self._fanout   = fanout

        self._members: Dict[str, Member] = {
            node_id: Member(node_id=node_id, address=address)
        }
        self._suspect_since: Dict[str, float] = {}
        self._pending_deltas: List[dict]  = []
        self._lock    = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="gossip")
        self._thread.start()
        log.info("Gossip protocol started node_id=%s", self._id)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    # ── membership API ────────────────────────────────────────────────────────

    def join(self, member: Member) -> None:
        with self._lock:
            existing = self._members.get(member.node_id)
            if existing and member.incarnation <= existing.incarnation:
                return
            self._members[member.node_id] = member
            self._queue_delta(member)
            log.debug("Member joined: %s", member.node_id)

    def leave(self, node_id: str) -> None:
        with self._lock:
            m = self._members.get(node_id)
            if m:
                m.state = MemberState.LEFT
                self._queue_delta(m)

    def members(self) -> List[Member]:
        with self._lock:
            return [m for m in self._members.values() if m.state == MemberState.ALIVE]

    def all_members(self) -> List[Member]:
        with self._lock:
            return list(self._members.values())

    def merge_deltas(self, deltas: List[dict]) -> None:
        """Called when we receive a gossip message from a peer."""
        with self._lock:
            for d in deltas:
                incoming = Member.from_dict(d)
                existing = self._members.get(incoming.node_id)
                if existing is None or incoming.incarnation > existing.incarnation:
                    self._members[incoming.node_id] = incoming
                elif (
                    incoming.incarnation == existing.incarnation
                    and self._state_priority(incoming.state) > self._state_priority(existing.state)
                ):
                    existing.state = incoming.state

    # ── internal loop ─────────────────────────────────────────────────────────

    def _run(self) -> None:
        while self._running:
            try:
                self._probe_round()
                self._expire_suspects()
                self._gossip_round()
            except Exception:
                log.exception("Gossip round error")
            time.sleep(self._interval)

    def _probe_round(self) -> None:
        with self._lock:
            peers = [m for m in self._members.values()
                     if m.node_id != self._id and m.state == MemberState.ALIVE]
        if not peers:
            return
        target = random.choice(peers)
        ack = self._probe(target.address, {"type": "ping", "from": self._id})
        if ack:
            with self._lock:
                target.last_seen_ms = int(time.time() * 1000)
            return
        # Indirect probe
        indirect = random.sample(
            [p for p in peers if p.node_id != target.node_id],
            min(self._fanout, len(peers) - 1),
        )
        acked = any(
            self._probe(p.address, {"type": "ping-req", "target": target.address, "from": self._id})
            for p in indirect
        )
        if not acked:
            with self._lock:
                if target.node_id not in self._suspect_since:
                    target.state = MemberState.SUSPECT
                    self._suspect_since[target.node_id] = time.time()
                    self._queue_delta(target)
                    log.warning("Node suspected: %s", target.node_id)

    def _expire_suspects(self) -> None:
        now = time.time()
        with self._lock:
            expired = [nid for nid, t in self._suspect_since.items()
                       if now - t > self._sus_ttl]
            for nid in expired:
                m = self._members.get(nid)
                if m and m.state == MemberState.SUSPECT:
                    m.state = MemberState.DEAD
                    self._queue_delta(m)
                    log.warning("Node declared dead: %s", nid)
                del self._suspect_since[nid]

    def _gossip_round(self) -> None:
        with self._lock:
            peers = [m for m in self._members.values()
                     if m.node_id != self._id and m.state == MemberState.ALIVE]
            if not peers or not self._pending_deltas:
                return
            targets = random.sample(peers, min(self._fanout, len(peers)))
            deltas = list(self._pending_deltas)
            self._pending_deltas.clear()
        for t in targets:
            try:
                self._gossip(t.address, deltas)
            except Exception:
                log.debug("Gossip send failed to %s", t.address)

    def _queue_delta(self, member: Member) -> None:
        self._pending_deltas.append(member.to_dict())

    @staticmethod
    def _state_priority(state: MemberState) -> int:
        return {MemberState.ALIVE: 0, MemberState.SUSPECT: 1,
                MemberState.DEAD: 2, MemberState.LEFT: 3}.get(state, 0)
