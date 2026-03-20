"""
c2/cluster/coordinator.py

Distributed C2 cluster coordinator using Raft-inspired leader election.

Changes from previous version:
  - asyncio.Lock guards all mutable state (term, role, voted_for, leader_id)
    eliminating data races across the three concurrent coroutines.
  - _peer_discovery_loop() uses SCAN instead of KEYS (O(N) blocking).
  - Leader address reads use the already-open async Redis connection — no
    per-call connection allocation.
  - redirect_to_leader() is now async.
  - Step-down quorum check corrected: need alive >= quorum-1 (majority of peers).
  - Dead imports removed (os, asdict, ClusterState).
  - random imported at module level.
  - _local_ip() uses a context manager.
  - _new_election_deadline() is a module-level function.
"""

import asyncio
import hashlib
import json
import logging
import random
import socket
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

import aiohttp
import redis.asyncio as aioredis

log = logging.getLogger("c2.cluster")

# ── Constants ─────────────────────────────────────────────────────────────────
HEARTBEAT_INTERVAL   = 1.0
ELECTION_TIMEOUT_MIN = 3.0
ELECTION_TIMEOUT_MAX = 6.0
REDIS_LEADER_KEY     = "aegis:cluster:leader"
REDIS_LEADER_TTL     = 5
REDIS_NODE_PREFIX    = "aegis:cluster:node:"
REDIS_NODE_TTL       = 10


def _new_election_deadline() -> float:
    return random.uniform(ELECTION_TIMEOUT_MIN, ELECTION_TIMEOUT_MAX)


class NodeRole(str, Enum):
    LEADER    = "leader"
    FOLLOWER  = "follower"
    CANDIDATE = "candidate"


@dataclass
class ClusterNode:
    node_id:   str
    address:   str
    role:      NodeRole = NodeRole.FOLLOWER
    last_seen: float    = field(default_factory=time.time)
    term:      int      = 0
    version:   str      = "5.0"


class ClusterCoordinator:
    """
    Manages cluster membership, leader election, and automatic failover.

    All mutable cluster state is guarded by self._lock to prevent data races
    between the heartbeat, election, and peer-discovery coroutines.

    Usage:
        coord = ClusterCoordinator(redis_url, peer_addresses)
        await coord.start()
        if coord.is_leader():
            await dispatch_task(...)
    """

    def __init__(
        self,
        redis_url:      str,
        peer_addresses: List[str],
        bind_port:      int = 8444,
    ) -> None:
        self.node_id = self._stable_node_id()
        self.address = f"http://{self._local_ip()}:{bind_port}"
        self._lock   = asyncio.Lock()

        # Protected mutable state
        self._role:       NodeRole      = NodeRole.FOLLOWER
        self._term:       int           = 0
        self._voted_for:  Optional[str] = None
        self._leader_id:  Optional[str] = None
        self._peers:      List[str]     = list(peer_addresses)

        self._redis_url         = redis_url
        self._redis:             Optional[aioredis.Redis]        = None
        self._session:           Optional[aiohttp.ClientSession] = None
        self._last_heartbeat    = time.monotonic()
        self._election_deadline = _new_election_deadline()
        self._running           = False

    # ── Public API ────────────────────────────────────────────────────────────

    def is_leader(self) -> bool:
        return self._role == NodeRole.LEADER

    async def get_leader_address(self) -> Optional[str]:
        return await self._async_get_leader_addr()

    async def redirect_to_leader(self) -> Optional[str]:
        """Return leader address for 307 redirect, or None if this node is leader."""
        if self.is_leader():
            return None
        return await self._async_get_leader_addr()

    async def start(self) -> None:
        self._redis = await aioredis.from_url(self._redis_url, decode_responses=True)
        self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2.0))
        self._running = True
        log.info(f"Cluster node {self.node_id[:8]} starting at {self.address}")
        try:
            await asyncio.gather(
                self._heartbeat_loop(),
                self._election_loop(),
                self._peer_discovery_loop(),
            )
        finally:
            await self.stop()

    async def stop(self) -> None:
        self._running = False
        if self._session and not self._session.closed:
            await self._session.close()
        if self._redis:
            await self._redis.aclose()

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    async def _heartbeat_loop(self) -> None:
        while self._running:
            if self._role == NodeRole.LEADER:
                await self._send_heartbeats()
                await self._renew_leader_key()
            await asyncio.sleep(HEARTBEAT_INTERVAL)

    async def _send_heartbeats(self) -> None:
        async with self._lock:
            peers = list(self._peers)
            term  = self._term

        payload = {
            "type":      "heartbeat",
            "leader_id": self.node_id,
            "term":      term,
            "address":   self.address,
        }
        results = await asyncio.gather(
            *[self._post_peer(p, "/cluster/heartbeat", payload) for p in peers],
            return_exceptions=True,
        )
        alive = sum(1 for r in results if isinstance(r, dict))
        log.debug(f"Heartbeat: {alive}/{len(peers)} peers responded")

        # Quorum requires a majority of the whole cluster (self + peers).
        cluster_size = len(peers) + 1
        quorum       = (cluster_size // 2) + 1
        # We always count ourselves, so we need `alive` peers to reach quorum.
        if len(peers) > 0 and alive < quorum - 1:
            log.warning(f"Lost quorum ({alive} of {len(peers)} peers) — stepping down")
            await self._step_down()

    async def _renew_leader_key(self) -> None:
        async with self._lock:
            data = json.dumps({
                "node_id": self.node_id,
                "address": self.address,
                "term":    self._term,
            })
        await self._redis.setex(REDIS_LEADER_KEY, REDIS_LEADER_TTL, data)

    # ── Election ──────────────────────────────────────────────────────────────

    async def _election_loop(self) -> None:
        while self._running:
            async with self._lock:
                role     = self._role
                elapsed  = time.monotonic() - self._last_heartbeat
                deadline = self._election_deadline
            if role == NodeRole.FOLLOWER and elapsed > deadline:
                await self._start_election()
            await asyncio.sleep(0.25)

    async def _start_election(self) -> None:
        async with self._lock:
            self._term     += 1
            self._role      = NodeRole.CANDIDATE
            self._voted_for = self.node_id
            term            = self._term
            peers           = list(self._peers)

        votes = 1
        log.info(f"Election started: term={term} peers={len(peers)}")

        payload = {
            "type":         "vote_request",
            "candidate_id": self.node_id,
            "term":         term,
            "address":      self.address,
        }
        results = await asyncio.gather(
            *[self._post_peer(p, "/cluster/vote", payload) for p in peers],
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, dict) and r.get("granted") and r.get("term") == term:
                votes += 1

        cluster_size = len(peers) + 1
        majority     = (cluster_size // 2) + 1

        if votes >= majority:
            await self._become_leader()
        else:
            log.info(f"Election failed: term={term} votes={votes}/{cluster_size} (need {majority})")
            async with self._lock:
                if self._role == NodeRole.CANDIDATE:
                    self._role            = NodeRole.FOLLOWER
                    self._election_deadline = _new_election_deadline()

    async def _become_leader(self) -> None:
        async with self._lock:
            self._role      = NodeRole.LEADER
            self._leader_id = self.node_id
            term            = self._term
            peers           = list(self._peers)

        log.info(f"Became LEADER for term {term}")
        await self._renew_leader_key()
        payload = {"type": "new_leader", "leader_id": self.node_id,
                   "term": term, "address": self.address}
        await asyncio.gather(
            *[self._post_peer(p, "/cluster/heartbeat", payload) for p in peers],
            return_exceptions=True,
        )

    async def _step_down(self) -> None:
        async with self._lock:
            self._role            = NodeRole.FOLLOWER
            self._last_heartbeat  = time.monotonic()
            self._election_deadline = _new_election_deadline()
        log.info("Stepped down to FOLLOWER")

    # ── RPC handlers ──────────────────────────────────────────────────────────

    async def handle_heartbeat(self, data: dict) -> dict:
        incoming_term = int(data.get("term", 0))
        leader_id     = data.get("leader_id", "")
        async with self._lock:
            if incoming_term >= self._term:
                self._term           = incoming_term
                self._leader_id      = leader_id
                self._last_heartbeat = time.monotonic()
                if self._role != NodeRole.FOLLOWER:
                    self._role            = NodeRole.FOLLOWER
                    self._election_deadline = _new_election_deadline()
                    log.info(f"Reverted to FOLLOWER on heartbeat from {leader_id[:8]}")
            term = self._term
        return {"ok": True, "node_id": self.node_id, "term": term}

    async def handle_vote_request(self, data: dict) -> dict:
        candidate_id  = data.get("candidate_id", "")
        incoming_term = int(data.get("term", 0))
        granted       = False
        async with self._lock:
            if incoming_term > self._term:
                self._term      = incoming_term
                self._voted_for = None
                if self._role != NodeRole.FOLLOWER:
                    self._role            = NodeRole.FOLLOWER
                    self._election_deadline = _new_election_deadline()
            if (incoming_term == self._term
                    and (self._voted_for is None or self._voted_for == candidate_id)):
                self._voted_for      = candidate_id
                granted              = True
                self._last_heartbeat = time.monotonic()
            term = self._term
        log.debug(f"Vote {candidate_id[:8]} term={incoming_term}: granted={granted}")
        return {"granted": granted, "term": term, "node_id": self.node_id}

    # ── Peer discovery ────────────────────────────────────────────────────────

    async def _peer_discovery_loop(self) -> None:
        """Register self and discover peers using SCAN (not KEYS)."""
        while self._running:
            async with self._lock:
                role = self._role
                term = self._term

            node_key = f"{REDIS_NODE_PREFIX}{self.node_id}"
            await self._redis.setex(node_key, REDIS_NODE_TTL, json.dumps({
                "node_id": self.node_id,
                "address": self.address,
                "role":    role.value,
                "term":    term,
                "ts":      time.time(),
            }))

            live_peers: List[str] = []
            cursor = 0
            while True:
                cursor, keys = await self._redis.scan(
                    cursor=cursor, match=f"{REDIS_NODE_PREFIX}*", count=100
                )
                for k in keys:
                    raw = await self._redis.get(k)
                    if not raw:
                        continue
                    try:
                        n = json.loads(raw)
                        if n.get("node_id") != self.node_id:
                            live_peers.append(n["address"])
                    except (json.JSONDecodeError, KeyError):
                        pass
                if cursor == 0:
                    break

            async with self._lock:
                self._peers = live_peers

            await asyncio.sleep(5)

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _async_get_leader_addr(self) -> Optional[str]:
        """Read the current leader address using the shared async Redis connection."""
        try:
            raw = await self._redis.get(REDIS_LEADER_KEY)
            if raw:
                return json.loads(raw).get("address")
        except Exception as exc:
            log.debug(f"get_leader_addr: {exc}")
        return None

    async def _post_peer(self, peer_addr: str, path: str, payload: dict) -> Optional[dict]:
        try:
            async with self._session.post(peer_addr + path, json=payload) as resp:
                return await resp.json()
        except Exception as exc:
            log.debug(f"Peer {peer_addr} unreachable: {exc}")
            return None

    @staticmethod
    def _stable_node_id() -> str:
        raw = socket.gethostname() + str(uuid.getnode())
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def _local_ip() -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"
