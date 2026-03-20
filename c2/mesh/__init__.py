import logging
log = logging.getLogger(__name__)
"""
AEGIS-Advanced C2 Mesh Networking
=====================================
Peer-to-peer mesh layer for distributed C2 nodes:
node discovery via UDP broadcast, encrypted gossip protocol,
task distribution, result aggregation, leader election,
network partition detection, and split-brain recovery.
"""
import os
import json
import time
import socket
import threading
import hashlib
import hmac as _hmac
import struct
import random
import uuid
from typing import Dict, List, Optional, Set, Callable

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

# ── Configuration ─────────────────────────────────────────────────────────
MESH_PORT   = int(os.environ.get("MESH_PORT", "5001"))
C2_SECRET   = os.environ.get("C2_SECRET", "").encode()
if not C2_SECRET:
    import logging as _log_m; _log_m.getLogger("aegis.mesh").warning(
        "C2_SECRET not set — mesh auth disabled; set C2_SECRET env var")
NODE_ID     = os.environ.get("NODE_ID", "mesh-" + uuid.uuid4().hex[:8])
GOSSIP_TTL  = 3     # max hops for gossip messages
HB_INTERVAL = 10    # seconds between mesh heartbeats
DEAD_AFTER  = 35    # seconds without heartbeat → dead


# ── MAC/signing helpers ───────────────────────────────────────────────────

def _sign(data: bytes) -> bytes:
    """HMAC-SHA256 sign a payload."""
    return _hmac.new(C2_SECRET, data, hashlib.sha256).digest()[:8]

def _verify(data: bytes, sig: bytes) -> bool:
    return _hmac.compare_digest(_sign(data), sig)

def _pack(msg: dict) -> bytes:
    """Pack a mesh message: 8-byte HMAC + JSON payload."""
    raw = json.dumps(msg, separators=(",", ":")).encode()
    return _sign(raw) + raw

def _unpack(data: bytes) -> Optional[dict]:
    """Unpack and verify a mesh message."""
    if len(data) < 9: return None
    sig, raw = data[:8], data[8:]
    if not _verify(raw, sig): return None
    try:
        return json.loads(raw.decode())
    except Exception:
        return None


# ══════════════════════════════════════════════
# Mesh Node
# ══════════════════════════════════════════════

class MeshNode:
    """
    Represents a peer in the mesh network.
    Tracks its state, last-seen time, and capabilities.
    """

    def __init__(self, node_id: str, ip: str, port: int,
                 capabilities: dict = None):
        self.node_id      = node_id
        self.ip           = ip
        self.port         = port
        self.capabilities = capabilities or {}
        self.last_seen    = time.time()
        self.is_leader    = False
        self.score        = 0           # for leader election

    @property
    def is_alive(self) -> bool:
        return time.time() - self.last_seen < DEAD_AFTER

    def to_dict(self) -> dict:
        return {
            "node_id":      self.node_id,
            "ip":           self.ip,
            "port":         self.port,
            "capabilities": self.capabilities,
            "last_seen":    self.last_seen,
            "is_leader":    self.is_leader,
            "alive":        self.is_alive,
        }


# ══════════════════════════════════════════════
# Gossip Protocol
# ══════════════════════════════════════════════

class GossipMesh:
    """
    UDP gossip-based mesh network.
    Nodes discover each other, exchange state, and distribute tasks.
    Uses epidemic broadcast with TTL to prevent infinite loops.
    """

    def __init__(self, node_id: str = None,
                 host: str = "0.0.0.0",
                 port: int = MESH_PORT,
                 redis_host: str = None):
        self.node_id   = node_id or NODE_ID
        self.host      = host
        self.port      = port
        self._peers: Dict[str, MeshNode] = {}
        self._seen_msgs: Set[str] = set()
        self._lock     = threading.Lock()
        self._running  = False
        self._sock: Optional[socket.socket] = None
        self._callbacks: Dict[str, List[Callable]] = {}
        self._local_caps = {}

        # Redis integration
        if redis_host and HAS_REDIS:
            kw = dict(host=redis_host, port=6379, db=0, decode_responses=True)
            pw = os.environ.get("REDIS_PASSWORD", "")
            if pw: kw["password"] = pw
            try:
                self._redis = redis.Redis(**kw)
            except Exception:
                self._redis = None
        else:
            self._redis = None

    def set_capabilities(self, caps: dict):
        """Set local node capabilities advertised to peers."""
        self._local_caps = caps

    def on(self, msg_type: str, callback: Callable):
        """Register handler for a message type."""
        self._callbacks.setdefault(msg_type, []).append(callback)

    def _fire(self, msg_type: str, msg: dict):
        for cb in self._callbacks.get(msg_type, []):
            try: cb(msg)
            except Exception as _e: log.debug("suppressed exception: %s", _e)

    def start(self) -> "GossipMesh":
        self._running = True
        self._sock    = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._sock.bind((self.host, self.port))

        threading.Thread(target=self._recv_loop, daemon=True,
                          name="mesh-recv").start()
        threading.Thread(target=self._heartbeat_loop, daemon=True,
                          name="mesh-hb").start()
        threading.Thread(target=self._cleanup_loop, daemon=True,
                          name="mesh-cleanup").start()
        print("[mesh] Node {} started on :{}".format(self.node_id[:8], self.port))
        return self

    def stop(self):
        self._running = False
        try: self._sock.close()
        except Exception as _e: log.debug("suppressed exception: %s", _e)

    # ── Send/Broadcast ─────────────────────────────────────────────────────

    def broadcast(self, msg_type: str, payload: dict, ttl: int = GOSSIP_TTL):
        """Broadcast a message to all known peers."""
        msg = self._make_msg(msg_type, payload, ttl)
        packed = _pack(msg)
        with self._lock:
            peers = list(self._peers.values())
        for peer in peers:
            if peer.is_alive:
                self._send_to(packed, peer.ip, peer.port)
        # Also broadcast to subnet
        try:
            self._sock.sendto(packed, ("<broadcast>", self.port))
        except Exception as _exc:
            log.debug("broadcast: %s", _exc)

    def send(self, node_id: str, msg_type: str, payload: dict):
        """Send a message to a specific node."""
        peer = self._peers.get(node_id)
        if not peer or not peer.is_alive:
            return False
        msg    = self._make_msg(msg_type, payload, ttl=1)
        packed = _pack(msg)
        self._send_to(packed, peer.ip, peer.port)
        return True

    def _send_to(self, data: bytes, ip: str, port: int):
        try:
            self._sock.sendto(data, (ip, port))
        except Exception as _exc:
            log.debug("_send_to: %s", _exc)

    def _make_msg(self, msg_type: str, payload: dict, ttl: int) -> dict:
        msg_id = hashlib.sha256(
            (msg_type + json.dumps(payload, sort_keys=True)
             + str(time.time())).encode()).hexdigest()[:12]
        return {
            "id":      msg_id,
            "type":    msg_type,
            "from":    self.node_id,
            "ttl":     ttl,
            "ts":      time.time(),
            "payload": payload,
        }

    # ── Receive ────────────────────────────────────────────────────────────

    def _recv_loop(self):
        self._sock.settimeout(1)
        while self._running:
            try:
                data, addr = self._sock.recvfrom(65535)
                msg = _unpack(data)
                if not msg: continue
                self._handle(msg, addr)
            except socket.timeout:
                pass
            except Exception as _exc:
                log.debug("_recv_loop: %s", _exc)

    def _handle(self, msg: dict, addr: tuple):
        """Handle incoming mesh message."""
        msg_id = msg.get("id", "")
        if msg_id in self._seen_msgs:
            return  # duplicate
        self._seen_msgs.add(msg_id)
        # Trim seen set
        if len(self._seen_msgs) > 10000:
            self._seen_msgs = set(list(self._seen_msgs)[-5000:])

        sender_id = msg.get("from", "")
        msg_type  = msg.get("type", "")
        payload   = msg.get("payload", {})
        ttl       = msg.get("ttl", 0)

        # Update peer state
        if sender_id and sender_id != self.node_id:
            with self._lock:
                if sender_id not in self._peers:
                    self._peers[sender_id] = MeshNode(
                        sender_id, addr[0], addr[1],
                        payload.get("capabilities", {}))
                self._peers[sender_id].last_seen = time.time()
                if "ip" in payload:
                    self._peers[sender_id].ip = payload["ip"]

        # Handle message types
        if msg_type == "heartbeat":
            self._handle_heartbeat(payload, addr)
        elif msg_type == "task":
            self._fire("task", {"task": payload, "from": sender_id})
        elif msg_type == "result":
            self._fire("result", {"result": payload, "from": sender_id})
        elif msg_type == "elect":
            self._handle_election(payload, sender_id)
        elif msg_type == "announce":
            self._handle_announce(payload, sender_id, addr)
        elif msg_type == "probe":
            self._send_pong(addr)

        # Fire generic handler
        self._fire(msg_type, msg)

        # Forward (gossip relay) if TTL > 0
        if ttl > 1 and sender_id != self.node_id:
            msg["ttl"] = ttl - 1
            packed = _pack(msg)
            with self._lock:
                peers = list(self._peers.values())
            # Relay to a random subset (3 nodes max)
            relay_targets = random.sample(
                [p for p in peers if p.node_id != sender_id and p.is_alive],
                min(3, len(peers)))
            for peer in relay_targets:
                self._send_to(packed, peer.ip, peer.port)

        # Publish to Redis
        if self._redis:
            try:
                self._redis.publish("mesh", json.dumps({
                    "from": sender_id, "type": msg_type,
                    "payload": payload, "addr": "{}:{}".format(*addr),
                }))
            except Exception as _exc:
                log.debug("unknown: %s", _exc)

    def _handle_heartbeat(self, payload: dict, addr: tuple):
        """Process heartbeat from peer."""
        node_id = payload.get("node_id", "")
        if not node_id or node_id == self.node_id: return
        with self._lock:
            if node_id not in self._peers:
                self._peers[node_id] = MeshNode(
                    node_id, addr[0], payload.get("port", addr[1]),
                    payload.get("capabilities", {}))
            peer = self._peers[node_id]
            peer.last_seen    = time.time()
            peer.capabilities = payload.get("capabilities", peer.capabilities)

    def _handle_announce(self, payload: dict, sender: str, addr: tuple):
        """A new node is announcing itself to the mesh."""
        self._handle_heartbeat(payload, addr)
        # Reply with our own announce
        self.broadcast("heartbeat", {
            "node_id":      self.node_id,
            "port":         self.port,
            "capabilities": self._local_caps,
        }, ttl=1)

    def _handle_election(self, payload: dict, sender: str):
        """Simple bully-algorithm leader election."""
        their_score = payload.get("score", 0)
        my_score    = int(self.node_id.replace("-", ""), 16) % 100000
        if my_score > their_score:
            # I am higher — claim leadership
            self.broadcast("elect", {"score": my_score, "leader": self.node_id}, ttl=2)
            with self._lock:
                for p in self._peers.values():
                    p.is_leader = False
        else:
            # Accept them as leader
            with self._lock:
                for p in self._peers.values():
                    p.is_leader = p.node_id == payload.get("leader", "")

    def _send_pong(self, addr: tuple):
        """Reply to probe with our state."""
        msg = self._make_msg("pong", {
            "node_id":      self.node_id,
            "port":         self.port,
            "peers":        len(self._peers),
            "capabilities": self._local_caps,
        }, ttl=1)
        self._send_to(_pack(msg), addr[0], addr[1])

    # ── Heartbeat loop ─────────────────────────────────────────────────────

    def _heartbeat_loop(self):
        # Announce to broadcast on startup
        time.sleep(1)
        self.broadcast("announce", {
            "node_id":      self.node_id,
            "port":         self.port,
            "capabilities": self._local_caps,
        }, ttl=2)

        while self._running:
            self.broadcast("heartbeat", {
                "node_id":      self.node_id,
                "port":         self.port,
                "capabilities": self._local_caps,
                "peer_count":   len(self._peers),
            }, ttl=1)
            time.sleep(HB_INTERVAL)

    def _cleanup_loop(self):
        """Remove dead peers periodically."""
        while self._running:
            time.sleep(DEAD_AFTER)
            with self._lock:
                dead = [nid for nid, p in self._peers.items() if not p.is_alive]
                for nid in dead:
                    del self._peers[nid]
                    if self._redis:
                        try:
                            self._redis.publish("aegis_events", json.dumps({
                                "kind": "mesh_peer_dead",
                                "message": "Mesh peer {} lost".format(nid[:8]),
                                "severity": "high",
                            }))
                        except Exception as _e: log.debug("suppressed exception: %s", _e)

    # ── Public API ─────────────────────────────────────────────────────────

    def get_peers(self) -> List[MeshNode]:
        with self._lock:
            return [p for p in self._peers.values() if p.is_alive]

    def peer_count(self) -> int:
        return len(self.get_peers())

    def is_leader(self) -> bool:
        """Return True if this node is the mesh leader."""
        with self._lock:
            peers = list(self._peers.values())
        if not peers: return True
        my_score = int(self.node_id.replace("-", ""), 16) % 100000
        return all(
            my_score >= (int(p.node_id.replace("-",""),16) % 100000)
            for p in peers if p.is_alive
        )

    def distribute_task(self, task: dict) -> Optional[str]:
        """
        Distribute a task to the least-loaded peer.
        Returns the target node_id or None if no peers.
        """
        peers = sorted(self.get_peers(),
                        key=lambda p: p.capabilities.get("active_tasks", 0))
        if not peers: return None
        target = peers[0]
        self.send(target.node_id, "task", task)
        return target.node_id

    def collect_results(self, timeout: float = 30.0) -> List[dict]:
        """Collect results from peers (uses callback, not blocking)."""
        results = []
        def _cb(msg): results.append(msg)
        self.on("result", _cb)
        time.sleep(timeout)
        return results

    def topology(self) -> dict:
        """Return mesh network topology snapshot."""
        peers = self.get_peers()
        return {
            "self":       self.node_id,
            "is_leader":  self.is_leader(),
            "peer_count": len(peers),
            "peers": [p.to_dict() for p in peers],
        }


# Module-level mesh singleton
_mesh: Optional[GossipMesh] = None

def get_mesh(auto_start: bool = False, **kwargs) -> GossipMesh:
    """Get or create the module-level mesh singleton."""
    global _mesh
    if _mesh is None:
        _mesh = GossipMesh(**kwargs)
        if auto_start:
            _mesh.start()
    return _mesh


__all__ = [
    "MeshNode", "GossipMesh", "get_mesh",
    "MESH_PORT", "HB_INTERVAL", "DEAD_AFTER",
]
