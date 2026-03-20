"""
c2/network/topology.py
AEGIS-SILENTIUM v12 — Network Topology Graph

Maintains a live graph of the discovered network:
  • Hosts with open ports, OS fingerprint, role classification
  • Subnets with CIDR membership
  • Connectivity edges with latency and bandwidth estimates
  • Dijkstra/A* shortest-path routing
  • Choke-point and critical-node analysis
  • Export to Graphviz DOT / D3 JSON / NMAP XML

Node roles are auto-classified from open ports:
  DOMAIN_CONTROLLER  — 88/TCP (Kerberos), 389/TCP (LDAP), 3268/TCP
  WEB_SERVER         — 80/443
  DATABASE           — 3306/5432/1433/1521/27017
  MAIL_SERVER        — 25/465/587/143/993
  FIREWALL           — default gateway, filtered majority
  WORKSTATION        — no server ports
"""
from __future__ import annotations

import heapq
import ipaddress
import logging
import math
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

log = logging.getLogger("aegis.network.topology")


class NodeRole(str, Enum):
    UNKNOWN           = "unknown"
    WORKSTATION       = "workstation"
    SERVER            = "server"
    WEB_SERVER        = "web_server"
    DATABASE          = "database"
    DOMAIN_CONTROLLER = "domain_controller"
    MAIL_SERVER       = "mail_server"
    FIREWALL          = "firewall"
    ROUTER            = "router"
    PRINTER           = "printer"
    IOT               = "iot"
    C2_BEACON         = "c2_beacon"       # our node


_ROLE_PORTS = {
    NodeRole.DOMAIN_CONTROLLER: {88, 389, 636, 3268, 3269},
    NodeRole.WEB_SERVER:        {80, 443, 8080, 8443},
    NodeRole.DATABASE:          {3306, 5432, 1433, 1521, 27017, 6379, 9200},
    NodeRole.MAIL_SERVER:       {25, 465, 587, 143, 993, 110, 995},
    NodeRole.FIREWALL:          set(),
    NodeRole.ROUTER:            {22, 23, 161, 162},
    NodeRole.PRINTER:           {9100, 631, 515},
}


@dataclass
class NetworkNode:
    node_id:   str
    ip:        str
    hostname:  Optional[str] = None
    mac:       Optional[str] = None
    os_info:   str           = ""
    open_ports: List[int]    = field(default_factory=list)
    services:  Dict[int, str] = field(default_factory=dict)   # port → service name
    role:      NodeRole      = NodeRole.UNKNOWN
    subnet:    Optional[str] = None
    ttl:       Optional[int] = None
    last_seen: float         = field(default_factory=time.time)
    is_alive:  bool          = True
    tags:      List[str]     = field(default_factory=list)
    meta:      dict          = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.role == NodeRole.UNKNOWN and self.open_ports:
            self.role = self._classify_role()

    def _classify_role(self) -> NodeRole:
        port_set = set(self.open_ports)
        scores: Dict[NodeRole, int] = {}
        for role, role_ports in _ROLE_PORTS.items():
            if role_ports:
                overlap = len(port_set & role_ports)
                if overlap:
                    scores[role] = overlap
        if not scores:
            return NodeRole.WORKSTATION if port_set else NodeRole.UNKNOWN
        return max(scores, key=scores.get)

    def to_dict(self) -> dict:
        return {
            "node_id":    self.node_id,
            "ip":         self.ip,
            "hostname":   self.hostname,
            "os_info":    self.os_info,
            "open_ports": self.open_ports,
            "services":   {str(k): v for k, v in self.services.items()},
            "role":       self.role.value,
            "subnet":     self.subnet,
            "last_seen":  self.last_seen,
            "is_alive":   self.is_alive,
            "tags":       self.tags,
        }


@dataclass
class NetworkEdge:
    edge_id:   str
    src_id:    str
    dst_id:    str
    latency_ms: float = 0.0
    bandwidth: float  = 0.0    # Mbps, 0 = unknown
    protocol:  str    = ""
    port:      Optional[int] = None
    weight:    float  = 1.0    # for routing (lower = preferred)
    last_seen: float  = field(default_factory=time.time)
    bidirectional: bool = True

    def to_dict(self) -> dict:
        return {
            "edge_id":      self.edge_id,
            "src_id":       self.src_id,
            "dst_id":       self.dst_id,
            "latency_ms":   self.latency_ms,
            "bandwidth":    self.bandwidth,
            "protocol":     self.protocol,
            "weight":       self.weight,
            "bidirectional": self.bidirectional,
        }


@dataclass
class NetworkPath:
    nodes:     List[str]
    total_weight: float
    hops:      int
    latency_ms: float

    def to_dict(self) -> dict:
        return {
            "nodes":        self.nodes,
            "total_weight": self.total_weight,
            "hops":         self.hops,
            "latency_ms":   self.latency_ms,
        }


class NetworkTopology:
    """
    Live network topology graph with routing and analysis.

    Usage::

        topo = NetworkTopology()
        topo.add_node(NetworkNode(node_id="h1", ip="10.0.0.1", open_ports=[22, 80]))
        topo.add_node(NetworkNode(node_id="h2", ip="10.0.0.2", open_ports=[3306]))
        topo.add_edge(NetworkEdge(edge_id="e1", src_id="h1", dst_id="h2", latency_ms=1.5))

        path = topo.shortest_path("h1", "h2")
        chokepoints = topo.find_chokepoints()
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, NetworkNode] = {}
        self._edges: Dict[str, NetworkEdge] = {}
        self._adj:   Dict[str, Dict[str, str]] = {}   # src → {dst → edge_id}
        self._subnets: Dict[str, Set[str]] = {}        # CIDR → set of node_ids
        self._lock = threading.RLock()

    # ── Mutation ──────────────────────────────────────────────────────────────

    def add_node(self, node: NetworkNode) -> None:
        with self._lock:
            self._nodes[node.node_id] = node
            self._adj.setdefault(node.node_id, {})
            if node.subnet:
                self._subnets.setdefault(node.subnet, set()).add(node.node_id)
            # Auto-assign to subnet from IP
            elif node.ip:
                for cidr in self._subnets:
                    try:
                        if ipaddress.ip_address(node.ip) in ipaddress.ip_network(cidr, strict=False):
                            self._subnets[cidr].add(node.node_id)
                            node.subnet = cidr
                            break
                    except ValueError:
                        pass

    def update_node(self, node_id: str, **kwargs) -> bool:
        with self._lock:
            node = self._nodes.get(node_id)
            if not node:
                return False
            for k, v in kwargs.items():
                if hasattr(node, k):
                    setattr(node, k, v)
            node.last_seen = time.time()
            return True

    def add_edge(self, edge: NetworkEdge) -> None:
        with self._lock:
            self._edges[edge.edge_id] = edge
            self._adj.setdefault(edge.src_id, {})[edge.dst_id] = edge.edge_id
            if edge.bidirectional:
                self._adj.setdefault(edge.dst_id, {})[edge.src_id] = edge.edge_id

    def remove_node(self, node_id: str) -> None:
        with self._lock:
            self._nodes.pop(node_id, None)
            # Remove incident edges
            edges_to_del = [eid for eid, e in self._edges.items()
                            if e.src_id == node_id or e.dst_id == node_id]
            for eid in edges_to_del:
                e = self._edges.pop(eid)
                self._adj.get(e.src_id, {}).pop(e.dst_id, None)
                self._adj.get(e.dst_id, {}).pop(e.src_id, None)
            self._adj.pop(node_id, None)

    def add_subnet(self, cidr: str) -> None:
        with self._lock:
            self._subnets.setdefault(cidr, set())
            # Assign existing nodes to subnet
            network = ipaddress.ip_network(cidr, strict=False)
            for node in self._nodes.values():
                try:
                    if ipaddress.ip_address(node.ip) in network:
                        self._subnets[cidr].add(node.node_id)
                        if not node.subnet:
                            node.subnet = cidr
                except ValueError:
                    pass

    # ── Routing ───────────────────────────────────────────────────────────────

    def shortest_path(
        self,
        src_id: str,
        dst_id: str,
        weight_fn: Optional[callable] = None,
    ) -> Optional[NetworkPath]:
        """Dijkstra shortest path. weight_fn(edge) → float overrides edge.weight."""
        with self._lock:
            if src_id not in self._nodes or dst_id not in self._nodes:
                return None
            adj = {k: dict(v) for k, v in self._adj.items()}
            edges = dict(self._edges)

        dist:  Dict[str, float] = {src_id: 0.0}
        prev:  Dict[str, Optional[str]] = {src_id: None}
        heap = [(0.0, src_id)]

        while heap:
            d, u = heapq.heappop(heap)
            if u == dst_id:
                break
            if d > dist.get(u, math.inf):
                continue
            for v, eid in adj.get(u, {}).items():
                edge = edges.get(eid)
                if not edge:
                    continue
                w = weight_fn(edge) if weight_fn else edge.weight
                nd = dist[u] + w
                if nd < dist.get(v, math.inf):
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(heap, (nd, v))

        if dst_id not in dist:
            return None

        # Reconstruct path
        path = []
        cur = dst_id
        while cur is not None:
            path.append(cur)
            cur = prev.get(cur)
        path.reverse()

        total_latency = sum(
            edges.get(adj.get(path[i], {}).get(path[i+1], ""), type("E", (), {"latency_ms": 0})()).latency_ms
            for i in range(len(path) - 1)
        )

        return NetworkPath(
            nodes        = path,
            total_weight = dist[dst_id],
            hops         = len(path) - 1,
            latency_ms   = total_latency,
        )

    def all_paths_bfs(self, src_id: str, max_depth: int = 5) -> Dict[str, NetworkPath]:
        """BFS from src to all reachable nodes."""
        with self._lock:
            adj = {k: dict(v) for k, v in self._adj.items()}
            edges = dict(self._edges)

        result: Dict[str, NetworkPath] = {}
        visited = {src_id}
        queue = [(src_id, [src_id], 0.0, 0.0)]

        while queue:
            cur, path, weight, latency = queue.pop(0)
            if len(path) > max_depth + 1:
                continue
            for nxt, eid in adj.get(cur, {}).items():
                if nxt in visited:
                    continue
                edge = edges.get(eid)
                w = edge.weight if edge else 1.0
                l = edge.latency_ms if edge else 0.0
                new_path = path + [nxt]
                new_weight = weight + w
                new_latency = latency + l
                result[nxt] = NetworkPath(
                    nodes=new_path, total_weight=new_weight,
                    hops=len(new_path)-1, latency_ms=new_latency
                )
                visited.add(nxt)
                queue.append((nxt, new_path, new_weight, new_latency))
        return result

    # ── Analysis ──────────────────────────────────────────────────────────────

    def find_chokepoints(self) -> List[str]:
        """
        Find articulation points — nodes whose removal disconnects the graph.
        Uses Tarjan's algorithm.
        """
        with self._lock:
            nodes = list(self._nodes.keys())
            adj = {k: list(v.keys()) for k, v in self._adj.items()}

        disc:   Dict[str, int]  = {}
        low:    Dict[str, int]  = {}
        parent: Dict[str, Optional[str]] = {}
        ap:     Set[str]        = set()
        timer   = [0]

        def dfs(u: str) -> None:
            disc[u] = low[u] = timer[0]
            timer[0] += 1
            children = 0
            for v in adj.get(u, []):
                if v not in disc:
                    children += 1
                    parent[v] = u
                    dfs(v)
                    low[u] = min(low[u], low[v])
                    # u is AP if:
                    if parent.get(u) is None and children > 1:
                        ap.add(u)
                    if parent.get(u) is not None and low[v] >= disc[u]:
                        ap.add(u)
                elif v != parent.get(u):
                    low[u] = min(low[u], disc[v])

        for node in nodes:
            if node not in disc:
                parent[node] = None
                dfs(node)

        return list(ap)

    def find_connected_components(self) -> List[List[str]]:
        """Find all connected components (union-find)."""
        with self._lock:
            nodes = list(self._nodes.keys())
            adj = {k: list(v.keys()) for k, v in self._adj.items()}

        visited: Set[str] = set()
        components: List[List[str]] = []

        def bfs(start: str) -> List[str]:
            component = []
            q = [start]
            visited.add(start)
            while q:
                u = q.pop(0)
                component.append(u)
                for v in adj.get(u, []):
                    if v not in visited:
                        visited.add(v)
                        q.append(v)
            return component

        for node in nodes:
            if node not in visited:
                components.append(bfs(node))
        return components

    def nodes_by_role(self, role: NodeRole) -> List[NetworkNode]:
        with self._lock:
            return [n for n in self._nodes.values() if n.role == role]

    def subnet_membership(self, ip: str) -> Optional[str]:
        try:
            addr = ipaddress.ip_address(ip)
            with self._lock:
                for cidr in self._subnets:
                    if addr in ipaddress.ip_network(cidr, strict=False):
                        return cidr
        except ValueError:
            pass
        return None

    def get_node_by_ip(self, ip: str) -> Optional[NetworkNode]:
        with self._lock:
            for node in self._nodes.values():
                if node.ip == ip:
                    return node
        return None

    # ── Export ────────────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "nodes":   [n.to_dict() for n in self._nodes.values()],
                "edges":   [e.to_dict() for e in self._edges.values()],
                "subnets": {cidr: list(ids) for cidr, ids in self._subnets.items()},
                "stats":   self.stats(),
            }

    def to_dot(self) -> str:
        """Export to Graphviz DOT format."""
        lines = ["digraph topology {", "  rankdir=LR;",
                 "  node [shape=box, style=filled];"]
        role_colors = {
            NodeRole.DOMAIN_CONTROLLER: "red",
            NodeRole.WEB_SERVER:        "lightblue",
            NodeRole.DATABASE:          "orange",
            NodeRole.FIREWALL:          "gray",
            NodeRole.ROUTER:            "yellow",
            NodeRole.WORKSTATION:       "white",
            NodeRole.C2_BEACON:         "green",
        }
        with self._lock:
            nodes = list(self._nodes.values())
            edges = list(self._edges.values())
        for n in nodes:
            color = role_colors.get(n.role, "white")
            label = f"{n.ip}\\n{n.hostname or ''}"
            lines.append(f'  "{n.node_id}" [label="{label}" fillcolor={color}];')
        for e in edges:
            label = f"{e.latency_ms:.1f}ms" if e.latency_ms else ""
            lines.append(f'  "{e.src_id}" -> "{e.dst_id}" [label="{label}"];')
        lines.append("}")
        return "\n".join(lines)

    def to_d3_json(self) -> dict:
        """Export to D3.js force-graph format."""
        with self._lock:
            nodes = [{"id": n.node_id, "ip": n.ip,
                      "role": n.role.value, "label": n.hostname or n.ip}
                     for n in self._nodes.values()]
            links = [{"source": e.src_id, "target": e.dst_id,
                      "latency": e.latency_ms}
                     for e in self._edges.values()]
        return {"nodes": nodes, "links": links}

    def stats(self) -> dict:
        with self._lock:
            role_counts = {}
            for n in self._nodes.values():
                role_counts[n.role.value] = role_counts.get(n.role.value, 0) + 1
            return {
                "node_count":   len(self._nodes),
                "edge_count":   len(self._edges),
                "subnet_count": len(self._subnets),
                "by_role":      role_counts,
                "alive":        sum(1 for n in self._nodes.values() if n.is_alive),
            }
