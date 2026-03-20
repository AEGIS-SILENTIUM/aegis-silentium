"""
c2/intelligence/threat_graph.py
AEGIS-SILENTIUM v12 — Threat Intelligence Graph (Advanced)

Directed attributed graph for threat intelligence:
  • Nodes: ThreatActor, Campaign, Tool, Infrastructure, Victim, Technique, IOC
  • Edges: typed with confidence, temporal metadata, evidence
  • PageRank for actor scoring (weighted by edge confidence)
  • BFS shortest path with max-depth guard
  • Betweenness centrality (approx.) for chokepoint analysis
  • Community detection via label propagation
  • Temporal edge analysis (activity windows)
  • MITRE ATT&CK technique linkage
  • Kill-chain path enumeration
  • Diamond model attribution helpers
  • Full DOT/JSON export for visualisation
"""
from __future__ import annotations

import logging
import math
import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

log = logging.getLogger("aegis.intelligence.graph")


# ── Enumerations ──────────────────────────────────────────────────────────────

class EdgeType(str, Enum):
    USES             = "uses"
    ATTRIBUTED_TO    = "attributed_to"
    SHARES_INFRA     = "shares_infra_with"
    TARGETS          = "targets"
    RELATED_TO       = "related_to"
    EVOLVED_FROM     = "evolved_from"
    COMMUNICATES     = "communicates_with"
    DEPLOYS          = "deploys"
    COMPROMISES      = "compromises"
    IMPERSONATES     = "impersonates"


class NodeKind(str, Enum):
    ACTOR       = "threat_actor"
    CAMPAIGN    = "campaign"
    TOOL        = "tool"
    INFRA       = "infrastructure"
    VICTIM      = "victim"
    TECHNIQUE   = "technique"
    IOC         = "ioc"


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ThreatActor:
    actor_id:       str
    name:           str
    aliases:        List[str]        = field(default_factory=list)
    origin:         str              = ""
    motivation:     str              = ""
    sophistication: str              = "intermediate"
    first_seen:     Optional[float]  = None
    last_seen:      Optional[float]  = None
    tags:           List[str]        = field(default_factory=list)
    description:    str              = ""

    def to_dict(self) -> dict:
        return {
            "actor_id": self.actor_id, "name": self.name,
            "aliases": self.aliases, "origin": self.origin,
            "motivation": self.motivation, "sophistication": self.sophistication,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "tags": self.tags, "description": self.description,
        }


@dataclass
class ThreatEdge:
    edge_id:    str
    source_id:  str
    target_id:  str
    edge_type:  EdgeType
    confidence: float = 0.70
    created_at: float = field(default_factory=time.time)
    timestamp:  Optional[float] = None   # when observed in the wild
    evidence:   str   = ""
    meta:       dict  = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "edge_id": self.edge_id, "source_id": self.source_id,
            "target_id": self.target_id, "edge_type": self.edge_type.value,
            "confidence": self.confidence, "created_at": self.created_at,
            "timestamp": self.timestamp, "evidence": self.evidence,
        }


@dataclass
class _GraphNode:
    node_id: str
    kind:    NodeKind
    data:    dict
    score:   float = 1.0       # PageRank score
    created_at: float = field(default_factory=time.time)


# ── Main Graph ────────────────────────────────────────────────────────────────

class ThreatGraph:
    """
    Directed attributed threat intelligence graph.

    Design notes:
      - Adjacency represented as out-edge sets (edge_id → ThreatEdge lookup)
        rather than adjacency lists, so edge metadata is O(1) accessible.
      - PageRank uses confidence-weighted edges for more accurate scoring.
      - Betweenness centrality uses Brandes' algorithm (O(VE) approximation
        for sparse graphs, sampled for large graphs).
      - Label propagation runs synchronous rounds until convergence.
      - All public methods are thread-safe via RLock.

    Usage::
        g = ThreatGraph()
        g.add_actor(ThreatActor(actor_id="apt29", name="APT29"))
        g.add_node("cobalt-strike", NodeKind.TOOL, {"name": "Cobalt Strike"})
        g.add_edge("apt29", "cobalt-strike", EdgeType.USES, confidence=0.95)

        path = g.shortest_path("apt29", "target-node")
        scores = g.pagerank()
        communities = g.detect_communities()
    """

    _DAMPING        = 0.85
    _PAGERANK_ITERS = 50
    _CENTRALITY_SAMPLES = 50   # for betweenness sampling on large graphs

    def __init__(self) -> None:
        self._nodes:      Dict[str, _GraphNode]   = {}
        self._edges:      Dict[str, ThreatEdge]   = {}
        self._out_edges:  Dict[str, Set[str]]     = {}   # node_id → {edge_id}
        self._in_edges:   Dict[str, Set[str]]     = {}   # node_id → {edge_id}
        self._lock        = threading.RLock()

    # ── Node & edge mutation ──────────────────────────────────────────────────

    def add_actor(self, actor: ThreatActor) -> None:
        with self._lock:
            self._nodes[actor.actor_id] = _GraphNode(
                node_id=actor.actor_id, kind=NodeKind.ACTOR, data=actor.to_dict()
            )
            self._out_edges.setdefault(actor.actor_id, set())
            self._in_edges.setdefault(actor.actor_id, set())

    def add_node(self, node_id: str, kind: NodeKind, data: dict) -> None:
        with self._lock:
            self._nodes[node_id] = _GraphNode(node_id=node_id, kind=kind, data=data)
            self._out_edges.setdefault(node_id, set())
            self._in_edges.setdefault(node_id, set())

    def add_edge(
        self,
        source_id:  str,
        target_id:  str,
        edge_type:  EdgeType,
        confidence: float           = 0.70,
        evidence:   str             = "",
        timestamp:  Optional[float] = None,
        meta:       Optional[dict]  = None,
    ) -> str:
        """Add a directed edge; auto-creates stub nodes if missing. Returns edge_id."""
        edge = ThreatEdge(
            edge_id   = str(uuid.uuid4()),
            source_id = source_id,
            target_id = target_id,
            edge_type = edge_type,
            confidence= confidence,
            evidence  = evidence,
            timestamp = timestamp or time.time(),
            meta      = meta or {},
        )
        with self._lock:
            for nid in (source_id, target_id):
                if nid not in self._nodes:
                    self._nodes[nid] = _GraphNode(
                        node_id=nid, kind=NodeKind.IOC, data={"id": nid}
                    )
                self._out_edges.setdefault(nid, set())
                self._in_edges.setdefault(nid, set())
            self._edges[edge.edge_id] = edge
            self._out_edges[source_id].add(edge.edge_id)
            self._in_edges[target_id].add(edge.edge_id)
        return edge.edge_id

    def remove_node(self, node_id: str) -> None:
        with self._lock:
            for eid in list(self._out_edges.get(node_id, set())):
                e = self._edges.pop(eid, None)
                if e:
                    self._in_edges.get(e.target_id, set()).discard(eid)
            for eid in list(self._in_edges.get(node_id, set())):
                e = self._edges.pop(eid, None)
                if e:
                    self._out_edges.get(e.source_id, set()).discard(eid)
            self._nodes.pop(node_id, None)
            self._out_edges.pop(node_id, None)
            self._in_edges.pop(node_id, None)

    # ── Query ─────────────────────────────────────────────────────────────────

    def neighbors(
        self,
        node_id:        str,
        direction:      str              = "out",
        edge_type:      Optional[EdgeType] = None,
        min_confidence: float            = 0.0,
    ) -> List[dict]:
        """Return neighbours with edge metadata."""
        with self._lock:
            eids: Set[str] = set()
            if direction in ("out", "both"):
                eids.update(self._out_edges.get(node_id, set()))
            if direction in ("in", "both"):
                eids.update(self._in_edges.get(node_id, set()))
            results = []
            for eid in eids:
                e = self._edges.get(eid)
                if not e or e.confidence < min_confidence:
                    continue
                if edge_type and e.edge_type != edge_type:
                    continue
                peer_id = e.target_id if e.source_id == node_id else e.source_id
                peer = self._nodes.get(peer_id)
                results.append({
                    "node": peer.data if peer else {"id": peer_id},
                    "kind": peer.kind.value if peer else "unknown",
                    "edge": e.to_dict(),
                })
        return results

    def shortest_path(
        self, src: str, dst: str, max_depth: int = 8
    ) -> Optional[List[str]]:
        """BFS shortest path — respects edge direction. Returns None if unreachable."""
        with self._lock:
            if src not in self._nodes or dst not in self._nodes:
                return None

        visited: Set[str] = {src}
        queue: List[List[str]] = [[src]]

        while queue:
            path = queue.pop(0)
            if len(path) > max_depth:
                return None
            node = path[-1]
            with self._lock:
                targets = [
                    self._edges[eid].target_id
                    for eid in self._out_edges.get(node, set())
                    if eid in self._edges
                ]
            for nxt in targets:
                if nxt in visited:
                    continue
                new_path = path + [nxt]
                if nxt == dst:
                    return new_path
                visited.add(nxt)
                queue.append(new_path)
        return None

    def all_attack_paths(
        self,
        src:       str,
        dst:       str,
        max_depth: int   = 6,
        min_conf:  float = 0.5,
    ) -> List[List[str]]:
        """
        Enumerate ALL paths from src to dst (DFS) up to max_depth.
        Filters edges below min_confidence. Useful for kill-chain analysis.
        Returns list of node-ID paths sorted by total confidence desc.
        """
        paths: List[Tuple[List[str], float]] = []

        def dfs(path: List[str], conf_product: float) -> None:
            node = path[-1]
            if node == dst:
                paths.append((list(path), conf_product))
                return
            if len(path) > max_depth:
                return
            with self._lock:
                edges_out = [
                    self._edges[eid]
                    for eid in self._out_edges.get(node, set())
                    if eid in self._edges
                ]
            for e in edges_out:
                if e.confidence < min_conf:
                    continue
                if e.target_id in path:  # cycle prevention
                    continue
                dfs(path + [e.target_id], conf_product * e.confidence)

        with self._lock:
            if src not in self._nodes or dst not in self._nodes:
                return []

        dfs([src], 1.0)
        paths.sort(key=lambda x: -x[1])
        return [p for p, _ in paths]

    # ── Graph algorithms ──────────────────────────────────────────────────────

    def pagerank(self, weighted: bool = True) -> Dict[str, float]:
        """
        Compute confidence-weighted PageRank.
        With weighted=True, edge weight = edge.confidence; otherwise uniform.
        Handles dangling nodes (no out-edges) via global redistribution.
        """
        with self._lock:
            node_ids = list(self._nodes.keys())
            # out_map: node_id → list of (target_id, weight)
            out_map: Dict[str, List[Tuple[str, float]]] = {}
            for nid in node_ids:
                edges_list = []
                for eid in self._out_edges.get(nid, set()):
                    e = self._edges.get(eid)
                    if e:
                        w = e.confidence if weighted else 1.0
                        edges_list.append((e.target_id, w))
                out_map[nid] = edges_list

        n = len(node_ids)
        if n == 0:
            return {}

        scores = {nid: 1.0 / n for nid in node_ids}

        for _ in range(self._PAGERANK_ITERS):
            new_scores: Dict[str, float] = {nid: (1 - self._DAMPING) / n
                                             for nid in node_ids}
            dangling_sum = 0.0

            for src in node_ids:
                edges_out = out_map[src]
                if not edges_out:
                    dangling_sum += self._DAMPING * scores[src]
                    continue
                total_w = sum(w for _, w in edges_out) or 1.0
                for tgt, w in edges_out:
                    if tgt in new_scores:
                        new_scores[tgt] += self._DAMPING * scores[src] * (w / total_w)

            # Distribute dangling mass equally
            if dangling_sum > 0:
                per_node = dangling_sum / n
                for nid in node_ids:
                    new_scores[nid] += per_node

            scores = new_scores

        # Store back into nodes
        with self._lock:
            for nid, score in scores.items():
                if nid in self._nodes:
                    self._nodes[nid].score = score

        return scores

    def betweenness_centrality(self, normalise: bool = True) -> Dict[str, float]:
        """
        Approximate betweenness centrality using Brandes' algorithm.
        On graphs with >_CENTRALITY_SAMPLES nodes, uses random-source sampling
        to keep runtime bounded.

        Higher score → node lies on more shortest paths → chokepoint.
        """
        with self._lock:
            node_ids = list(self._nodes.keys())
            adj: Dict[str, List[str]] = {
                nid: [
                    self._edges[eid].target_id
                    for eid in self._out_edges.get(nid, set())
                    if eid in self._edges
                ]
                for nid in node_ids
            }

        n = len(node_ids)
        if n < 2:
            return {nid: 0.0 for nid in node_ids}

        betweenness = {nid: 0.0 for nid in node_ids}
        sources = node_ids if n <= self._CENTRALITY_SAMPLES else \
                  random.sample(node_ids, self._CENTRALITY_SAMPLES)

        for s in sources:
            # BFS from s
            stack: List[str] = []
            pred: Dict[str, List[str]] = {v: [] for v in node_ids}
            sigma = {v: 0.0 for v in node_ids}; sigma[s] = 1.0
            dist  = {v: -1   for v in node_ids}; dist[s]  = 0
            queue = [s]
            while queue:
                v = queue.pop(0); stack.append(v)
                for w in adj.get(v, []):
                    if dist[w] < 0:
                        queue.append(w); dist[w] = dist[v] + 1
                    if dist[w] == dist[v] + 1:
                        sigma[w] += sigma[v]; pred[w].append(v)
            # Accumulation
            delta = {v: 0.0 for v in node_ids}
            while stack:
                w = stack.pop()
                for v in pred[w]:
                    if sigma[w] > 0:
                        delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
                if w != s:
                    betweenness[w] += delta[w]

        # Normalise
        if normalise and n > 2:
            scale = 2.0 / ((n - 1) * (n - 2))
            if n > self._CENTRALITY_SAMPLES:
                scale *= n / self._CENTRALITY_SAMPLES
            for nid in betweenness:
                betweenness[nid] *= scale

        return betweenness

    def detect_communities(self, max_iters: int = 30) -> Dict[str, int]:
        """
        Label propagation community detection.
        O(V+E) per iteration, converges quickly on sparse graphs.
        Returns {node_id: community_id} mapping.
        """
        with self._lock:
            node_ids = list(self._nodes.keys())
            adj: Dict[str, List[str]] = {}
            for nid in node_ids:
                neighbours = set()
                for eid in self._out_edges.get(nid, set()):
                    e = self._edges.get(eid)
                    if e:
                        neighbours.add(e.target_id)
                for eid in self._in_edges.get(nid, set()):
                    e = self._edges.get(eid)
                    if e:
                        neighbours.add(e.source_id)
                adj[nid] = list(neighbours)

        # Initialise: each node in its own community
        labels = {nid: i for i, nid in enumerate(node_ids)}

        for _ in range(max_iters):
            changed = False
            order = list(node_ids)
            random.shuffle(order)
            for nid in order:
                nbrs = adj.get(nid, [])
                if not nbrs:
                    continue
                # Majority vote among neighbours
                counts: Dict[int, int] = {}
                for nb in nbrs:
                    lb = labels.get(nb, -1)
                    counts[lb] = counts.get(lb, 0) + 1
                best = max(counts, key=counts.__getitem__)
                if labels[nid] != best:
                    labels[nid] = best
                    changed = True
            if not changed:
                break

        # Remap to contiguous community IDs
        seen: Dict[int, int] = {}
        result: Dict[str, int] = {}
        cid_counter = 0
        for nid, lb in labels.items():
            if lb not in seen:
                seen[lb] = cid_counter
                cid_counter += 1
            result[nid] = seen[lb]
        return result

    def activity_window(
        self, node_id: str
    ) -> Tuple[Optional[float], Optional[float]]:
        """
        Return (first_seen, last_seen) timestamps of all edges incident to node_id.
        Useful for determining when a threat actor / campaign was active.
        """
        timestamps = []
        with self._lock:
            for eid in (self._out_edges.get(node_id, set()) |
                        self._in_edges.get(node_id, set())):
                e = self._edges.get(eid)
                if e and e.timestamp:
                    timestamps.append(e.timestamp)
        if not timestamps:
            return (None, None)
        return (min(timestamps), max(timestamps))

    def cluster_campaigns(self, min_shared_infra: int = 2) -> List[List[str]]:
        """Cluster campaigns by shared infrastructure (union-find)."""
        with self._lock:
            campaigns = [nid for nid, n in self._nodes.items()
                         if n.kind == NodeKind.CAMPAIGN]
        parent = {c: c for c in campaigns}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        infra_to_campaigns: Dict[str, Set[str]] = {}
        for c in campaigns:
            with self._lock:
                for eid in self._out_edges.get(c, set()):
                    e = self._edges.get(eid)
                    if e and e.edge_type == EdgeType.SHARES_INFRA:
                        infra_to_campaigns.setdefault(e.target_id, set()).add(c)

        for infra, camps in infra_to_campaigns.items():
            camp_list = list(camps)
            if len(camp_list) >= min_shared_infra:
                root = find(camp_list[0])
                for c in camp_list[1:]:
                    parent[find(c)] = root

        groups: Dict[str, List[str]] = {}
        for c in campaigns:
            r = find(c)
            groups.setdefault(r, []).append(c)
        return [g for g in groups.values() if len(g) > 1]

    def actor_score(self, actor_id: str) -> float:
        return self.pagerank().get(actor_id, 0.0)

    # ── Export ────────────────────────────────────────────────────────────────

    def export(self) -> dict:
        """Full graph export as JSON-serialisable dict."""
        with self._lock:
            return {
                "nodes": [{"id": n.node_id, "kind": n.kind.value,
                            "data": n.data, "score": n.score}
                           for n in self._nodes.values()],
                "edges": [e.to_dict() for e in self._edges.values()],
                "stats": self.stats(),
            }

    def to_dot(self) -> str:
        """Export as GraphViz DOT language."""
        lines = ["digraph ThreatGraph {", '  rankdir=LR;']
        _colours = {
            NodeKind.ACTOR: "#ff4444", NodeKind.CAMPAIGN: "#ff8800",
            NodeKind.TOOL: "#4488ff", NodeKind.INFRA: "#44aa44",
            NodeKind.VICTIM: "#aa44aa", NodeKind.TECHNIQUE: "#888888",
            NodeKind.IOC: "#44cccc",
        }
        with self._lock:
            for nid, node in self._nodes.items():
                colour = _colours.get(node.kind, "#cccccc")
                label  = node.data.get("name", nid)[:32]
                lines.append(
                    f'  "{nid}" [label="{label}" shape=box '
                    f'style=filled fillcolor="{colour}"];'
                )
            for eid, edge in self._edges.items():
                label = f"{edge.edge_type.value} ({edge.confidence:.0%})"
                lines.append(
                    f'  "{edge.source_id}" -> "{edge.target_id}" '
                    f'[label="{label}" weight={edge.confidence:.2f}];'
                )
        lines.append("}")
        return "\n".join(lines)

    def stats(self) -> dict:
        with self._lock:
            kinds: Dict[str, int] = {}
            edge_types: Dict[str, int] = {}
            for n in self._nodes.values():
                kinds[n.kind.value] = kinds.get(n.kind.value, 0) + 1
            for e in self._edges.values():
                edge_types[e.edge_type.value] = edge_types.get(e.edge_type.value, 0) + 1
            return {
                "node_count":  len(self._nodes),
                "edge_count":  len(self._edges),
                "by_kind":     kinds,
                "by_edge_type": edge_types,
            }


__all__ = [
    "ThreatGraph", "ThreatActor", "ThreatEdge",
    "EdgeType", "NodeKind",
]
