"""
c2/distributed/merkle.py
AEGIS-SILENTIUM v12 — Merkle Tree State Reconciliation

Allows two nodes to efficiently compare their key-value state and
identify diverging keys without exchanging a full dump.

Algorithm
---------
  Build a complete binary Merkle tree over a sorted list of (key, value)
  pairs.  The root hash summarises the entire state.  Two nodes can walk
  the tree top-down, descending only into subtrees whose hashes differ,
  to find the exact set of diverging keys in O(d * k) messages where d
  is tree depth and k is the number of differing keys.

  Leaf hash  : SHA-256(key || ":" || value)
  Parent hash: SHA-256(left_hash || right_hash)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class MerkleNode:
    hash: str
    left:  Optional["MerkleNode"] = field(default=None, repr=False)
    right: Optional["MerkleNode"] = field(default=None, repr=False)
    key:   Optional[str] = None   # only set on leaf nodes
    value: Optional[str] = None   # only set on leaf nodes

    @property
    def is_leaf(self) -> bool:
        return self.key is not None


class MerkleTree:
    """
    Immutable Merkle tree built from a dict snapshot.

    Usage::

        tree_a = MerkleTree(state_dict_a)
        tree_b = MerkleTree(state_dict_b)

        if tree_a.root_hash != tree_b.root_hash:
            diff = MerkleTree.diff(tree_a, tree_b)
            # diff is a list of keys that differ between a and b
    """

    def __init__(self, state: Optional[Dict[str, str]] = None) -> None:
        self._state: Dict[str, str] = dict(state or {})
        self._leaves: List[MerkleNode] = []
        self._root: Optional[MerkleNode] = None
        self._rebuild()

    def update(self, key: str, value: str) -> None:
        """Update a single key and rebuild the tree. Supports incremental updates."""
        self._state[key] = value
        self._rebuild()

    def delete(self, key: str) -> None:
        """Remove a key and rebuild the tree."""
        self._state.pop(key, None)
        self._rebuild()

    def _rebuild(self) -> None:
        """Internal: rebuild leaves and root from current state."""
        sorted_pairs: List[Tuple[str, str]] = sorted(self._state.items())
        self._leaves = [
            MerkleNode(hash=_sha256(f"{k}:{v}"), key=k, value=v)
            for k, v in sorted_pairs
        ]
        self._root = self._build(self._leaves) if self._leaves else None

    # ── public API ────────────────────────────────────────────────────────────

    @property
    def root_hash(self) -> str:
        return self._root.hash if self._root else _sha256("")

    @property
    def leaf_count(self) -> int:
        return len(self._leaves)

    def get_proof(self, key: str) -> List[str]:
        """Return the sibling hashes needed to verify a leaf."""
        idx = self._key_index(key)
        if idx is None:
            return []
        return self._proof_path(self._root, list(range(len(self._leaves))), idx, [])

    @staticmethod
    def diff(tree_a: "MerkleTree", tree_b: "MerkleTree") -> List[str]:
        """
        Return the list of keys whose values differ between tree_a and tree_b.
        Keys present in one tree but not the other are also included.
        """
        keys_a = {n.key: n.value for n in tree_a._leaves}
        keys_b = {n.key: n.value for n in tree_b._leaves}
        differing: List[str] = []

        all_keys = set(keys_a) | set(keys_b)
        for k in all_keys:
            if keys_a.get(k) != keys_b.get(k):
                differing.append(k)

        return sorted(differing)

    def to_dict(self) -> dict:
        """Serialise the tree structure for network transmission."""
        return {
            "root_hash": self.root_hash,
            "leaf_count": self.leaf_count,
            "leaves": [
                {"key": n.key, "hash": n.hash}
                for n in self._leaves
            ],
        }

    # ── internal ──────────────────────────────────────────────────────────────

    def _build(self, nodes: List[MerkleNode]) -> Optional[MerkleNode]:
        if not nodes:
            return None
        if len(nodes) == 1:
            return nodes[0]

        mid = len(nodes) // 2
        left  = self._build(nodes[:mid])
        right = self._build(nodes[mid:])
        combined = (left.hash if left else "") + (right.hash if right else "")
        return MerkleNode(hash=_sha256(combined), left=left, right=right)

    def _key_index(self, key: str) -> Optional[int]:
        for i, leaf in enumerate(self._leaves):
            if leaf.key == key:
                return i
        return None

    def _proof_path(
        self,
        node: Optional[MerkleNode],
        indices: List[int],
        target: int,
        path: List[str],
    ) -> List[str]:
        if node is None or node.is_leaf:
            return path
        mid = len(indices) // 2
        left_indices  = indices[:mid]
        right_indices = indices[mid:]
        if target in left_indices:
            sibling_hash = node.right.hash if node.right else ""
            return self._proof_path(node.left, left_indices, target, path + [sibling_hash])
        else:
            sibling_hash = node.left.hash if node.left else ""
            return self._proof_path(node.right, right_indices, target, path + [sibling_hash])
