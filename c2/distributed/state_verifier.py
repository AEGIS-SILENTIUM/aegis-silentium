"""
c2/distributed/state_verifier.py
AEGIS-SILENTIUM v12 — Automated State Verification after Failover

After any leader election or replica promotion, the new primary runs a
background verification that samples its state against a quorum of
followers using Merkle proofs.  Discrepancies trigger an alert and
initiate a full anti-entropy sync.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from .merkle import MerkleTree

log = logging.getLogger("aegis.state_verifier")


class StateVerifier:
    """
    Post-failover state consistency verifier.

    Parameters
    ----------
    node_id         : this node's id
    state_fn        : callable() → Dict[str,str]  (local state snapshot)
    peer_root_fn    : callable(addr) → str         (peer's Merkle root)
    peer_leaves_fn  : callable(addr) → List[dict]  (peer's leaf list)
    alert_fn        : callable(msg: str) → None    (fire an alert)
    sync_fn         : callable(peer_addr) → None   (trigger anti-entropy)
    sample_fraction : fraction of keys to spot-check (default 0.2)
    quorum_size     : number of peers to verify against (default 2)
    """

    def __init__(
        self,
        node_id:          str,
        state_fn:         Callable[[], Dict[str, str]],
        peer_root_fn:     Callable[[str], str],
        peer_leaves_fn:   Callable[[str], List[dict]],
        alert_fn:         Callable[[str], None],
        sync_fn:          Callable[[str], None],
        sample_fraction:  float = 0.2,
        quorum_size:      int   = 2,
    ) -> None:
        self._node_id        = node_id
        self._state_fn       = state_fn
        self._peer_root      = peer_root_fn
        self._peer_leaves    = peer_leaves_fn
        self._alert          = alert_fn
        self._sync           = sync_fn
        self._sample_frac    = sample_fraction
        self._quorum_size    = quorum_size
        self._results: List[dict] = []
        self._lock = threading.Lock()

    def verify_after_failover(self, peers: List[str]) -> dict:
        """
        Run a full verification against a quorum of peers.
        Returns a result dict with divergence details.
        """
        local_state = self._state_fn()
        local_tree  = MerkleTree(local_state)

        selected_peers = random.sample(peers, min(self._quorum_size, len(peers)))
        divergent_keys: set = set()
        peer_errors: List[str] = []

        for peer_addr in selected_peers:
            try:
                peer_root = self._peer_root(peer_addr)
                if peer_root == local_tree.root_hash:
                    log.info("StateVerifier: in-sync with %s", peer_addr)
                    continue

                peer_leaves = self._peer_leaves(peer_addr)
                peer_tree = MerkleTree.__new__(MerkleTree)
                peer_tree._leaves = []
                peer_tree._root   = None
                # Rebuild from leaf list for diff
                peer_state = {l["key"]: l.get("value", "") for l in peer_leaves}
                peer_tree_real = MerkleTree(peer_state)
                divergent = MerkleTree.diff(local_tree, peer_tree_real)
                divergent_keys.update(divergent)
                log.warning(
                    "StateVerifier: %d divergent keys vs %s: %s",
                    len(divergent), peer_addr, divergent[:10]
                )
            except Exception as exc:
                peer_errors.append(f"{peer_addr}: {exc}")
                log.error("StateVerifier: peer error %s: %s", peer_addr, exc)

        result = {
            "node_id":         self._node_id,
            "timestamp":       time.time(),
            "peers_checked":   selected_peers,
            "peer_errors":     peer_errors,
            "divergent_keys":  sorted(divergent_keys),
            "divergent_count": len(divergent_keys),
            "clean":           len(divergent_keys) == 0 and not peer_errors,
        }

        with self._lock:
            self._results.append(result)

        if divergent_keys:
            msg = (
                f"[AEGIS-SILENTIUM] Post-failover divergence detected on {self._node_id}: "
                f"{len(divergent_keys)} keys differ vs quorum. "
                f"Sample: {sorted(divergent_keys)[:5]}"
            )
            self._alert(msg)
            for peer_addr in selected_peers:
                try:
                    self._sync(peer_addr)
                except Exception as exc:
                    log.error("Failed to trigger anti-entropy with %s: %s", peer_addr, exc)

        return result

    def last_results(self, n: int = 10) -> List[dict]:
        with self._lock:
            return list(self._results[-n:])
