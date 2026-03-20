"""
c2/distributed/anti_entropy.py
AEGIS-SILENTIUM v12 — Anti-Entropy with Incremental Sync

Periodically, nodes compare their state fingerprints (Merkle root) with a
random peer.  If they diverge, only the delta is exchanged — not a full
dump — drastically reducing sync bandwidth.

Protocol
--------
  1. Local node computes its MerkleTree and sends root_hash to a random peer.
  2. Peer replies with its own root_hash.
  3. If hashes match: done.
  4. If hashes differ: exchange leaf lists to find diverging keys.
  5. Fetch values for diverging keys from the peer and apply locally.
  6. Peer does the same in parallel.

Thread
------
  AntiEntropyScheduler runs a background thread that fires every
  sync_interval seconds and selects a random peer.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from .merkle import MerkleTree

log = logging.getLogger("aegis.anti_entropy")


class AntiEntropyScheduler:
    """
    Runs periodic anti-entropy sessions between this node and random peers.

    Parameters
    ----------
    node_id        : identifier for this node
    state_fn       : callable() → Dict[str, str]  (current full state snapshot)
    apply_fn       : callable(key, value) → None   (apply a received value)
    peers_fn       : callable() → List[str]        (current live peer addresses)
    exchange_fn    : callable(peer_addr, diff_keys) → Dict[str, str]
                     (ask peer for its values for the given keys)
    root_fn        : callable(peer_addr) → str     (ask peer for its Merkle root)
    leaves_fn      : callable(peer_addr) → List[dict] (ask peer for leaf list)
    sync_interval  : seconds between sessions (default 30)
    """

    def __init__(
        self,
        node_id:       str,
        state_fn:      Callable[[], Dict[str, str]],
        apply_fn:      Callable[[str, str], None],
        peers_fn:      Callable[[], List[str]],
        exchange_fn:   Callable[[str, List[str]], Dict[str, str]],
        root_fn:       Callable[[str], str],
        leaves_fn:     Callable[[str], List[dict]],
        sync_interval: float = 30.0,
    ) -> None:
        self._node_id      = node_id
        self._state_fn     = state_fn
        self._apply_fn     = apply_fn
        self._peers_fn     = peers_fn
        self._exchange_fn  = exchange_fn
        self._root_fn      = root_fn
        self._leaves_fn    = leaves_fn
        self._interval     = sync_interval
        self._running      = False
        self._thread: Optional[threading.Thread] = None
        self._stats        = {"sessions": 0, "keys_synced": 0, "errors": 0}

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="anti-entropy"
        )
        self._thread.start()
        log.info("Anti-entropy started node=%s interval=%ss", self._node_id, self._interval)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def stats(self) -> dict:
        return dict(self._stats)

    # ── session ───────────────────────────────────────────────────────────────

    def run_session(self, peer_addr: str) -> int:
        """
        Run one anti-entropy session with peer_addr.
        Returns the number of keys synced.
        """
        try:
            peer_root = self._root_fn(peer_addr)
            local_state = self._state_fn()
            local_tree  = MerkleTree(local_state)

            if local_tree.root_hash == peer_root:
                log.debug("Anti-entropy: in-sync with %s", peer_addr)
                return 0

            # Roots differ — find diverging keys via leaf exchange
            peer_leaves = self._leaves_fn(peer_addr)
            peer_state  = {l["key"]: l["hash"] for l in peer_leaves}

            # Keys whose leaf hash differs or are missing locally
            diff_keys: List[str] = []
            local_leaf_hashes = {n.key: n.hash for n in local_tree._leaves}
            for key, phash in peer_state.items():
                if local_leaf_hashes.get(key) != phash:
                    diff_keys.append(key)
            # Keys we have that peer doesn't (peer should pull from us, but we log)
            for key in local_leaf_hashes:
                if key not in peer_state:
                    diff_keys.append(key)

            diff_keys = list(set(diff_keys))
            if not diff_keys:
                return 0

            # Fetch peer's values for diverging keys
            peer_values = self._exchange_fn(peer_addr, diff_keys)
            applied = 0
            for key, value in peer_values.items():
                try:
                    self._apply_fn(key, value)
                    applied += 1
                except Exception as exc:
                    log.warning("Failed to apply key=%s: %s", key, exc)

            log.info(
                "Anti-entropy: synced %d/%d keys from %s",
                applied, len(diff_keys), peer_addr
            )
            self._stats["keys_synced"] += applied
            return applied

        except Exception as exc:
            self._stats["errors"] += 1
            log.warning("Anti-entropy session failed peer=%s: %s", peer_addr, exc)
            return 0

    # ── background loop ───────────────────────────────────────────────────────

    def _loop(self) -> None:
        while self._running:
            time.sleep(self._interval)
            try:
                peers = self._peers_fn()
                if peers:
                    peer = random.choice(peers)
                    self._stats["sessions"] += 1
                    self.run_session(peer)
            except Exception:
                log.exception("Anti-entropy loop error")
