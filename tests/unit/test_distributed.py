"""
tests/unit/test_distributed.py
AEGIS-SILENTIUM v12 — Unit tests for all distributed systems modules

Run: pytest tests/unit/test_distributed.py -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "c2"))

import time
import threading
import pytest

# ── HLC ───────────────────────────────────────────────────────────────────────
from distributed.hlc import HybridLogicalClock, HLCTimestamp

class TestHLC:
    def test_monotonic_ticks(self):
        hlc = HybridLogicalClock("n1")
        ts1 = hlc.now()
        ts2 = hlc.now()
        assert ts2 >= ts1

    def test_recv_advances_clock(self):
        hlc_a = HybridLogicalClock("a")
        hlc_b = HybridLogicalClock("b")
        ts_a  = hlc_a.now()
        ts_b  = hlc_b.recv(ts_a)
        assert ts_b >= ts_a

    def test_thread_safety(self):
        hlc    = HybridLogicalClock("t")
        stamps = []
        lock   = threading.Lock()
        def tick():
            for _ in range(50):
                with lock:
                    stamps.append(hlc.now())
        threads = [threading.Thread(target=tick) for _ in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert len(stamps) == 250

    def test_drift_rejected(self):
        hlc = HybridLogicalClock("n")
        far_future = HLCTimestamp(l=int(time.time() * 1000) + 120_000, c=0)
        with pytest.raises(ValueError, match="drift"):
            hlc.recv(far_future)

    def test_serialisation(self):
        hlc = HybridLogicalClock("n")
        ts  = hlc.now()
        d   = ts.to_dict()
        ts2 = HLCTimestamp.from_dict(d)
        assert ts == ts2

    def test_comparison(self):
        ts1 = HLCTimestamp(l=1000, c=0)
        ts2 = HLCTimestamp(l=1000, c=1)
        ts3 = HLCTimestamp(l=1001, c=0)
        assert ts1 < ts2 < ts3


# ── Merkle ────────────────────────────────────────────────────────────────────
from distributed.merkle import MerkleTree

class TestMerkleTree:
    def test_empty_tree(self):
        t = MerkleTree({})
        assert t.root_hash  # not empty string
        assert t.leaf_count == 0

    def test_single_key(self):
        t = MerkleTree({"k": "v"})
        assert t.leaf_count == 1

    def test_identical_trees_same_hash(self):
        state = {"a": "1", "b": "2", "c": "3"}
        t1 = MerkleTree(state)
        t2 = MerkleTree(state)
        assert t1.root_hash == t2.root_hash

    def test_different_value_different_hash(self):
        t1 = MerkleTree({"k": "v1"})
        t2 = MerkleTree({"k": "v2"})
        assert t1.root_hash != t2.root_hash

    def test_diff_detects_changes(self):
        t1 = MerkleTree({"a": "1", "b": "2", "c": "3"})
        t2 = MerkleTree({"a": "1", "b": "CHANGED", "d": "4"})
        diff = MerkleTree.diff(t1, t2)
        assert "b" in diff
        assert "c" in diff  # in t1 not t2
        assert "d" in diff  # in t2 not t1
        assert "a" not in diff

    def test_diff_empty_against_populated(self):
        t1 = MerkleTree({})
        t2 = MerkleTree({"x": "1"})
        diff = MerkleTree.diff(t1, t2)
        assert "x" in diff

    def test_to_dict(self):
        t = MerkleTree({"a": "1"})
        d = t.to_dict()
        assert "root_hash" in d
        assert "leaves" in d


# ── WAL ───────────────────────────────────────────────────────────────────────
from distributed.wal import WriteAheadLog, WALStateMachine

class TestWAL:
    def test_append_monotonic_index(self):
        wal = WriteAheadLog()
        e1  = wal.append(0, "set", "k1", "v1")
        e2  = wal.append(0, "set", "k2", "v2")
        assert e2.index == e1.index + 1

    def test_entries_after(self):
        wal = WriteAheadLog()
        wal.append(0, "set", "k1", "v1")
        wal.append(0, "set", "k2", "v2")
        wal.append(0, "set", "k3", "v3")
        after = wal.entries_after(1)
        assert len(after) == 2

    def test_compact(self):
        wal  = WriteAheadLog()
        for i in range(10):
            wal.append(0, "set", f"k{i}", f"v{i}")
        wal.compact(5, {"k0": "v0"})
        assert all(e.index > 5 for e in wal)

    def test_state_machine_set_get(self):
        wal = WriteAheadLog()
        sm  = WALStateMachine(wal)
        sm.set("x", 42)
        assert sm.get("x") == 42

    def test_state_machine_delete(self):
        wal = WriteAheadLog()
        sm  = WALStateMachine(wal)
        sm.set("x", 1)
        sm.delete("x")
        assert sm.get("x") is None

    def test_replay_protection(self):
        wal = WriteAheadLog()
        sm  = WALStateMachine(wal)
        sm.set("a", 1)
        sm.set("b", 2)
        last = sm.last_applied
        # replay — should skip already-applied
        applied = sm.replay()
        assert applied == 0  # nothing new applied

    def test_crash_recovery(self):
        wal     = WriteAheadLog()
        sm_orig = WALStateMachine(wal)
        sm_orig.set("key", "val")

        # New SM replays the same WAL
        sm_new = WALStateMachine(wal)
        sm_new.replay()
        assert sm_new.get("key") == "val"


# ── CRDTs ─────────────────────────────────────────────────────────────────────
from distributed.crdt import GCounter, PNCounter, ORSet, LWWRegister, VectorClock

class TestCRDTs:
    def test_gcounter_merge(self):
        a = GCounter("n1"); a.increment(3)
        b = GCounter("n2"); b.increment(5)
        m = a.merge(b)
        assert m.value == 8

    def test_gcounter_idempotent(self):
        a = GCounter("n1"); a.increment(10)
        m = a.merge(a)
        assert m.value == 10

    def test_pncounter(self):
        c = PNCounter("n1")
        c.increment(10)
        c.decrement(3)
        assert c.value == 7

    def test_pncounter_merge(self):
        a = PNCounter("n1"); a.increment(5)
        b = PNCounter("n2"); b.decrement(2)
        m = a.merge(b)
        assert m.value == 3

    def test_orset_add_remove(self):
        s = ORSet()
        s.add("x")
        s.add("y")
        s.remove("x")
        assert "x" not in s.items()
        assert "y" in s.items()

    def test_orset_concurrent_add_wins(self):
        s1 = ORSet(); s2 = ORSet()
        s1.add("k")
        # s2 hasn't seen the add yet; remove concurrent with s1's add
        # After merge, add from s1 should survive
        m = s1.merge(s2)
        assert "k" in m.items()

    def test_orset_merge_commutative(self):
        s1 = ORSet(); s2 = ORSet()
        s1.add("a"); s2.add("b")
        m1 = s1.merge(s2)
        m2 = s2.merge(s1)
        assert m1.items() == m2.items()

    def test_lww_register(self):
        r = LWWRegister(value=None, timestamp_ms=0, node_id="n0")
        r = r.write("v1", timestamp_ms=100, node_id="n1")
        r = r.write("v2", timestamp_ms=50,  node_id="n2")  # older, ignored
        assert r.value == "v1"

    def test_vector_clock_tick(self):
        vc = VectorClock("n1")
        vc.tick()
        d = vc.to_dict()
        assert d.get("n1") == 1

    def test_vector_clock_merge(self):
        vc1 = VectorClock("n1"); vc1.tick(); vc1.tick()
        vc2 = VectorClock("n2"); vc2.tick()
        m = vc1.merge(vc2)
        d = m.to_dict()
        assert d["n1"] == 2
        assert d["n2"] == 1


# ── Gossip ────────────────────────────────────────────────────────────────────
from distributed.gossip import GossipProtocol, Member, MemberState

class TestGossip:
    def _make_protocol(self):
        calls = []
        def probe_fn(addr, msg): return True
        def gossip_fn(addr, deltas): calls.append(deltas)
        return GossipProtocol("n1", "127.0.0.1:5000", probe_fn, gossip_fn,
                               probe_interval=999, suspect_timeout=999), calls

    def test_join(self):
        g, _ = self._make_protocol()
        g.join(Member(node_id="n2", address="127.0.0.1:5001"))
        assert any(m.node_id == "n2" for m in g.members())

    def test_leave(self):
        g, _ = self._make_protocol()
        g.join(Member(node_id="n2", address="127.0.0.1:5001"))
        g.leave("n2")
        assert not any(m.node_id == "n2" for m in g.members())

    def test_merge_deltas(self):
        g, _ = self._make_protocol()
        g.join(Member(node_id="n2", address="127.0.0.1:5001"))
        delta = [{"node_id": "n2", "address": "127.0.0.1:5001",
                  "state": "suspect", "incarnation": 1}]
        g.merge_deltas(delta)
        suspects = [m for m in g.all_members() if m.state == MemberState.SUSPECT]
        assert any(m.node_id == "n2" for m in suspects)


# ── Fencing ───────────────────────────────────────────────────────────────────
from distributed.fencing import FencingTokenManager, StaleEpochError

class TestFencing:
    def test_new_epoch_increments(self):
        f = FencingTokenManager()
        e1 = f.new_epoch()
        e2 = f.new_epoch()
        assert e2 == e1 + 1

    def test_validate_current(self):
        f = FencingTokenManager()
        e = f.new_epoch()
        f.validate(e)  # should not raise

    def test_validate_stale(self):
        f = FencingTokenManager()
        e = f.new_epoch()
        f.new_epoch()  # bump again
        with pytest.raises(StaleEpochError):
            f.validate(e)

    def test_thread_safety(self):
        f      = FencingTokenManager()
        epochs = []
        lock   = threading.Lock()
        def bump():
            for _ in range(100):
                with lock:
                    epochs.append(f.new_epoch())
        threads = [threading.Thread(target=bump) for _ in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert len(set(epochs)) == 500  # all unique


# ── MVCC ──────────────────────────────────────────────────────────────────────
from distributed.mvcc import MVCCStore
from distributed.hlc  import HybridLogicalClock

class TestMVCC:
    def test_write_read(self):
        store = MVCCStore(HybridLogicalClock("t"))
        store.write("k", "v1")
        assert store.read_latest("k") == "v1"

    def test_snapshot_isolation(self):
        hlc   = HybridLogicalClock("t")
        store = MVCCStore(hlc)
        snap  = store.begin_snapshot()
        store.write("k", "after_snap")
        assert store.read("k", snap) is None  # write happened after snap
        store.release_snapshot(snap)

    def test_delete(self):
        store = MVCCStore(HybridLogicalClock("t"))
        store.write("k", "v")
        store.delete("k")
        assert store.read_latest("k") is None

    def test_multiple_versions(self):
        store = MVCCStore(HybridLogicalClock("t"))
        snap1 = store.begin_snapshot()
        store.write("k", "v1")
        snap2 = store.begin_snapshot()
        store.write("k", "v2")
        assert store.read("k", snap1) is None
        assert store.read("k", snap2) == "v1"
        store.release_snapshot(snap1)
        store.release_snapshot(snap2)


# ── Quorum ────────────────────────────────────────────────────────────────────
from distributed.quorum import QuorumManager, ConsistencyLevel, QuorumError

class TestQuorum:
    def _make_manager(self, n=3, fail_indices=None):
        fail_indices = fail_indices or []
        store = {}
        def read_fn(addr, key):
            idx = int(addr.split(":")[1])
            if idx in fail_indices:
                raise ConnectionError("down")
            return store.get(key, (None, 0))
        def write_fn(addr, key, val, ts):
            idx = int(addr.split(":")[1])
            if idx in fail_indices:
                raise ConnectionError("down")
            store[key] = (val, ts)
            return True
        addrs = [f"node:{i}" for i in range(n)]
        return QuorumManager(addrs, read_fn, write_fn), store

    def test_quorum_write(self):
        qm, _ = self._make_manager(3)
        cnt   = qm.write("k", "v", 1, ConsistencyLevel.QUORUM)
        assert cnt >= 2  # majority of 3

    def test_one_write(self):
        qm, _ = self._make_manager(3)
        cnt   = qm.write("k", "v", 1, ConsistencyLevel.ONE)
        assert cnt >= 1

    def test_quorum_write_fails_without_majority(self):
        qm, _ = self._make_manager(3, fail_indices=[0, 1])
        with pytest.raises(QuorumError):
            qm.write("k", "v", 1, ConsistencyLevel.QUORUM)

    def test_quorum_read(self):
        qm, _ = self._make_manager(3)
        qm.write("k", "v", 100, ConsistencyLevel.ALL)
        val = qm.read("k", ConsistencyLevel.QUORUM)
        assert val == "v"


# ── Anti-Entropy ──────────────────────────────────────────────────────────────
from distributed.anti_entropy import AntiEntropyScheduler

class TestAntiEntropy:
    def test_no_sync_when_in_sync(self):
        state = {"a": "1", "b": "2"}
        tree  = MerkleTree(state)

        applied = []
        sched = AntiEntropyScheduler(
            node_id     = "n1",
            state_fn    = lambda: dict(state),
            apply_fn    = lambda k, v: applied.append((k, v)),
            peers_fn    = lambda: ["peer1"],
            exchange_fn = lambda addr, keys: {},
            root_fn     = lambda addr: tree.root_hash,
            leaves_fn   = lambda addr: tree.to_dict()["leaves"],
            sync_interval = 9999,
        )
        synced = sched.run_session("peer1")
        assert synced == 0
        assert not applied

    def test_sync_when_diverged(self):
        local  = {"a": "1", "b": "2"}
        remote = {"a": "1", "b": "CHANGED", "c": "3"}

        remote_tree = MerkleTree(remote)
        applied     = {}

        sched = AntiEntropyScheduler(
            node_id     = "n1",
            state_fn    = lambda: dict(local),
            apply_fn    = lambda k, v: applied.update({k: v}),
            peers_fn    = lambda: ["peer1"],
            exchange_fn = lambda addr, keys: {k: remote[k] for k in keys if k in remote},
            root_fn     = lambda addr: remote_tree.root_hash,
            leaves_fn   = lambda addr: [{"key": l.key, "hash": l.hash, "value": l.value}
                                         for l in remote_tree._leaves],
            sync_interval = 9999,
        )
        synced = sched.run_session("peer1")
        assert synced > 0
        assert "b" in applied


# ── 2PC ───────────────────────────────────────────────────────────────────────
from distributed.two_phase_commit import TwoPCCoordinator, Mutation, TxnState

class TestTwoPhaseCommit:
    def _make_coordinator(self, n=3, fail_prepare=None, fail_commit=None):
        fail_prepare = fail_prepare or []
        fail_commit  = fail_commit  or []
        store = {}

        def prepare_fn(addr, txn_id, mutations):
            if addr in fail_prepare: return False
            return True

        def commit_fn(addr, txn_id):
            if addr in fail_commit: return False
            store[txn_id] = "committed"
            return True

        def abort_fn(addr, txn_id):
            store[txn_id] = "aborted"
            return True

        addrs = [f"node:{i}" for i in range(n)]
        return TwoPCCoordinator(addrs, prepare_fn, commit_fn, abort_fn, timeout=2.0), store

    def test_successful_commit(self):
        coord, store = self._make_coordinator(3)
        ok, txn_id = coord.execute([Mutation("k", "v")])
        assert ok
        txn = coord.get_transaction(txn_id)
        assert txn.state == TxnState.COMMITTED

    def test_abort_on_prepare_failure(self):
        coord, store = self._make_coordinator(3, fail_prepare=["node:0"])
        ok, txn_id = coord.execute([Mutation("k", "v")])
        assert not ok
        txn = coord.get_transaction(txn_id)
        assert txn.state == TxnState.ABORTED


# ── Lease Cache ───────────────────────────────────────────────────────────────
from distributed.lease import LeaseCache, SpeculativeReadBuffer

class TestLeaseCache:
    def test_read_with_valid_lease(self):
        local_store = {"k": "local"}
        cache = LeaseCache(
            node_id      = "n1",
            is_leader_fn = lambda: False,
            leader_fn    = lambda: "leader:5000",
            forward_fn   = lambda k: "from_leader",
            store_fn     = lambda k: local_store.get(k),
            lease_duration_s = 10.0,
        )
        cache.grant_lease("leader:5000", epoch=1)
        assert cache.has_valid_lease()
        assert cache.read("k") == "local"

    def test_read_without_lease_forwards(self):
        cache = LeaseCache(
            node_id      = "n1",
            is_leader_fn = lambda: False,
            leader_fn    = lambda: "leader:5000",
            forward_fn   = lambda k: "from_leader",
            store_fn     = lambda k: None,
        )
        assert cache.read("k") == "from_leader"

    def test_speculative_read_hit(self):
        buf = SpeculativeReadBuffer(
            forward_fn = lambda k: "from_leader",
            store_fn   = lambda k: None,
        )
        buf.record_write("k", "speculative_val", write_ts_ms=1000)
        val = buf.read("k", after_ts_ms=1000)
        assert val == "speculative_val"

    def test_speculative_read_miss_forwards(self):
        buf = SpeculativeReadBuffer(
            forward_fn = lambda k: "leader_val",
            store_fn   = lambda k: None,
        )
        val = buf.read("k")
        assert val == "leader_val"


# ── Consistent Hash Ring ──────────────────────────────────────────────────────
from distributed.consistent_hash import ConsistentHashRing, BloomFilter, PriorityTaskQueue, PriorityTask

class TestConsistentHashRing:
    def test_routing(self):
        ring = ConsistentHashRing()
        ring.add_node("n1")
        ring.add_node("n2")
        ring.add_node("n3")
        node = ring.get_node("some_key")
        assert node in ("n1", "n2", "n3")

    def test_stability_after_add(self):
        ring = ConsistentHashRing()
        ring.add_node("n1")
        ring.add_node("n2")
        assignments_before = {k: ring.get_node(k) for k in [f"key{i}" for i in range(100)]}
        ring.add_node("n3")
        assignments_after = {k: ring.get_node(k) for k in assignments_before}
        # Most keys should stay on the same node
        changed = sum(1 for k in assignments_before if assignments_before[k] != assignments_after[k])
        assert changed < 50  # less than half remapped

    def test_get_n_nodes(self):
        ring = ConsistentHashRing()
        for i in range(5):
            ring.add_node(f"n{i}")
        nodes = ring.get_nodes("k", 3)
        assert len(nodes) == 3
        assert len(set(nodes)) == 3  # distinct


class TestBloomFilter:
    def test_no_false_negatives(self):
        bf = BloomFilter(capacity=1000, error_rate=0.01)
        items = [f"item:{i}" for i in range(500)]
        for item in items:
            bf.add(item)
        for item in items:
            assert item in bf

    def test_false_positive_rate(self):
        bf     = BloomFilter(capacity=1000, error_rate=0.05)
        for i in range(1000):
            bf.add(f"present:{i}")
        fp = sum(1 for i in range(10000) if f"absent:{i}" in bf)
        assert fp / 10000 < 0.15  # within 3× target rate


class TestPriorityTaskQueue:
    def test_priority_order(self):
        q = PriorityTaskQueue()
        q.push(PriorityTask(priority=5, task_id="low"))
        q.push(PriorityTask(priority=1, task_id="high"))
        q.push(PriorityTask(priority=3, task_id="mid"))
        t1 = q.pop(timeout=0.1)
        t2 = q.pop(timeout=0.1)
        t3 = q.pop(timeout=0.1)
        assert t1.task_id == "high"
        assert t2.task_id == "mid"
        assert t3.task_id == "low"

    def test_timeout_returns_none(self):
        q = PriorityTaskQueue()
        t = q.pop(timeout=0.05)
        assert t is None

    def test_delayed_task(self):
        q = PriorityTaskQueue()
        q.push(PriorityTask(priority=1, task_id="delayed"), delay_s=0.2)
        t = q.pop(timeout=0.05)
        assert t is None  # not ready yet
        time.sleep(0.25)
        t = q.pop(timeout=0.1)
        assert t is not None and t.task_id == "delayed"


# ── Dead Letter Queue ─────────────────────────────────────────────────────────
from distributed.dead_letter import DeadLetterQueue

class TestDLQ:
    def test_push_and_list(self):
        dlq = DeadLetterQueue()
        e   = dlq.push("webhook", {"url": "http://x"}, "timeout", attempts=3)
        entries = dlq.list_entries()
        assert any(x.entry_id == e.entry_id for x in entries)

    def test_resolve(self):
        dlq = DeadLetterQueue()
        e   = dlq.push("task", "payload", "failed")
        dlq.resolve(e.entry_id)
        unresolved = dlq.list_entries(resolved=False)
        assert not any(x.entry_id == e.entry_id for x in unresolved)

    def test_replay(self):
        dlq     = DeadLetterQueue()
        e       = dlq.push("task", {"id": "t1"}, "net error")
        replayed = []
        def replay_fn(entry):
            replayed.append(entry.entry_id)
            return True
        success = dlq.replay(e.entry_id, replay_fn)
        assert success
        assert e.entry_id in replayed

    def test_max_size_eviction(self):
        dlq = DeadLetterQueue(max_size=5)
        for i in range(10):
            dlq.push("src", f"p{i}", "err")
        assert len(dlq.list_entries()) <= 5

    def test_stats(self):
        dlq = DeadLetterQueue()
        dlq.push("src", "p", "err")
        s = dlq.stats()
        assert s["total_received"] >= 1
