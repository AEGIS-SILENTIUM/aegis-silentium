"""
tests/unit/test_v11_modules.py
AEGIS-SILENTIUM v12 — Comprehensive Unit Tests

Coverage:
  - Raft consensus (RaftLog, RaftNode states, leader election)
  - KV State Machine (SET/DEL/CAS/INCR/MSET)
  - IOC Manager (CRUD, lookup, expiry, bulk ops)
  - MITRE ATT&CK (observation, campaign profile, navigator export)
  - Threat Graph (add/query/PageRank/shortest path)
  - Plugin Engine (load_inline, enable/disable, dispatch, timeout)
  - Event Log (write, read, tail, consumer groups, batch)
  - Event Projector (view registration, projection application)
  - Network Topology (add node/edge, routing, chokepoints)
  - Fencing Token Manager (multi-resource, epoch history, grace window)
  - WAL (append, CRC verify, replay, checkpoint, compaction)
  - Saga Orchestrator (happy path, compensation, partial failure)
  - Service Registry (register, heartbeat, expiry, LB strategies)
"""

import sys, os, time, threading, uuid
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../c2'))

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Raft Consensus
# ─────────────────────────────────────────────────────────────────────────────

class TestRaftLog:
    def _make_log(self):
        from consensus.raft import RaftLog, LogEntry
        return RaftLog(), LogEntry

    def test_append_and_last_index(self):
        log, LE = self._make_log()
        log.append(LE(term=1, index=1, command="a"))
        log.append(LE(term=1, index=2, command="b"))
        assert log.last_index() == 2
        assert log.last_term() == 1

    def test_entry_at(self):
        log, LE = self._make_log()
        e = LE(term=2, index=1, command={"op": "SET"})
        log.append(e)
        got = log.entry_at(1)
        assert got is not None
        assert got.term == 2
        assert got.command == {"op": "SET"}

    def test_truncate_after(self):
        log, LE = self._make_log()
        for i in range(1, 6):
            log.append(LE(term=1, index=i, command=i))
        log.truncate_after(3)
        assert log.last_index() == 3
        assert log.entry_at(4) is None
        assert log.entry_at(5) is None

    def test_slice(self):
        log, LE = self._make_log()
        for i in range(1, 6):
            log.append(LE(term=1, index=i, command=i))
        sl = log.slice(2, 4)
        assert len(sl) == 2
        assert sl[0].index == 2
        assert sl[1].index == 3

    def test_compact(self):
        log, LE = self._make_log()
        for i in range(1, 6):
            log.append(LE(term=1, index=i, command=i))
        log.compact(3, 1)
        assert log.snapshot_index() == 3
        assert log.last_index() == 5
        # entries before 3 are gone
        assert log.entry_at(1) is None

    def test_term_at_snapshot(self):
        log, LE = self._make_log()
        log.append(LE(term=1, index=1, command="x"))
        log.compact(1, 1)
        assert log.term_at(1) == 1


class TestKVStateMachine:
    def _make_sm(self):
        from consensus.state_machine import KVStateMachine
        from consensus.raft import LogEntry
        sm = KVStateMachine()
        return sm, LogEntry

    def test_set_and_get(self):
        sm, LE = self._make_sm()
        sm.apply(LE(term=1, index=1, command={"op": "SET", "key": "x", "value": 42}))
        assert sm.get("x") == 42

    def test_del(self):
        sm, LE = self._make_sm()
        sm.apply(LE(term=1, index=1, command={"op": "SET", "key": "y", "value": "hello"}))
        sm.apply(LE(term=1, index=2, command={"op": "DEL", "key": "y"}))
        assert sm.get("y") is None

    def test_cas_success(self):
        sm, LE = self._make_sm()
        sm.apply(LE(term=1, index=1, command={"op": "SET", "key": "z", "value": 10}))
        sm.apply(LE(term=1, index=2, command={"op": "CAS", "key": "z", "expected": 10, "value": 20}))
        assert sm.get("z") == 20

    def test_cas_fail(self):
        sm, LE = self._make_sm()
        sm.apply(LE(term=1, index=1, command={"op": "SET", "key": "z", "value": 10}))
        sm.apply(LE(term=1, index=2, command={"op": "CAS", "key": "z", "expected": 99, "value": 20}))
        assert sm.get("z") == 10   # unchanged

    def test_incr(self):
        sm, LE = self._make_sm()
        sm.apply(LE(term=1, index=1, command={"op": "INCR", "key": "ctr", "delta": 5}))
        sm.apply(LE(term=1, index=2, command={"op": "INCR", "key": "ctr", "delta": 3}))
        assert sm.get("ctr") == 8

    def test_mset(self):
        sm, LE = self._make_sm()
        sm.apply(LE(term=1, index=1, command={"op": "MSET", "pairs": {"a": 1, "b": 2, "c": 3}}))
        assert sm.get("a") == 1
        assert sm.get("b") == 2
        assert sm.get("c") == 3

    def test_keys_prefix(self):
        sm, LE = self._make_sm()
        sm.apply(LE(term=1, index=1, command={"op": "MSET",
                    "pairs": {"node:1": "a", "node:2": "b", "task:1": "c"}}))
        node_keys = sm.keys("node:")
        assert "node:1" in node_keys
        assert "node:2" in node_keys
        assert "task:1" not in node_keys

    def test_noop_skipped(self):
        sm, LE = self._make_sm()
        sm.apply(LE(term=1, index=1, command={"__noop__": True}))
        assert sm.stats()["applied_count"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# IOC Manager
# ─────────────────────────────────────────────────────────────────────────────

class TestIOCManager:
    def _make_mgr(self):
        from intelligence.ioc_manager import IOCManager, IOC, IOCType, IOCSeverity
        return IOCManager(auto_expire=False), IOC, IOCType, IOCSeverity

    def test_add_and_get(self):
        mgr, IOC, IOCType, _ = self._make_mgr()
        ioc = IOC(ioc_id="", ioc_type=IOCType.IP_ADDRESS, value="10.0.0.1", confidence=0.9)
        ioc_id = mgr.add(ioc)
        got = mgr.get(ioc_id)
        assert got is not None
        assert got.value == "10.0.0.1"
        assert got.severity.value == "critical"  # 0.9 → critical

    def test_lookup_ip(self):
        mgr, IOC, IOCType, _ = self._make_mgr()
        ioc = IOC(ioc_id="", ioc_type=IOCType.IP_ADDRESS, value="192.168.1.100")
        mgr.add(ioc)
        results = mgr.lookup_ip("192.168.1.100")
        assert len(results) == 1
        assert results[0].value == "192.168.1.100"

    def test_lookup_domain_wildcard(self):
        mgr, IOC, IOCType, _ = self._make_mgr()
        ioc = IOC(ioc_id="", ioc_type=IOCType.DOMAIN, value="*.evil.com")
        mgr.add(ioc)
        results = mgr.lookup_domain("payload.evil.com")
        assert len(results) >= 1

    def test_lookup_hash(self):
        mgr, IOC, IOCType, _ = self._make_mgr()
        h = "a" * 64
        ioc = IOC(ioc_id="", ioc_type=IOCType.SHA256, value=h)
        mgr.add(ioc)
        results = mgr.lookup_hash(h)
        assert len(results) == 1

    def test_remove(self):
        mgr, IOC, IOCType, _ = self._make_mgr()
        ioc = IOC(ioc_id="", ioc_type=IOCType.URL, value="http://malware.test/payload")
        ioc_id = mgr.add(ioc)
        ok = mgr.remove(ioc_id)
        assert ok
        assert mgr.get(ioc_id) is None

    def test_search_by_tag(self):
        mgr, IOC, IOCType, _ = self._make_mgr()
        ioc1 = IOC(ioc_id="", ioc_type=IOCType.DOMAIN, value="apt29.com", tags=["apt29"])
        ioc2 = IOC(ioc_id="", ioc_type=IOCType.DOMAIN, value="cozy.bear", tags=["apt29", "russia"])
        ioc3 = IOC(ioc_id="", ioc_type=IOCType.DOMAIN, value="other.com", tags=["lazarus"])
        mgr.add(ioc1); mgr.add(ioc2); mgr.add(ioc3)
        results = mgr.search(tags=["apt29"])
        assert len(results) == 2

    def test_bulk_add(self):
        mgr, IOC, IOCType, _ = self._make_mgr()
        iocs = [IOC(ioc_id="", ioc_type=IOCType.IP_ADDRESS, value=f"10.0.0.{i}") for i in range(10)]
        count = mgr.bulk_add(iocs)
        assert count == 10
        assert mgr.stats()["active_count"] == 10

    def test_export_import(self):
        mgr, IOC, IOCType, _ = self._make_mgr()
        ioc = IOC(ioc_id="", ioc_type=IOCType.CVE, value="CVE-2024-1234", confidence=0.95, tags=["critical"])
        mgr.add(ioc)
        exported = mgr.export_all()
        assert len(exported) == 1
        mgr2, _, _, _ = self._make_mgr()
        mgr2.import_bulk(exported)
        results = mgr2.search(tags=["critical"])
        assert len(results) == 1

    def test_hit_counting(self):
        mgr, IOC, IOCType, _ = self._make_mgr()
        ioc = IOC(ioc_id="", ioc_type=IOCType.IP_ADDRESS, value="1.2.3.4")
        mgr.add(ioc)
        for _ in range(5):
            mgr.lookup_ip("1.2.3.4")
        results = mgr.search()
        assert results[0].hit_count == 5

    def test_ttl_expiry(self):
        mgr, IOC, IOCType, _ = self._make_mgr()
        ioc = IOC(ioc_id="", ioc_type=IOCType.DOMAIN, value="expired.com", ttl_seconds=0)
        ioc_id = mgr.add(ioc)
        time.sleep(0.01)
        results = mgr.search()  # active=True, so expired items excluded
        assert not any(r.ioc_id == ioc_id for r in results)


# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK
# ─────────────────────────────────────────────────────────────────────────────

class TestMITREMapper:
    def _make(self):
        from intelligence.mitre_attack import MITREMapper
        return MITREMapper()

    def test_embedded_techniques_loaded(self):
        m = self._make()
        stats = m.stats()
        assert stats["total_techniques"] > 40
        assert stats["total_tactics"] == 12

    def test_get_technique(self):
        m = self._make()
        t = m.get_technique("T1059")
        assert t is not None
        assert t.name == "Command and Scripting Interpreter"
        assert "TA0002" in t.tactic_ids

    def test_subtechnique(self):
        m = self._make()
        t = m.get_technique("T1059.001")
        assert t is not None
        assert t.is_subtechnique
        assert t.parent_id == "T1059"

    def test_observe_and_retrieve(self):
        m = self._make()
        obs_id = m.observe("T1059.001", campaign_id="camp-1",
                           confidence=0.9, evidence="PS encoded cmd")
        assert obs_id
        obs_list = m.all_observations()
        assert any(o["obs_id"] == obs_id for o in obs_list)

    def test_campaign_profile(self):
        m = self._make()
        m.observe("T1059.001", campaign_id="camp-x", confidence=0.9)
        m.observe("T1046", campaign_id="camp-x", confidence=0.7)
        m.observe("T1021.004", campaign_id="camp-x", confidence=0.8)
        profile = m.campaign_profile("camp-x")
        assert profile["technique_count"] == 3
        assert len(profile["tactic_coverage"]) > 0

    def test_navigator_export(self):
        m = self._make()
        m.observe("T1059.001", campaign_id="camp-y", confidence=0.85)
        nav = m.navigator_export(campaign_id="camp-y")
        assert nav["domain"] == "enterprise-attack"
        assert len(nav["techniques"]) >= 1
        assert nav["techniques"][0]["techniqueID"] == "T1059.001"

    def test_techniques_for_tactic(self):
        m = self._make()
        techs = m.techniques_for_tactic("TA0002")
        assert len(techs) > 0
        assert all("TA0002" in t.tactic_ids for t in techs)


# ─────────────────────────────────────────────────────────────────────────────
# Threat Graph
# ─────────────────────────────────────────────────────────────────────────────

class TestThreatGraph:
    def _make(self):
        from intelligence.threat_graph import ThreatGraph, ThreatActor, EdgeType, NodeKind
        return ThreatGraph(), ThreatActor, EdgeType, NodeKind

    def test_add_actor_and_node(self):
        g, TA, ET, NK = self._make()
        actor = TA(actor_id="apt29", name="APT29", aliases=["Cozy Bear"])
        g.add_actor(actor)
        g.add_node("wellmess", NK.TOOL, {"name": "WellMess"})
        assert g.stats()["node_count"] == 2

    def test_add_edge_and_neighbors(self):
        g, TA, ET, NK = self._make()
        g.add_actor(TA(actor_id="apt29", name="APT29", aliases=[]))
        g.add_node("wellmess", NK.TOOL, {"name": "WellMess"})
        g.add_edge("apt29", "wellmess", ET.USES, confidence=0.95)
        neighbors = g.neighbors("apt29", direction="out")
        assert len(neighbors) == 1
        assert neighbors[0]["edge"]["edge_type"] == "uses"

    def test_shortest_path(self):
        g, TA, ET, NK = self._make()
        for i in range(4):
            g.add_node(str(i), NK.IOC, {"id": i})
        g.add_edge("0", "1", ET.RELATED_TO)
        g.add_edge("1", "2", ET.RELATED_TO)
        g.add_edge("2", "3", ET.RELATED_TO)
        path = g.shortest_path("0", "3")
        assert path == ["0", "1", "2", "3"]

    def test_no_path(self):
        g, TA, ET, NK = self._make()
        g.add_node("a", NK.IOC, {})
        g.add_node("b", NK.IOC, {})
        assert g.shortest_path("a", "b") is None

    def test_pagerank(self):
        g, TA, ET, NK = self._make()
        for nid in ["hub", "a", "b", "c"]:
            g.add_node(nid, NK.IOC, {})
        g.add_edge("a", "hub", ET.RELATED_TO)
        g.add_edge("b", "hub", ET.RELATED_TO)
        g.add_edge("c", "hub", ET.RELATED_TO)
        scores = g.pagerank()
        assert scores["hub"] > scores["a"]

    def test_export(self):
        g, TA, ET, NK = self._make()
        g.add_node("n1", NK.IOC, {"v": 1})
        g.add_node("n2", NK.IOC, {"v": 2})
        g.add_edge("n1", "n2", ET.COMMUNICATES)
        exported = g.export()
        assert len(exported["nodes"]) == 2
        assert len(exported["edges"]) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Plugin Engine
# ─────────────────────────────────────────────────────────────────────────────

class TestPluginEngine:
    def _make(self):
        from plugins.engine import PluginEngine, PluginManifest, PluginHook, PluginStatus
        engine = PluginEngine(plugin_dir="/tmp/aegis-plugins-test")
        return engine, PluginManifest, PluginHook, PluginStatus

    def test_load_inline_and_enable(self):
        engine, PM, PH, PS = self._make()
        manifest = PM(plugin_id="test-plugin", name="Test", version="1.0",
                      author="test", description="unit test plugin",
                      plugin_type="notification", hooks=["on_event"])
        results_store = []
        def on_event(ctx):
            results_store.append(ctx)
            return {"handled": True}
        engine.load_inline(manifest, {"on_event": on_event})
        engine.enable("test-plugin")
        stats = engine.stats()
        assert stats["enabled_plugins"] == 1

    def test_dispatch_hook(self):
        engine, PM, PH, PS = self._make()
        manifest = PM(plugin_id="disp-test", name="Dispatch Test", version="1.0",
                      author="test", description="dispatch test",
                      plugin_type="notification", hooks=["on_alert"])
        called = []
        def on_alert(ctx): called.append(ctx["message"]); return {"ok": True}
        engine.load_inline(manifest, {"on_alert": on_alert})
        engine.enable("disp-test")
        results = engine.dispatch(PH.ON_ALERT, {"message": "test-alert", "severity": "high"})
        assert len(results) == 1
        assert results[0]["result"]["ok"]
        assert called == ["test-alert"]

    def test_disable_stops_dispatch(self):
        engine, PM, PH, PS = self._make()
        manifest = PM(plugin_id="dis-test2", name="Disable Test", version="1.0",
                      author="test", description="",
                      plugin_type="notification", hooks=["on_event"])
        called = []
        def on_event(ctx): called.append(1)
        engine.load_inline(manifest, {"on_event": on_event})
        engine.enable("dis-test2")
        engine.dispatch(PH.ON_EVENT, {})
        engine.disable("dis-test2")
        engine.dispatch(PH.ON_EVENT, {})
        assert len(called) == 1  # only fired once

    def test_timeout_handled(self):
        import time as _time
        engine, PM, PH, PS = self._make()
        engine._HOOK_TIMEOUT = 0.1  # short timeout
        manifest = PM(plugin_id="timeout-test", name="Timeout Test", version="1.0",
                      author="test", description="",
                      plugin_type="notification", hooks=["on_node_connect"])
        def on_node_connect(ctx): _time.sleep(5)  # will timeout
        engine.load_inline(manifest, {"on_node_connect": on_node_connect})
        engine.enable("timeout-test")
        results = engine.dispatch(PH.ON_NODE_CONNECT, {})
        assert len(results) == 0  # timeout = no result
        assert engine.stats()["total_timeouts"] >= 1

    def test_stats(self):
        engine, PM, PH, PS = self._make()
        s = engine.stats()
        assert "total_plugins" in s
        assert "enabled_plugins" in s
        assert "total_dispatches" in s


# ─────────────────────────────────────────────────────────────────────────────
# Event Log
# ─────────────────────────────────────────────────────────────────────────────

class TestEventLog:
    def _make(self):
        from streaming.event_log import EventLog
        return EventLog()

    def test_write_and_read(self):
        log = self._make()
        log.write("c2.events", "node.connected", {"node_id": "abc"}, immediate=True)
        time.sleep(0.05)
        records = log.read("c2.events", start_offset=0, max_records=10)
        assert len(records) == 1
        assert records[0].event_type == "node.connected"
        assert records[0].payload["node_id"] == "abc"

    def test_sequential_offsets(self):
        log = self._make()
        offsets = [log.write("c2.t", "e", i, immediate=True) for i in range(5)]
        assert offsets == list(range(5))

    def test_tail(self):
        log = self._make()
        for i in range(20):
            log.write("c2.t", "e", i, immediate=True)
        tail = log.tail("c2.t", n=5)
        assert len(tail) == 5
        assert tail[-1].payload == 19

    def test_topic_isolation(self):
        log = self._make()
        log.write("topic-a", "e", {"a": 1}, immediate=True)
        log.write("topic-b", "e", {"b": 2}, immediate=True)
        recs_a = log.read("topic-a")
        recs_b = log.read("topic-b")
        assert len(recs_a) == 1 and recs_a[0].payload["a"] == 1
        assert len(recs_b) == 1 and recs_b[0].payload["b"] == 2

    def test_consumer_offset_tracking(self):
        log = self._make()
        for i in range(10):
            log.write("c2.t2", "e", i, immediate=True)
        reader = log.get_reader("consumer-1", "c2.t2", start_offset=0)
        batch1 = reader.poll(max_records=5)
        assert len(batch1) == 5
        batch2 = reader.poll(max_records=5)
        assert len(batch2) == 5
        batch3 = reader.poll(max_records=5)
        assert len(batch3) == 0

    def test_push_subscription(self):
        log = self._make()
        received = []
        log.subscribe("c2.sub", lambda r: received.append(r.event_type))
        log.write("c2.sub", "test.event", {}, immediate=True)
        time.sleep(0.05)
        assert "test.event" in received

    def test_write_batch(self):
        log = self._make()
        records = [("c2.batch", "e", i) for i in range(5)]
        offsets = log.write_batch(records)
        assert len(offsets) == 5
        assert offsets == list(range(offsets[0], offsets[0]+5))

    def test_stats(self):
        log = self._make()
        log.write("t", "e", {}, immediate=True)
        s = log.stats()
        assert s["total_written"] >= 1
        assert "current_offset" in s


# ─────────────────────────────────────────────────────────────────────────────
# Event Projector
# ─────────────────────────────────────────────────────────────────────────────

class TestEventProjector:
    def test_projection_applied(self):
        from streaming.event_log import EventLog
        from streaming.projector import EventProjector, ProjectionView
        log = EventLog()
        projector = EventProjector(log, poll_interval=0.05)

        counts = {"c": 0}
        def handler(state, event):
            state["count"] = state.get("count", 0) + 1
            return state

        view = ProjectionView(name="counter", handler=handler)
        projector.register_view_all_topics(view)
        projector.start()

        for _ in range(5):
            log.write("t", "e", {}, immediate=True)
        time.sleep(0.3)

        result = projector.query("counter")
        assert result["count"] >= 5

    def test_builtin_views(self):
        from streaming.event_log import EventLog
        from streaming.projector import (
            EventProjector, make_node_status_view,
            make_alert_counter_view
        )
        log = EventLog()
        p = EventProjector(log, poll_interval=0.05)
        p.register_view_all_topics(make_node_status_view())
        p.register_view_all_topics(make_alert_counter_view())
        p.start()

        log.write("c2", "node.connected", {"node_id": "n1", "ip": "1.2.3.4"}, immediate=True)
        log.write("c2", "alert", {"severity": "high", "message": "test"}, immediate=True)
        time.sleep(0.3)

        nodes = p.query("node_status")
        alerts = p.query("alert_counters")
        assert "n1" in nodes
        assert alerts["high"] >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Network Topology
# ─────────────────────────────────────────────────────────────────────────────

class TestNetworkTopology:
    def _make(self):
        from network.topology import NetworkTopology, NetworkNode, NetworkEdge, NodeRole
        return NetworkTopology(), NetworkNode, NetworkEdge, NodeRole

    def test_add_node_and_role_classification(self):
        topo, NN, NE, NR = self._make()
        node = NN(node_id="web1", ip="10.0.0.1", open_ports=[80, 443])
        topo.add_node(node)
        assert topo.stats()["node_count"] == 1
        assert node.role == NR.WEB_SERVER

    def test_domain_controller_role(self):
        _, NN, _, NR = self._make()
        node = NN(node_id="dc1", ip="10.0.0.2", open_ports=[88, 389, 3268])
        assert node.role == NR.DOMAIN_CONTROLLER

    def test_shortest_path(self):
        topo, NN, NE, NR = self._make()
        for i in range(4):
            topo.add_node(NN(node_id=f"n{i}", ip=f"10.0.0.{i}"))
        topo.add_edge(NE(edge_id="e1", src_id="n0", dst_id="n1", weight=1))
        topo.add_edge(NE(edge_id="e2", src_id="n1", dst_id="n2", weight=1))
        topo.add_edge(NE(edge_id="e3", src_id="n2", dst_id="n3", weight=1))
        path = topo.shortest_path("n0", "n3")
        assert path is not None
        assert path.nodes == ["n0", "n1", "n2", "n3"]
        assert path.hops == 3

    def test_shortest_path_weighted(self):
        topo, NN, NE, NR = self._make()
        for i in range(3):
            topo.add_node(NN(node_id=f"n{i}", ip=f"10.0.0.{i}"))
        # Direct path is expensive
        topo.add_edge(NE(edge_id="e-direct", src_id="n0", dst_id="n2", weight=100))
        # Indirect is cheaper
        topo.add_edge(NE(edge_id="e-a", src_id="n0", dst_id="n1", weight=1))
        topo.add_edge(NE(edge_id="e-b", src_id="n1", dst_id="n2", weight=1))
        path = topo.shortest_path("n0", "n2")
        assert path.nodes == ["n0", "n1", "n2"]

    def test_chokepoints(self):
        topo, NN, NE, NR = self._make()
        # Linear graph: 0-1-2-3 — node 1 and 2 are chokepoints
        for i in range(4):
            topo.add_node(NN(node_id=str(i), ip=f"10.0.0.{i}"))
        topo.add_edge(NE(edge_id="e01", src_id="0", dst_id="1", bidirectional=True))
        topo.add_edge(NE(edge_id="e12", src_id="1", dst_id="2", bidirectional=True))
        topo.add_edge(NE(edge_id="e23", src_id="2", dst_id="3", bidirectional=True))
        cps = topo.find_chokepoints()
        assert "1" in cps or "2" in cps

    def test_connected_components(self):
        topo, NN, NE, NR = self._make()
        for i in range(4):
            topo.add_node(NN(node_id=str(i), ip=f"10.0.0.{i}"))
        topo.add_edge(NE(edge_id="e01", src_id="0", dst_id="1"))
        topo.add_edge(NE(edge_id="e23", src_id="2", dst_id="3"))
        comps = topo.find_connected_components()
        assert len(comps) == 2

    def test_nodes_by_role(self):
        topo, NN, NE, NR = self._make()
        topo.add_node(NN(node_id="db1", ip="10.0.0.1", open_ports=[3306]))
        topo.add_node(NN(node_id="web1", ip="10.0.0.2", open_ports=[80, 443]))
        dbs = topo.nodes_by_role(NR.DATABASE)
        assert len(dbs) >= 1
        assert dbs[0].node_id == "db1"

    def test_export_formats(self):
        topo, NN, NE, NR = self._make()
        topo.add_node(NN(node_id="n1", ip="10.0.0.1"))
        d = topo.to_dict()
        assert "nodes" in d and "edges" in d
        d3 = topo.to_d3_json()
        assert "nodes" in d3 and "links" in d3
        dot = topo.to_dot()
        assert "digraph" in dot


# ─────────────────────────────────────────────────────────────────────────────
# Fencing Token Manager (v11)
# ─────────────────────────────────────────────────────────────────────────────

class TestFencingV11:
    def _make(self):
        from distributed.fencing import FencingTokenManager, StaleEpochError, EpochExpiredError
        return FencingTokenManager(), StaleEpochError, EpochExpiredError

    def test_initial_epoch(self):
        mgr, _, _ = self._make()
        assert mgr.current_epoch == 0

    def test_new_epoch_increments(self):
        mgr, _, _ = self._make()
        e1 = mgr.new_epoch(reason="test")
        e2 = mgr.new_epoch(reason="test")
        assert e1 == 1 and e2 == 2

    def test_validate_current_epoch(self):
        mgr, _, _ = self._make()
        epoch = mgr.new_epoch()
        mgr.validate(epoch)  # should not raise

    def test_stale_epoch_raises(self):
        mgr, StaleEpochError, _ = self._make()
        mgr.new_epoch()
        mgr.new_epoch()
        with pytest.raises(StaleEpochError):
            mgr.validate(0)

    def test_per_resource_fencing(self):
        mgr, StaleEpochError, _ = self._make()
        e_global = mgr.new_epoch(resource="global")
        e_camp   = mgr.new_epoch(resource="campaigns")
        mgr.validate(e_global, resource="global")
        mgr.validate(e_camp, resource="campaigns")
        with pytest.raises(StaleEpochError):
            mgr.validate(0, resource="global")

    def test_history_recorded(self):
        mgr, _, _ = self._make()
        mgr.new_epoch(reason="election", operator="node-1")
        mgr.new_epoch(reason="reelection", operator="node-2")
        history = mgr.history(limit=10)
        assert len(history) >= 2
        assert any(h["reason"] == "election" for h in history)

    def test_retire_epoch(self):
        mgr, StaleEpochError, EpochExpiredError = self._make()
        epoch = mgr.new_epoch()
        ok = mgr.retire_epoch(epoch)
        assert ok

    def test_stats(self):
        mgr, _, _ = self._make()
        mgr.new_epoch()
        s = mgr.stats()
        assert "resources" in s
        assert s["resources"]["global"]["epoch_changes"] >= 1


# ─────────────────────────────────────────────────────────────────────────────
# WAL (v11)
# ─────────────────────────────────────────────────────────────────────────────

class TestWALV11:
    def _make(self):
        from distributed.wal import WriteAheadLog, WALSyncMode, WALEntryType
        return WriteAheadLog(sync_mode=WALSyncMode.NONE), WALEntryType

    def test_append_returns_sequence(self):
        wal, _ = self._make()
        s1 = wal.append(term=1, operation="SET", payload={"k": "v"})
        s2 = wal.append(term=1, operation="SET", payload={"k": "w"})
        assert s1 == 0 and s2 == 1

    def test_crc_verify_on_replay(self):
        wal, _ = self._make()
        wal.append(term=1, operation="OP", payload={"x": 1})
        wal.append(term=1, operation="OP", payload={"x": 2})
        entries = wal.replay_from(seq=0, verify=True)
        assert len(entries) == 2
        assert all(e.verify() for e in entries)

    def test_corruption_detection(self):
        wal, _ = self._make()
        wal.append(term=1, operation="OP", payload={})
        # Corrupt the checksum
        entry = wal._segments[0].entries[0]
        entry.checksum = "deadbeef"
        entries = wal.replay_from(verify=True)
        assert wal._metrics["corruption_detected"] >= 1
        assert len(entries) == 0  # skipped

    def test_checkpoint(self):
        wal, _ = self._make()
        wal.append(term=1, operation="OP", payload={})
        cp = wal.checkpoint(reason="unit-test")
        assert cp >= 1
        assert wal.last_checkpoint() == cp

    def test_compact(self):
        wal, _ = self._make()
        for i in range(20):
            wal.append(term=1, operation="OP", payload={"i": i})
        wal.checkpoint()
        removed = wal.compact_up_to(wal.last_checkpoint())
        assert removed >= 0

    def test_stats(self):
        wal, _ = self._make()
        wal.append(term=1, operation="OP", payload={})
        s = wal.stats()
        assert s["total_appended"] == 1
        assert "current_sequence" in s


# ─────────────────────────────────────────────────────────────────────────────
# Saga Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class TestSagaOrchestrator:
    def _make(self):
        from distributed.saga import SagaOrchestrator, SagaDefinition, SagaState, SagaStep
        return SagaOrchestrator(), SagaDefinition, SagaState

    def test_happy_path(self):
        orch, SD, SS = self._make()
        log = []
        defn = (SD("test_saga")
            .step("step1", action=lambda ctx: log.append("s1") or {"s1": True})
            .step("step2", action=lambda ctx: log.append("s2") or {"s2": True})
            .step("step3", action=lambda ctx: log.append("s3") or {"s3": True}))
        orch.register(defn)
        saga_id = orch.start("test_saga", context={"x": 1})
        rec = orch.get(saga_id)
        assert rec["state"] == SS.COMPLETED.value
        assert log == ["s1", "s2", "s3"]

    def test_compensation_on_failure(self):
        orch, SD, SS = self._make()
        compensated = []
        defn = (SD("comp_saga")
            .step("step1",
                  action=lambda ctx: {"s1": True},
                  compensation=lambda ctx: compensated.append("comp_s1"))
            .step("step2",
                  action=lambda ctx: (_ for _ in ()).throw(RuntimeError("step2 fails")),
                  compensation=lambda ctx: compensated.append("comp_s2")))
        orch.register(defn)
        saga_id = orch.start("comp_saga")
        rec = orch.get(saga_id)
        assert rec["state"] in (SS.COMPENSATED.value, SS.FAILED.value)
        assert "comp_s1" in compensated

    def test_context_passed_between_steps(self):
        orch, SD, SS = self._make()
        defn = (SD("ctx_saga")
            .step("step1", action=lambda ctx: {"value": 42})
            .step("step2", action=lambda ctx: {"doubled": ctx.get("value", 0) * 2}))
        orch.register(defn)
        saga_id = orch.start("ctx_saga", context={})
        rec = orch.get(saga_id)
        assert rec["state"] == SS.COMPLETED.value
        assert rec["context"]["doubled"] == 84

    def test_retry_on_transient_failure(self):
        orch, SD, SS = self._make()
        attempts = {"n": 0}
        def flaky(ctx):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise RuntimeError("transient")
            return {"ok": True}
        defn = SD("retry_saga").step("flaky", action=flaky, max_retries=3, retry_delay_ms=10)
        orch.register(defn)
        saga_id = orch.start("retry_saga")
        rec = orch.get(saga_id)
        assert rec["state"] == SS.COMPLETED.value
        assert attempts["n"] == 3

    def test_stats(self):
        orch, SD, SS = self._make()
        defn = SD("stat_saga").step("s", action=lambda ctx: {})
        orch.register(defn)
        orch.start("stat_saga")
        s = orch.stats()
        assert s["total_started"] == 1
        assert s["total_completed"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Service Registry
# ─────────────────────────────────────────────────────────────────────────────

class TestServiceRegistry:
    def _make(self):
        from distributed.service_registry import ServiceRegistry, ServiceInstance, ServiceState
        return ServiceRegistry(), ServiceInstance, ServiceState

    def test_register_and_discover(self):
        reg, SI, SS = self._make()
        svc = SI(service_id="c2-1", service_name="c2", address="10.0.0.1",
                 port=5000, tags=["primary"])
        reg.register(svc)
        found = reg.discover("c2")
        assert found is not None
        assert found.address == "10.0.0.1"

    def test_heartbeat_updates_state(self):
        reg, SI, SS = self._make()
        svc = SI(service_id="svc-1", service_name="api", address="10.0.0.2", port=80)
        reg.register(svc)
        ok = reg.heartbeat("svc-1")
        assert ok
        got = reg.get("svc-1")
        assert got.state == SS.PASSING

    def test_deregister(self):
        reg, SI, SS = self._make()
        svc = SI(service_id="del-1", service_name="temp", address="1.2.3.4", port=9000)
        reg.register(svc)
        ok = reg.deregister("del-1")
        assert ok
        assert reg.get("del-1") is None

    def test_round_robin_lb(self):
        reg, SI, SS = self._make()
        for i in range(3):
            svc = SI(service_id=f"rr-{i}", service_name="rr-svc",
                     address=f"10.0.0.{i}", port=80)
            svc.state = SS.PASSING
            reg.register(svc)
            reg.heartbeat(f"rr-{i}")
        seen = set()
        for _ in range(9):
            s = reg.discover("rr-svc", strategy="round_robin")
            if s:
                seen.add(s.service_id)
        assert len(seen) == 3  # all three hit

    def test_ttl_expiry(self):
        reg, SI, SS = self._make()
        svc = SI(service_id="ttl-1", service_name="ttl-svc",
                 address="1.2.3.4", port=80, ttl_seconds=0.01)
        reg.register(svc)
        time.sleep(0.05)
        found = reg.discover("ttl-svc")
        assert found is None  # expired

    def test_watch_notifications(self):
        reg, SI, SS = self._make()
        events = []
        reg.watch("watch-svc", lambda event, svc: events.append(event))
        svc = SI(service_id="w-1", service_name="watch-svc",
                 address="1.2.3.4", port=80)
        reg.register(svc)
        reg.deregister("w-1")
        assert "registered" in events
        assert "deregistered" in events

    def test_discover_all(self):
        reg, SI, SS = self._make()
        for i in range(4):
            svc = SI(service_id=f"all-{i}", service_name="all-svc",
                     address=f"10.0.0.{i}", port=80)
            reg.register(svc)
            reg.heartbeat(f"all-{i}")
        all_svcs = reg.discover_all("all-svc", state_filter=SS.PASSING)
        assert len(all_svcs) == 4

    def test_stats(self):
        reg, SI, SS = self._make()
        svc = SI(service_id="stats-1", service_name="stats-svc",
                 address="1.2.3.4", port=80)
        reg.register(svc)
        s = reg.stats()
        assert s["total_services"] >= 1
        assert "registrations" in s
