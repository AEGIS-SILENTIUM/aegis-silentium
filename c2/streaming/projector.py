"""
c2/streaming/projector.py
AEGIS-SILENTIUM v12 — Event Projector (Materialized Views)

Consumes the event log and maintains live read models (projections).
Each projection is a reduced in-memory view kept consistent by
replaying committed events in order.

Design
------
  • CQRS: writes go to EventLog, reads come from ProjectionViews
  • Projections are rebuilt on startup from the full event log
  • Async consumer threads advance each projection independently
  • Projections expose a query() method for fast O(1) reads

Built-in projections
--------------------
  NodeStatusView        — live node health map
  CampaignSummaryView   — campaign stats aggregated from events
  AlertCounterView      — per-severity alert counters
  ExfilVolumeView       — exfiltrated bytes per node per day
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .event_log import EventLog, EventLogReader, EventRecord

log = logging.getLogger("aegis.streaming.projector")


@dataclass
class ProjectionView:
    """A single named read model."""
    name:        str
    handler:     Callable[[dict, EventRecord], dict]   # (state, event) → new_state
    initial:     Callable[[], dict]                    = field(default=dict)
    description: str                                   = ""
    # Runtime fields
    _state:      dict = field(default_factory=dict, init=False, repr=False)
    _events_processed: int = field(default=0, init=False)
    _last_offset: int      = field(default=-1, init=False)
    _lock:       threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False
    )

    def __post_init__(self) -> None:
        self._state = self.initial()

    def apply(self, event: EventRecord) -> None:
        with self._lock:
            try:
                self._state = self.handler(self._state, event)
                self._events_processed += 1
                self._last_offset = event.offset
            except Exception as e:
                log.warning("Projection %s error at offset %d: %s",
                            self.name, event.offset, e)

    def query(self, key: Optional[str] = None) -> Any:
        with self._lock:
            if key:
                return self._state.get(key)
            return dict(self._state)

    def stats(self) -> dict:
        return {
            "name":              self.name,
            "events_processed":  self._events_processed,
            "last_offset":       self._last_offset,
            "state_keys":        list(self._state.keys()) if isinstance(self._state, dict) else [],
        }


class EventProjector:
    """
    Drives multiple ProjectionViews by consuming the EventLog.

    Usage::

        projector = EventProjector(event_log)
        projector.register_view(NodeStatusView)
        projector.start()

        # Later:
        nodes = projector.query("node_status")
    """

    def __init__(self, event_log: EventLog, poll_interval: float = 0.2) -> None:
        self._log           = event_log
        self._poll_interval = poll_interval
        self._views:    Dict[str, ProjectionView]    = {}
        self._readers:  Dict[str, EventLogReader]    = {}
        self._topics:   Dict[str, List[str]]         = {}   # topic → [view_name]
        self._running   = False
        self._lock      = threading.RLock()

    def register_view(self, view: ProjectionView, topics: List[str]) -> None:
        """Register a projection view to be updated on events from given topics."""
        with self._lock:
            self._views[view.name] = view
            for topic in topics:
                self._topics.setdefault(topic, []).append(view.name)
            if topics:
                reader_topic = topics[0] if len(topics) == 1 else "__all__"
                if reader_topic not in self._readers:
                    self._readers[reader_topic] = self._log.get_reader(
                        f"projector:{reader_topic}", reader_topic, start_offset=0
                    )

    def register_view_all_topics(self, view: ProjectionView) -> None:
        """Register a view that receives events from all topics."""
        with self._lock:
            self._views[view.name] = view
            self._topics.setdefault("__all__", []).append(view.name)
            if "__all__" not in self._readers:
                self._readers["__all__"] = self._log.get_reader(
                    "projector:__all__", "__all__", start_offset=0
                )

    def start(self) -> None:
        self._running = True
        t = threading.Thread(target=self._run, daemon=True, name="projector")
        t.start()
        log.info("EventProjector started with %d views", len(self._views))

    def stop(self) -> None:
        self._running = False

    def _run(self) -> None:
        while self._running:
            try:
                self._tick()
            except Exception:
                log.exception("Projector tick error")
            time.sleep(self._poll_interval)

    def _tick(self) -> None:
        # Poll per-topic readers
        with self._lock:
            readers = dict(self._readers)
            topics  = dict(self._topics)

        for reader_key, reader in readers.items():
            if reader_key == "__all__":
                records = self._log.read_all_topics(
                    start_offset=reader.current_offset(), max_records=500
                )
                if records:
                    self._log.commit_offset(
                        f"projector:__all__", "__all__", records[-1].offset
                    )
            else:
                records = reader.poll(max_records=500)

            for record in records:
                # Dispatch to views subscribed to this topic and to __all__
                view_names = set(topics.get(record.topic, []) + topics.get("__all__", []))
                for vname in view_names:
                    with self._lock:
                        view = self._views.get(vname)
                    if view:
                        view.apply(record)

    def query(self, view_name: str, key: Optional[str] = None) -> Any:
        with self._lock:
            view = self._views.get(view_name)
        if not view:
            return None
        return view.query(key)

    def stats(self) -> dict:
        with self._lock:
            return {
                "views": [v.stats() for v in self._views.values()],
                "topics": list(self._topics.keys()),
            }

    def rebuild(self, view_name: str) -> bool:
        """Replay the entire log to rebuild a view from scratch."""
        with self._lock:
            view = self._views.get(view_name)
        if not view:
            return False
        view._state = view.initial()
        view._events_processed = 0
        view._last_offset = -1
        all_records = self._log.read_all_topics(start_offset=0, max_records=100_000)
        for record in all_records:
            view.apply(record)
        log.info("Rebuilt projection %s (%d events)", view_name, view._events_processed)
        return True


# ── Built-in projection factories ─────────────────────────────────────────────

def make_node_status_view() -> ProjectionView:
    """Live map of node_id → status."""
    def handler(state: dict, event: EventRecord) -> dict:
        p = event.payload or {}
        node_id = p.get("node_id") or p.get("node")
        if not node_id:
            return state
        if event.event_type == "node.connected":
            state[node_id] = {**state.get(node_id, {}),
                              "status": "alive", "last_seen": event.timestamp,
                              "ip": p.get("ip", ""), "node_id": node_id}
        elif event.event_type == "node.heartbeat":
            if node_id in state:
                state[node_id]["last_seen"] = event.timestamp
                state[node_id]["status"] = "alive"
        elif event.event_type in ("node.dead", "node.killed"):
            if node_id in state:
                state[node_id]["status"] = "dead"
        elif event.event_type == "node.registered":
            state[node_id] = {**state.get(node_id, {}),
                              "status": "alive", "last_seen": event.timestamp,
                              "hostname": p.get("hostname", ""), "node_id": node_id}
        return state

    return ProjectionView(name="node_status", handler=handler,
                         description="Live node status map")


def make_campaign_summary_view() -> ProjectionView:
    """Per-campaign aggregated stats."""
    def handler(state: dict, event: EventRecord) -> dict:
        p = event.payload or {}
        cid = p.get("campaign_id")
        if not cid:
            return state
        s = state.setdefault(cid, {
            "campaign_id": cid, "task_count": 0, "node_count": 0,
            "exfil_bytes": 0, "created_at": event.timestamp
        })
        if event.event_type == "task.created":
            s["task_count"] += 1
        elif event.event_type == "node.registered":
            s["node_count"] += 1
        elif event.event_type == "exfil.received":
            s["exfil_bytes"] += p.get("size_bytes", 0)
        s["last_activity"] = event.timestamp
        return state

    return ProjectionView(name="campaign_summary", handler=handler,
                         description="Campaign aggregated stats")


def make_alert_counter_view() -> ProjectionView:
    """Count of alerts by severity."""
    def handler(state: dict, event: EventRecord) -> dict:
        if event.event_type != "alert":
            return state
        severity = (event.payload or {}).get("severity", "info")
        state[severity] = state.get(severity, 0) + 1
        state["total"]  = state.get("total", 0) + 1
        return state

    return ProjectionView(name="alert_counters", handler=handler,
                         initial=lambda: {"critical": 0, "high": 0, "medium": 0,
                                          "low": 0, "info": 0, "total": 0},
                         description="Alert counts by severity")
