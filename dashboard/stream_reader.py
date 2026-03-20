"""
dashboard/stream_reader.py

Dashboard data layer — reads from Redis Streams directly, not the C2 API.
The dashboard remains available during C2 restarts, leader elections,
and overload events.

Changes from previous version:
  - REDIS_NODE_KEY (which had a {} format placeholder) is no longer imported
    from broker — the correct auth record key pattern is constructed locally.
  - _get_node_last_seen() now queries aegis:node:beacon:{host_id}, which IS
    written by c2/app.py on every successful beacon (added there).
  - _ensure_consumer_group() creates consumer groups for ALL three streams
    the dashboard reads (TELEMETRY, ALERTS, RESULTS_PROCESSED) — not just one.
  - get_nodes() guards against self._redis being None (called before connect()).
  - live_events() yields a heartbeat dict rather than relying on Redis blocking
    returning None (which it does on timeout, not on "no messages").
  - REDIS_NODE_KEY removed; uses a local constant for the auth key pattern.
"""

import asyncio
import json
import logging
import time
from typing import AsyncIterator, List, Optional

import redis.asyncio as aioredis

from c2.task_queue.broker import (
    STREAM_TELEMETRY,
    STREAM_ALERTS,
    STREAM_RESULTS_PROCESSED,
    GROUP_TELEMETRY,
)

log = logging.getLogger("dashboard.stream")

# Auth record key pattern — matches what c2/auth/mtls.py writes.
AUTH_NODE_KEY_PATTERN = "aegis:auth:node:*"
AUTH_NODE_KEY_PREFIX  = "aegis:auth:node:"

# Last beacon timestamp — written by c2/app.py on every successful beacon.
NODE_LAST_BEACON_PREFIX = "aegis:node:beacon:"

CACHE_NODE_LIST = "aegis:dashboard:nodes"
CACHE_STATS     = "aegis:dashboard:stats"
CACHE_TTL       = 30  # seconds

# Consumer groups the dashboard participates in
_DASHBOARD_GROUPS = [
    (STREAM_TELEMETRY,        GROUP_TELEMETRY),
    (STREAM_ALERTS,           "dashboard-alert-consumers"),
    (STREAM_RESULTS_PROCESSED, "dashboard-result-consumers"),
]


class DashboardStreamReader:
    """
    Dashboard data layer.  All reads are from Redis Streams and cached
    aggregates — no calls to the C2 Flask application.
    """

    def __init__(self, redis_url: str) -> None:
        self._redis_url   = redis_url
        self._redis: Optional[aioredis.Redis] = None
        self._consumer_id = f"dashboard-{int(time.time())}"

    async def connect(self) -> None:
        self._redis = await aioredis.from_url(
            self._redis_url, decode_responses=True
        )
        await self._ensure_consumer_groups()
        log.info(f"DashboardStreamReader connected ({self._consumer_id})")

    async def close(self) -> None:
        if self._redis:
            await self._redis.aclose()

    async def __aenter__(self) -> "DashboardStreamReader":
        await self.connect()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    def _require_redis(self) -> aioredis.Redis:
        if self._redis is None:
            raise RuntimeError("DashboardStreamReader: connect() not called")
        return self._redis

    # ── Live event stream ─────────────────────────────────────────────────────

    async def live_events(self, since: str = "$") -> AsyncIterator[dict]:
        """
        Async generator of live telemetry and alert events.
        Suitable for an SSE endpoint — yields a heartbeat every ~1s when idle.
        """
        redis = self._require_redis()
        last_ids = {STREAM_TELEMETRY: since, STREAM_ALERTS: since}

        while True:
            try:
                # block=1000ms; returns empty list on timeout (not None).
                entries = await redis.xread(last_ids, count=50, block=1000)

                if not entries:
                    yield {"type": "heartbeat", "ts": time.time()}
                    continue

                for stream_bytes, messages in entries:
                    stream_name = stream_bytes if isinstance(stream_bytes, str) \
                                  else stream_bytes.decode()
                    for entry_id, data in messages:
                        last_ids[stream_name] = entry_id
                        yield {
                            "stream": stream_name,
                            "id":     entry_id,
                            "type":   data.get("event", data.get("severity", "event")),
                            "ts":     float(data.get("ts", time.time())),
                            "data":   data,
                        }

            except asyncio.CancelledError:
                return
            except Exception as exc:
                log.error(f"live_events error: {exc}")
                await asyncio.sleep(1)
                yield {"type": "error", "message": str(exc)}

    # ── Node listing ──────────────────────────────────────────────────────────

    async def get_nodes(self) -> List[dict]:
        """Return all known nodes, augmented with last-seen timestamps."""
        redis = self._require_redis()

        cached = await redis.get(CACHE_NODE_LIST)
        if cached:
            try:
                return json.loads(cached)
            except json.JSONDecodeError:
                pass  # stale / corrupt cache — rebuild

        nodes: List[dict] = []
        cursor = 0
        while True:
            cursor, keys = await redis.scan(
                cursor=cursor, match=AUTH_NODE_KEY_PATTERN, count=100
            )
            for k in keys:
                raw = await redis.get(k)
                if not raw:
                    continue
                try:
                    node = json.loads(raw)
                    host_id = node.get("host_id", "")
                    node["last_seen"] = await self._get_node_last_seen(host_id)
                    nodes.append(node)
                except (json.JSONDecodeError, KeyError):
                    pass
            if cursor == 0:
                break

        nodes.sort(key=lambda x: x.get("last_seen", 0), reverse=True)
        await redis.setex(CACHE_NODE_LIST, CACHE_TTL, json.dumps(nodes))
        return nodes

    async def _get_node_last_seen(self, host_id: str) -> float:
        """
        Read the last beacon timestamp for a node.
        Written by c2/app.py as:
            redis.setex(f"aegis:node:beacon:{host_id}", 86400, str(time.time()))
        """
        if not host_id:
            return 0.0
        redis = self._require_redis()
        raw   = await redis.get(f"{NODE_LAST_BEACON_PREFIX}{host_id}")
        try:
            return float(raw) if raw else 0.0
        except ValueError:
            return 0.0

    # ── Results ───────────────────────────────────────────────────────────────

    async def get_results(
        self,
        host_id: Optional[str] = None,
        limit:   int           = 100,
        since:   str           = "-",
    ) -> List[dict]:
        """Return processed results, optionally filtered by host_id."""
        redis   = self._require_redis()
        entries = await redis.xrevrange(STREAM_RESULTS_PROCESSED, count=limit)
        results = []
        for entry_id, data in entries:
            if host_id and data.get("host_id") != host_id:
                continue
            results.append({"id": entry_id, **data})
        return results

    # ── Stats ─────────────────────────────────────────────────────────────────

    async def get_stats(self) -> dict:
        """Return aggregate platform stats (cached 30s)."""
        redis  = self._require_redis()
        cached = await redis.get(CACHE_STATS)
        if cached:
            try:
                return json.loads(cached)
            except json.JSONDecodeError:
                pass

        pipe = redis.pipeline()
        pipe.xlen(STREAM_TELEMETRY)
        pipe.xlen(STREAM_ALERTS)
        pipe.xlen(STREAM_RESULTS_PROCESSED)
        tel_len, alert_len, result_len = await pipe.execute()

        nodes  = await self.get_nodes()
        cutoff = time.time() - 300  # active = seen within 5 minutes
        stats  = {
            "total_nodes":    len(nodes),
            "active_nodes":   sum(1 for n in nodes if n.get("last_seen", 0) > cutoff),
            "total_events":   tel_len,
            "active_alerts":  alert_len,
            "results_stored": result_len,
            "computed_at":    time.time(),
        }
        await redis.setex(CACHE_STATS, CACHE_TTL, json.dumps(stats))
        return stats

    # ── Alerts ────────────────────────────────────────────────────────────────

    async def get_alerts(self, limit: int = 50) -> List[dict]:
        redis   = self._require_redis()
        entries = await redis.xrevrange(STREAM_ALERTS, count=limit)
        acked   = await redis.smembers("aegis:alerts:acked")
        return [
            {"id": eid, "acked": eid in acked, **data}
            for eid, data in entries
        ]

    async def ack_alert(self, alert_id: str) -> bool:
        redis = self._require_redis()
        await redis.sadd("aegis:alerts:acked", alert_id)
        return True

    # ── Timeline ──────────────────────────────────────────────────────────────

    async def get_timeline(self, minutes: int = 60, limit: int = 200) -> List[dict]:
        """Return recent telemetry events for the activity timeline."""
        redis    = self._require_redis()
        cutoff   = time.time() - (minutes * 60)
        min_id   = f"{int(cutoff * 1000)}-0"
        entries  = await redis.xrange(STREAM_TELEMETRY, min=min_id, count=limit)
        return [{"id": eid, **data} for eid, data in entries]

    # ── Cluster status ────────────────────────────────────────────────────────

    async def get_cluster_status(self) -> dict:
        redis      = self._require_redis()
        cursor     = 0
        node_list  = []
        while True:
            cursor, keys = await redis.scan(
                cursor=cursor, match="aegis:cluster:node:*", count=100
            )
            for k in keys:
                raw = await redis.get(k)
                if raw:
                    try:
                        node_list.append(json.loads(raw))
                    except json.JSONDecodeError:
                        pass
            if cursor == 0:
                break

        leader_raw = await redis.get("aegis:cluster:leader")
        leader     = None
        if leader_raw:
            try:
                leader = json.loads(leader_raw)
            except json.JSONDecodeError:
                pass

        return {
            "cluster_size": len(node_list),
            "nodes":        node_list,
            "leader":       leader,
            "healthy":      leader is not None,
        }

    # ── Setup ─────────────────────────────────────────────────────────────────

    async def _ensure_consumer_groups(self) -> None:
        """Create consumer groups for all streams the dashboard reads."""
        redis = self._require_redis()
        for stream, group in _DASHBOARD_GROUPS:
            try:
                await redis.xgroup_create(stream, group, id="0", mkstream=True)
            except aioredis.ResponseError as exc:
                if "BUSYGROUP" not in str(exc):
                    raise
