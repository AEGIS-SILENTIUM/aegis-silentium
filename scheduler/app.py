import logging
log = logging.getLogger(__name__)
#!/usr/bin/env python3
"""
AEGIS-Advanced Scheduler v4
==============================
Campaign lifecycle management, intelligent task scheduling,
stale-task recovery, dead-node rebalancing, priority queue,
periodic rescanning, target deduplication, rate-limiting
of scan launches, and metric publishing to Redis.
"""
import os, time, json, uuid, threading, signal, sys
from datetime import datetime, timezone
from typing import List, Dict, Optional
import redis, psycopg2
from psycopg2.extras import RealDictCursor
import threading as _threading, random as _random

class _CircuitBreaker:
    """Opens after failure_threshold consecutive failures; resets after reset_timeout seconds."""
    def __init__(self, name, failure_threshold=3, reset_timeout=30.0):
        self.name=name; self._threshold=failure_threshold; self._reset=reset_timeout
        self._fails=0; self._state="closed"; self._opened=0.0; self._lock=_threading.Lock()
    def ok(self):
        with self._lock:
            if self._state=="closed": return True
            if self._state=="open":
                if time.time()-self._opened>=self._reset:
                    self._state="half_open"; log.info("CB[%s] half-open",self.name); return True
                return False
            return True
    def success(self):
        with self._lock: self._fails=0; self._state="closed"
    def failure(self):
        with self._lock:
            self._fails+=1
            if self._fails>=self._threshold:
                if self._state!="open": log.warning("CB[%s] OPEN after %d failures",self.name,self._fails)
                self._state="open"; self._opened=time.time()

_pg_cb = _CircuitBreaker("postgres"); _redis_cb = _CircuitBreaker("redis")

def _with_backoff(fn, label="", retries=3, base=1.0, cap=30.0):
    """Exponential backoff retry wrapper. Returns (result, ok)."""
    delay = base
    for i in range(1, retries+1):
        try:
            r = fn(); return r, True
        except Exception as e:
            if i==retries: log.error("%s: %d retries exhausted: %s",label,retries,e); return None,False
            jitter = delay*0.1*(_random.random()-0.5)
            wait = min(cap, delay+jitter)
            log.warning("%s: attempt %d/%d failed (%s) retry in %.1fs",label,i,retries,e,wait)
            time.sleep(wait); delay=min(cap,delay*2)



# ── Configuration ────────────────────────────────────────────────────────
REDIS_HOST     = os.environ.get("REDIS_HOST", "redis")
REDIS_PASS     = os.environ.get("REDIS_PASSWORD", "")
PG_HOST        = os.environ.get("POSTGRES_HOST", "postgres")
PG_DB          = os.environ.get("POSTGRES_DB", "aegis")
PG_USER        = os.environ.get("POSTGRES_USER", "aegis")
PG_PASS        = os.environ.get("POSTGRES_PASSWORD", "")

RESCAN_HOURS   = int(os.environ.get("RESCAN_INTERVAL_HOURS", "24"))
STALE_MINUTES  = int(os.environ.get("STALE_TASK_TIMEOUT_MIN", "30"))
DEAD_MINUTES   = int(os.environ.get("DEAD_NODE_MINUTES", "10"))
CYCLE_SECONDS  = int(os.environ.get("SCHEDULER_CYCLE_SECONDS", "60"))
MAX_PENDING    = int(os.environ.get("MAX_PENDING_TASKS", "5000"))
MAX_RATE_PER_H = int(os.environ.get("MAX_TASKS_PER_HOUR", "500"))

# ── Redis ────────────────────────────────────────────────────────────────
_rkw = dict(host=REDIS_HOST, port=6379, db=0, decode_responses=True)
if REDIS_PASS: _rkw["password"] = REDIS_PASS
R = redis.Redis(**_rkw)

# ── PostgreSQL ───────────────────────────────────────────────────────────
def _pg() -> psycopg2.extensions.connection:
    conn = psycopg2.connect(
        host=PG_HOST, database=PG_DB, user=PG_USER, password=PG_PASS,
        connect_timeout=5)
    conn.autocommit = True
    return conn


def _log(msg: str, level: str = "info"):
    _lvl = getattr(logging, level.upper(), logging.INFO)
    log.log(_lvl, "[scheduler] %s", msg)
    try:
        ev = {"kind": "scheduler", "severity": level, "message": msg,
              "ts": datetime.now(timezone.utc).isoformat()}
        R.publish("aegis_events", json.dumps(ev))
    except Exception as _e:
        log.debug("%s error: %s", __name__, _e)


# ══════════════════════════════════════════════
# Stale task recovery
# ══════════════════════════════════════════════

def recover_stale_tasks():
    """
    Reset tasks stuck in 'running' state for > STALE_MINUTES.
    Re-queues them with incremented priority for faster pickup.
    """
    recovered = 0
    try:
        conn = _pg()
        with conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("""
                SELECT id, task_uuid, target, priority, campaign_id
                FROM tasks
                WHERE status='running'
                  AND started_at < NOW() - INTERVAL '{} minutes'
            """.format(STALE_MINUTES))
            stale = c.fetchall()
            for row in stale:
                c.execute("""
                    UPDATE tasks
                    SET status='pending', assigned_to=NULL, started_at=NULL,
                        priority=%s
                    WHERE id=%s
                """, (min(row["priority"] + 1, 9), row["id"]))
                R.rpush("task_queue", json.dumps({
                    "task_uuid": row["task_uuid"],
                    "target":    row["target"],
                    "priority":  row["priority"] + 1,
                }))
                recovered += 1
        conn.close()
    except Exception as e:
        _log("recover_stale_tasks error: {}".format(e), "high")

    if recovered:
        _log("Recovered {} stale tasks".format(recovered), "high")
    return recovered


# ══════════════════════════════════════════════
# Dead node detection & task rebalancing
# ══════════════════════════════════════════════

def handle_dead_nodes():
    """
    Mark nodes as 'dead' if not seen in DEAD_MINUTES.
    Requeue any tasks assigned to dead nodes.
    """
    dead_count = 0
    reassigned = 0
    try:
        conn = _pg()
        with conn.cursor(cursor_factory=RealDictCursor) as c:
            # Find newly dead nodes
            c.execute("""
                UPDATE nodes SET status='dead'
                WHERE status='active'
                  AND last_seen < NOW() - INTERVAL '{} minutes'
                RETURNING node_id
            """.format(DEAD_MINUTES))
            dead_nodes = [r["node_id"] for r in c.fetchall()]
            dead_count = len(dead_nodes)

            # Requeue their tasks
            for node_id in dead_nodes:
                c.execute("""
                    SELECT id, task_uuid, target, priority FROM tasks
                    WHERE assigned_to=%s AND status='running'
                """, (node_id,))
                for row in c.fetchall():
                    c.execute("""
                        UPDATE tasks
                        SET status='pending', assigned_to=NULL, started_at=NULL
                        WHERE id=%s
                    """, (row["id"],))
                    R.rpush("task_queue", json.dumps({
                        "task_uuid": row["task_uuid"],
                        "target":    row["target"],
                    }))
                    reassigned += 1
        conn.close()
    except Exception as e:
        _log("handle_dead_nodes error: {}".format(e), "high")

    if dead_count:
        _log("{} nodes marked dead, {} tasks requeued".format(
            dead_count, reassigned), "high")
    return dead_count, reassigned


# ══════════════════════════════════════════════
# Periodic rescanning
# ══════════════════════════════════════════════

def schedule_rescans():
    """
    Re-queue completed tasks whose targets haven't been scanned
    in RESCAN_HOURS hours. Uses lower priority (1) to avoid
    starving new scans.
    """
    scheduled = 0
    try:
        conn = _pg()
        with conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("""
                SELECT DISTINCT ON (t.target)
                    t.target, t.campaign_id, t.completed_at
                FROM tasks t
                WHERE t.status = 'completed'
                  AND t.completed_at < NOW() - INTERVAL '{hours} hours'
                  AND NOT EXISTS (
                      SELECT 1 FROM tasks t2
                      WHERE t2.target = t.target
                        AND t2.status IN ('pending','running','assigned')
                  )
                ORDER BY t.target, t.completed_at ASC
                LIMIT 100
            """.format(hours=RESCAN_HOURS))
            targets = c.fetchall()

            for row in targets:
                tuuid = str(uuid.uuid4())
                c.execute("""
                    INSERT INTO tasks(task_uuid, campaign_id, target, priority)
                    VALUES(%s, %s, %s, %s)
                """, (tuuid, row["campaign_id"], row["target"], 1))
                R.rpush("task_queue", json.dumps({
                    "task_uuid": tuuid,
                    "target":    row["target"],
                    "priority":  1,
                }))
                scheduled += 1

        conn.close()
    except Exception as e:
        _log("schedule_rescans error: {}".format(e), "high")

    if scheduled:
        _log("Scheduled {} periodic rescans".format(scheduled))
    return scheduled


# ══════════════════════════════════════════════
# Priority queue repair
# ══════════════════════════════════════════════

def sync_redis_queue():
    """
    Ensure Redis task_queue is in sync with DB pending tasks.
    Adds any pending tasks not in Redis.
    """
    try:
        # Get all UUIDs currently in queue
        queue_len = R.llen("task_queue")
        if queue_len > MAX_PENDING:
            _log("Task queue at capacity ({})".format(queue_len), "high")
            return

        conn = _pg()
        with conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("""
                SELECT task_uuid, target, priority
                FROM tasks
                WHERE status='pending'
                  AND (assigned_to IS NULL OR assigned_to='')
                ORDER BY priority DESC, created_at ASC
                LIMIT 100
            """)
            pending = c.fetchall()
        conn.close()

        # Get existing queue items
        queue_raw = R.lrange("task_queue", 0, -1)
        in_queue  = set()
        for item in queue_raw:
            try:
                in_queue.add(json.loads(item).get("task_uuid", ""))
            except Exception as _e:
                log.debug("%s error: %s", __name__, _e)

        added = 0
        for row in pending:
            if row["task_uuid"] not in in_queue:
                R.rpush("task_queue", json.dumps({
                    "task_uuid": row["task_uuid"],
                    "target":    row["target"],
                    "priority":  row["priority"],
                }))
                added += 1

        if added:
            _log("Synced {} pending tasks to Redis queue".format(added))

    except Exception as e:
        _log("sync_redis_queue error: {}".format(e))


# ══════════════════════════════════════════════
# Rate limiting — prevent scan flood
# ══════════════════════════════════════════════

def enforce_rate_limit():
    """
    If tasks are being launched too fast, pause new launches.
    Stores launch count in Redis with 1h TTL.
    """
    key   = "scheduler:launches:{}".format(
        datetime.now(timezone.utc).strftime("%Y%m%d%H"))
    count = int(R.get(key) or 0)
    if count >= MAX_RATE_PER_H:
        _log("Rate limit hit: {} tasks launched this hour".format(count), "high")
        return False
    return True


def record_launch():
    key = "scheduler:launches:{}".format(
        datetime.now(timezone.utc).strftime("%Y%m%d%H"))
    R.incr(key)
    R.expire(key, 3600)


# ══════════════════════════════════════════════
# Campaign lifecycle
# ══════════════════════════════════════════════

def update_campaign_status():
    """
    Auto-close campaigns where all tasks are complete/failed.
    """
    try:
        conn = _pg()
        with conn.cursor() as c:
            c.execute("""
                UPDATE campaigns SET status='closed'
                WHERE status='active'
                  AND id IN (
                      SELECT campaign_id FROM tasks
                      GROUP BY campaign_id
                      HAVING COUNT(*) > 0
                         AND SUM(CASE WHEN status IN ('pending','running') THEN 1 ELSE 0 END) = 0
                  )
                RETURNING id, name
            """)
            closed = c.fetchall()
            for cid, cname in (closed or []):
                _log("Campaign '{}' ({}) auto-closed — all tasks complete".format(
                    cname, cid))
        conn.close()
    except Exception as e:
        _log("update_campaign_status error: {}".format(e))


# ══════════════════════════════════════════════
# Metrics publishing
# ══════════════════════════════════════════════

def publish_metrics():
    """Publish scheduler metrics to Redis for dashboard consumption."""
    try:
        conn = _pg()
        with conn.cursor() as c:
            metrics = {}
            for status in ["pending", "running", "completed", "failed"]:
                c.execute("SELECT COUNT(*) FROM tasks WHERE status=%s", (status,))
                metrics["tasks_{}".format(status)] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM nodes WHERE status='active' AND last_seen > NOW()-INTERVAL '5 minutes'")
            metrics["active_nodes"] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM nodes WHERE status='dead'")
            metrics["dead_nodes"] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM vulnerabilities")
            metrics["total_vulns"] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity='critical'")
            metrics["critical_vulns"] = c.fetchone()[0]
            metrics["queue_depth"] = R.llen("task_queue")
            metrics["ts"] = datetime.now(timezone.utc).isoformat()
        conn.close()
        R.set("scheduler:metrics", json.dumps(metrics), ex=120)
        R.publish("aegis_events", json.dumps({
            "kind":     "metrics",
            "severity": "info",
            "message":  "metrics updated",
            **metrics,
        }))
    except Exception as e:
        _log("publish_metrics error: {}".format(e))


# ══════════════════════════════════════════════
# Target deduplication
# ══════════════════════════════════════════════

def deduplicate_pending():
    """Remove duplicate pending tasks for the same target."""
    removed = 0
    try:
        conn = _pg()
        with conn.cursor() as c:
            c.execute("""
                DELETE FROM tasks
                WHERE status='pending'
                  AND id NOT IN (
                      SELECT MIN(id) FROM tasks
                      WHERE status='pending'
                      GROUP BY target, campaign_id
                  )
                RETURNING id
            """)
            removed = len(c.fetchall() or [])
        conn.close()
    except Exception as e:
        _log("deduplicate_pending error: {}".format(e))
    if removed:
        _log("Removed {} duplicate pending tasks".format(removed))
    return removed


# ══════════════════════════════════════════════
# Cleanup old data
# ══════════════════════════════════════════════

def cleanup_old_events(days: int = 30):
    """Remove events older than N days."""
    try:
        conn = _pg()
        with conn.cursor() as c:
            c.execute("DELETE FROM events WHERE ts < NOW() - INTERVAL '{} days'".format(days))
            n = c.rowcount
        conn.close()
        if n: _log("Purged {} old events".format(n))
    except Exception as e:
        _log("cleanup_old_events error: {}".format(e))


def cleanup_old_results(days: int = 90):
    """Remove scan results older than N days (keeps summary)."""
    try:
        conn = _pg()
        with conn.cursor() as c:
            c.execute("""
                UPDATE tasks SET result=NULL, logs=''
                WHERE completed_at < NOW() - INTERVAL '{} days'
                  AND result IS NOT NULL
                RETURNING id
            """.format(days))
            n = len(c.fetchall() or [])
        conn.close()
        if n: _log("Pruned results from {} old tasks".format(n))
    except Exception as e:
        _log("cleanup_old_results error: {}".format(e))


# ══════════════════════════════════════════════
# Graceful shutdown
# ══════════════════════════════════════════════

_shutdown = threading.Event()

def _signal_handler(sig, frame):
    _log("Shutdown signal received", "high")
    _shutdown.set()

signal.signal(signal.SIGTERM, _signal_handler)
signal.signal(signal.SIGINT,  _signal_handler)


# ══════════════════════════════════════════════
# Main loop
# ══════════════════════════════════════════════

def main():
    _log("Scheduler started (cycle={}s, rescan={}h, stale={}m)".format(
        CYCLE_SECONDS, RESCAN_HOURS, STALE_MINUTES))

    cycle         = 0
    last_rescan   = 0
    last_cleanup  = 0
    last_dedup    = 0

    while not _shutdown.is_set():
        cycle_start = time.time()

        # Every cycle: stale tasks + dead nodes + sync queue + metrics
        recover_stale_tasks()
        handle_dead_nodes()
        sync_redis_queue()
        publish_metrics()
        update_campaign_status()

        # Every 10 cycles (~10 min): dedup
        if cycle % 10 == 0:
            deduplicate_pending()

        # Periodic rescans (every RESCAN_HOURS, in scheduler cycles)
        rescan_cycles = max(1, (RESCAN_HOURS * 3600) // CYCLE_SECONDS)
        if cycle % rescan_cycles == 0 and cycle > 0:
            schedule_rescans()

        # Daily cleanup (every 24h)
        cleanup_cycles = max(1, 86400 // CYCLE_SECONDS)
        if cycle % cleanup_cycles == 0 and cycle > 0:
            cleanup_old_events(30)
            cleanup_old_results(90)

        cycle += 1

        # Sleep remainder of cycle
        elapsed = time.time() - cycle_start
        sleep   = max(1, CYCLE_SECONDS - elapsed)
        _shutdown.wait(timeout=sleep)

    _log("Scheduler stopped cleanly")


if __name__ == "__main__":
    main()
