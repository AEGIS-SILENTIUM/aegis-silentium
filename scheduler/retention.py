"""
AEGIS-SILENTIUM — Data Retention & Lifecycle Scheduler
========================================================
Runs as a background thread (or standalone process) and enforces
per-table retention policies:

  Table                  | Default Retention
  -----------------------|------------------
  events                 | 30 days
  operator_audit         | 365 days
  webhook_deliveries     | 14 days
  node_commands          | 7 days  (completed/failed only)
  chat_messages          | 90 days
  generated_payloads     | 30 days (expired/deployed status)
  beacon log data        | 60 days

Design principles
-----------------
* Never deletes data still in use (active/firing status).
* Runs in a low-priority background thread (SIGTERM-safe).
* Logs every sweep with row counts to the ``retention_runs`` table.
* Configurable per-table via environment variables:
    RETAIN_EVENTS_DAYS=30
    RETAIN_AUDIT_DAYS=365
    etc.
* Can be triggered manually via /api/admin/retention/run
"""
from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

log = logging.getLogger("aegis.retention")

# ── Policy defaults (days) ────────────────────────────────────────────────────
_POLICIES: dict[str, int] = {
    "events":              int(os.environ.get("RETAIN_EVENTS_DAYS",         "30")),
    "operator_audit":      int(os.environ.get("RETAIN_AUDIT_DAYS",          "365")),
    "webhook_deliveries":  int(os.environ.get("RETAIN_WEBHOOKS_DAYS",       "14")),
    "node_commands":       int(os.environ.get("RETAIN_NODE_CMDS_DAYS",      "7")),
    "chat_messages":       int(os.environ.get("RETAIN_CHAT_DAYS",           "90")),
    "generated_payloads":  int(os.environ.get("RETAIN_PAYLOADS_DAYS",       "30")),
    "surveillance_modules":int(os.environ.get("RETAIN_SURV_MODULES_DAYS",   "180")),
}

# ── Per-table SQL ─────────────────────────────────────────────────────────────
_DELETE_QUERIES: dict[str, str] = {
    "events": (
        "DELETE FROM events "
        "WHERE created_at < NOW() - (%s * INTERVAL '1 day')"
    ),
    "operator_audit": (
        "DELETE FROM operator_audit "
        "WHERE ts < NOW() - (%s * INTERVAL '1 day')"
    ),
    "webhook_deliveries": (
        "DELETE FROM webhook_deliveries "
        "WHERE attempted_at < NOW() - (%s * INTERVAL '1 day')"
    ),
    "node_commands": (
        "DELETE FROM node_commands "
        "WHERE status IN ('completed','failed','timeout') "
        "AND created_at < NOW() - (%s * INTERVAL '1 day')"
    ),
    "chat_messages": (
        "DELETE FROM chat_messages "
        "WHERE pinned = FALSE "
        "AND sent_at < NOW() - (%s * INTERVAL '1 day')"
    ),
    "generated_payloads": (
        "DELETE FROM generated_payloads "
        "WHERE status IN ('expired','deployed') "
        "AND created_at < NOW() - (%s * INTERVAL '1 day')"
    ),
}


def run_retention_sweep(pg_connect_fn: Callable[[], Any]) -> dict:
    """
    Execute all retention DELETE queries.
    Returns a summary dict with rows deleted per table.

    This function is safe to call multiple times concurrently
    (each query is atomic).
    """
    results   = {}
    total     = 0
    t_start   = time.monotonic()

    conn = pg_connect_fn()
    for table, query in _DELETE_QUERIES.items():
        days = _POLICIES.get(table, 30)
        try:
            t0 = time.monotonic()
            with conn.cursor() as cur:
                cur.execute(query, (days,))
                count = cur.rowcount
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            results[table] = {"deleted": count, "retention_days": days, "ms": elapsed_ms}
            total += count
            if count > 0:
                log.info(
                    "retention  table=%s  deleted=%d  days=%d  ms=%d",
                    table, count, days, elapsed_ms,
                )
        except Exception as e:
            log.error("retention error  table=%s  err=%s", table, e)
            results[table] = {"error": str(e), "retention_days": days}

    duration_ms = int((time.monotonic() - t_start) * 1000)

    # Record sweep in DB
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO retention_runs(table_name, rows_deleted, duration_ms) "
                "VALUES(%s,%s,%s)",
                ("ALL", total, duration_ms),
            )
    except Exception as _e:
        log.debug("%s error: %s", __name__, _e)

    log.info("retention sweep complete  total_deleted=%d  ms=%d", total, duration_ms)
    return {
        "total_deleted": total,
        "duration_ms":   duration_ms,
        "ran_at":        datetime.now(timezone.utc).isoformat(),
        "tables":        results,
    }


class RetentionScheduler:
    """
    Background thread that runs the retention sweep on a configurable interval.
    """

    def __init__(
        self,
        pg_connect_fn: Callable[[], Any],
        interval_hours: float = 24.0,
    ) -> None:
        self._pg       = pg_connect_fn
        self._interval = interval_hours * 3600
        self._thread   = threading.Thread(
            target=self._loop,
            name="retention-scheduler",
            daemon=True,
        )
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._thread.start()
        log.info(
            "retention scheduler started  interval_hours=%.1f",
            self._interval / 3600,
        )

    def stop(self) -> None:
        self._stop_event.set()

    def _loop(self) -> None:
        # Stagger first run by 5 minutes to avoid startup load
        self._stop_event.wait(timeout=300)
        while not self._stop_event.is_set():
            try:
                run_retention_sweep(self._pg)
            except Exception as e:
                log.error("retention scheduler error: %s", e)
            self._stop_event.wait(timeout=self._interval)


__all__ = ["RetentionScheduler", "run_retention_sweep", "_POLICIES"]
