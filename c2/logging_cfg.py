"""
AEGIS — Structured Logging
============================
Every log line is JSON.  Every request carries a correlation ID.

Design
------
* JSON formatter outputs a single-line JSON object per record with
  consistent fields: ts, level, logger, message, request_id, plus any
  extra fields passed as keyword args to the logger.
* Request IDs propagate via Python's ``threading.local`` so that any log
  call made anywhere during a request — including inside manager methods
  and background tasks — automatically includes the request ID without
  any extra plumbing.
* Flask ``before_request`` / ``after_request`` hooks set and clear the
  local automatically.
* A ``request_id`` filter attached to all handlers injects the value.

Usage
-----
    # In any module:
    import logging
    log = logging.getLogger("aegis.mymodule")
    log.info("Something happened", extra={"node_id": nid, "count": 4})

    # Output:
    # {"ts":"2026-01-01T00:00:00.123Z","level":"INFO","logger":"aegis.mymodule",
    #  "message":"Something happened","request_id":"a1b2c3d4",
    #  "node_id":"abc123","count":4}
"""
from __future__ import annotations

import json
import logging
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Optional

# ── Thread-local request ID ───────────────────────────────────────────────────

_ctx = threading.local()


def set_request_id(rid: str) -> None:
    _ctx.request_id = rid


def get_request_id() -> str:
    return getattr(_ctx, "request_id", "-")


def new_request_id() -> str:
    return uuid.uuid4().hex[:12]


def clear_request_id() -> None:
    _ctx.request_id = "-"


# ── JSON formatter ────────────────────────────────────────────────────────────

_RESERVED = frozenset({
    "args", "created", "exc_info", "exc_text", "filename", "funcName",
    "levelname", "levelno", "lineno", "message", "module", "msecs",
    "msg", "name", "pathname", "process", "processName", "relativeCreated",
    "stack_info", "thread", "threadName",
})


class JsonFormatter(logging.Formatter):
    """
    Emit one JSON object per log record on a single line.

    Standard fields always present:
      ts          — ISO-8601 UTC timestamp with milliseconds
      level       — INFO / WARNING / ERROR / CRITICAL / DEBUG
      logger      — logger hierarchy (e.g. "aegis.listeners")
      message     — formatted log message
      request_id  — correlation ID from thread-local
    Optional fields:
      error       — exception class + message (on exc_info)
      traceback   — full traceback lines (on exc_info, DEBUG level only)
    Extra fields passed via ``extra={}`` are merged in at top level.
    """

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()

        obj: dict = {
            "ts":         datetime.fromtimestamp(record.created, tz=timezone.utc)
                          .isoformat(timespec="milliseconds"),
            "level":      record.levelname,
            "logger":     record.name,
            "message":    record.message,
            "request_id": get_request_id(),
        }

        # Merge extra fields (skip internal logging attrs)
        for k, v in record.__dict__.items():
            if k not in _RESERVED and not k.startswith("_"):
                obj[k] = v

        # Exception info
        if record.exc_info:
            exc_type, exc_val, tb = record.exc_info
            obj["error"] = f"{exc_type.__name__}: {exc_val}"
            if record.levelno <= logging.DEBUG:
                obj["traceback"] = traceback.format_exception(
                    exc_type, exc_val, tb
                )

        try:
            return json.dumps(obj, default=str)
        except Exception:
            return json.dumps({"level": "ERROR",
                               "message": "log serialisation failed",
                               "raw": str(record.getMessage())})


# ── Request ID filter ─────────────────────────────────────────────────────────

class RequestIdFilter(logging.Filter):
    """Injects request_id into every LogRecord (used for non-JSON formatters)."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id()
        return True


# ── Setup ─────────────────────────────────────────────────────────────────────

def configure(level: str = "INFO") -> None:
    """
    Replace the root logger's handlers with a single JSON stdout handler.
    Call once at startup, before importing Flask routes.
    """
    import sys

    root = logging.getLogger()
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RequestIdFilter())
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Suppress noisy third-party loggers
    for noisy in ("werkzeug", "urllib3", "psycopg2"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logging.getLogger("aegis").info(
        "Structured JSON logging configured",
        extra={"log_level": level},
    )


# ── Flask integration ─────────────────────────────────────────────────────────

def init_app(app) -> None:
    """
    Register before/after request hooks on a Flask app to:
      1. Generate or propagate a request ID from X-Request-ID header.
      2. Inject request_id into all log calls during this request.
      3. Log request start/finish with timing and status code.
    """
    _log = logging.getLogger("aegis.request")

    @app.before_request
    def _before():
        from flask import request, g
        rid = (request.headers.get("X-Request-ID")
               or request.headers.get("X-Correlation-ID")
               or new_request_id())
        set_request_id(rid)
        g._req_start = time.monotonic()
        g._request_id = rid

    @app.after_request
    def _after(response):
        from flask import request, g
        duration_ms = round((time.monotonic() - getattr(g, "_req_start", 0)) * 1000, 1)
        rid         = getattr(g, "_request_id", get_request_id())
        response.headers["X-Request-ID"] = rid
        _log.info(
            "%s %s → %d (%.1fms)",
            request.method, request.path, response.status_code, duration_ms,
            extra={
                "method":      request.method,
                "path":        request.path,
                "status":      response.status_code,
                "duration_ms": duration_ms,
                "ip":          request.remote_addr,
            },
        )
        return response

    @app.teardown_request
    def _teardown(_exc):
        clear_request_id()


__all__ = [
    "configure", "init_app",
    "set_request_id", "get_request_id", "new_request_id", "clear_request_id",
    "JsonFormatter", "RequestIdFilter",
]
