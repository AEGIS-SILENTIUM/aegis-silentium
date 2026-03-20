"""
AEGIS-SILENTIUM — Structured Logging
======================================
Configures the Python logging stack to emit newline-delimited JSON
(NDJSON) — the standard format for log aggregation pipelines.

Every log record is enriched with:
  - correlation_id  (propagated from request context via contextvars)
  - operator        (current session operator)
  - service         ("aegis-c2")
  - level, logger, message, timestamp (ISO-8601)
  - extra fields passed as kwargs to logger.info()/etc.

Usage
-----
    from c2.observability.logging import setup_logging, correlation_id

    setup_logging(level="INFO", json_output=True)

    # In a Flask before_request hook:
    correlation_id.set(request.headers.get("X-Correlation-ID", uuid4().hex))

    # Logs anywhere in the call stack:
    log = logging.getLogger("aegis.c2")
    log.info("node registered", extra={"node_id": "abc123", "ip": "10.0.0.1"})
    # → {"ts":"2026-01-01T00:00:00Z","level":"INFO","logger":"aegis.c2",
    #    "msg":"node registered","corr":"a1b2c3d4","node_id":"abc123","ip":"10.0.0.1"}
"""
from __future__ import annotations

import json
import logging
import sys
import traceback
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Optional

# Per-request context propagated automatically
correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
current_operator: ContextVar[str] = ContextVar("current_operator", default="")

_SERVICE = "aegis-c2"


class JSONFormatter(logging.Formatter):
    """
    Formats every log record as a single-line JSON object.
    Adds correlation_id, operator, and any ``extra`` fields.
    """

    LEVEL_MAP = {
        logging.DEBUG:    "DEBUG",
        logging.INFO:     "INFO",
        logging.WARNING:  "WARNING",
        logging.ERROR:    "ERROR",
        logging.CRITICAL: "CRITICAL",
    }

    def format(self, record: logging.LogRecord) -> str:
        obj: dict = {
            "ts":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level":   self.LEVEL_MAP.get(record.levelno, "INFO"),
            "logger":  record.name,
            "msg":     record.getMessage(),
            "service": _SERVICE,
        }

        corr = correlation_id.get("")
        op   = current_operator.get("")
        if corr: obj["corr"]     = corr
        if op:   obj["operator"] = op

        # Exception info
        if record.exc_info:
            obj["exception"] = "".join(traceback.format_exception(*record.exc_info))

        # Merge extra fields (skip stdlib internals)
        _skip = {
            "args", "created", "exc_info", "exc_text", "filename",
            "funcName", "levelname", "levelno", "lineno", "message",
            "module", "msecs", "msg", "name", "pathname", "process",
            "processName", "relativeCreated", "stack_info", "thread",
            "threadName", "taskName",
        }
        for k, v in record.__dict__.items():
            if k not in _skip and not k.startswith("_"):
                obj[k] = v

        return json.dumps(obj, default=str)


class HumanFormatter(logging.Formatter):
    """
    Coloured human-readable formatter for development / terminal use.
    """

    _COLOURS = {
        "DEBUG":    "\033[37m",
        "INFO":     "\033[36m",
        "WARNING":  "\033[33m",
        "ERROR":    "\033[31m",
        "CRITICAL": "\033[35m",
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        level  = record.levelname
        colour = self._COLOURS.get(level, "")
        corr   = correlation_id.get("")
        corr_s = f" [{corr[:8]}]" if corr else ""
        ts     = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        return (
            f"{colour}{ts}{self._RESET} "
            f"{colour}{level:<8}{self._RESET} "
            f"\033[90m{record.name}{corr_s}\033[0m  "
            f"{record.getMessage()}"
        )


def setup_logging(
    level: str = "INFO",
    json_output: bool = True,
    stream=None,
) -> None:
    """
    Configure root logger.  Call once at application startup.

    Parameters
    ----------
    level      — "DEBUG" | "INFO" | "WARNING" | "ERROR"
    json_output — True → NDJSON (production), False → coloured (dev)
    stream     — output stream (default sys.stdout)
    """
    root    = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove default handlers
    root.handlers.clear()

    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(
        JSONFormatter() if json_output else HumanFormatter()
    )
    root.addHandler(handler)

    # Suppress noisy third-party loggers
    for noisy in ("werkzeug", "urllib3.connectionpool", "psycopg2"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


__all__ = ["setup_logging", "JSONFormatter", "HumanFormatter",
           "correlation_id", "current_operator"]
