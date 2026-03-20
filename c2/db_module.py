"""
AEGIS — Database Connection Pool
==================================
Replaces the per-request ``_pg_connect()`` / Flask-``g`` pattern with a
proper ``ThreadedConnectionPool`` that is safe to use from:
  * Flask request handlers
  * Background threads (mesh listener, scheduler, managers)
  * The ``emit()`` event emitter

Design decisions
----------------
* ``ThreadedConnectionPool`` from psycopg2 is the correct primitive —
  it is thread-safe and reuses connections across requests.
* A ``CircuitBreaker`` wraps ``_pool.getconn()`` so that a database
  outage does not cause every request to block for the TCP timeout.
* Connections are validated before being returned to callers: if a
  connection is in a bad transaction state or broken, it is replaced.
* The ``db_conn()`` context manager is the single correct way to
  acquire a connection anywhere in the codebase.
* ``autocommit=True`` is retained (matching the existing code style);
  managers that need explicit transactions use BEGIN/SAVEPOINT.

Pool sizing
-----------
Min connections: 2  (always warm)
Max connections: 20 (configurable via DB_POOL_MAX env var)

These numbers are conservative — adjust for your deployment's
PostgreSQL ``max_connections`` setting (typically 100–500).
"""
from __future__ import annotations

import contextlib
import logging
import os
import time
import threading
from typing import Optional

import psycopg2
import psycopg2.pool
import psycopg2.extras
from psycopg2.extras import RealDictCursor

from circuit import CircuitBreaker, CircuitOpenError

log = logging.getLogger("aegis.db")

# ── Config ────────────────────────────────────────────────────────────────────

PG_HOST     = os.environ.get("POSTGRES_HOST",     "localhost")
PG_DB       = os.environ.get("POSTGRES_DB",       "aegis")
PG_USER     = os.environ.get("POSTGRES_USER",     "aegis")
PG_PASS     = os.environ.get("POSTGRES_PASSWORD", "")
PG_PORT     = int(os.environ.get("POSTGRES_PORT", "5432"))
POOL_MIN    = int(os.environ.get("DB_POOL_MIN",   "2"))
POOL_MAX    = int(os.environ.get("DB_POOL_MAX",   "20"))

_DSN = (
    f"host={PG_HOST} port={PG_PORT} dbname={PG_DB} "
    f"user={PG_USER} password={PG_PASS} "
    f"connect_timeout=5 options='-c statement_timeout=30000'"
    # statement_timeout=30s: a slow query will never block indefinitely
)

# ── Circuit breaker ────────────────────────────────────────────────────────────

_db_breaker = CircuitBreaker(
    "postgresql",
    failure_threshold = 3,
    reset_timeout     = 5.0,
    max_timeout       = 60.0,
    success_threshold = 2,
)

# ── Pool ──────────────────────────────────────────────────────────────────────

_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None
_pool_lock = threading.Lock()


def _make_pool() -> psycopg2.pool.ThreadedConnectionPool:
    return psycopg2.pool.ThreadedConnectionPool(POOL_MIN, POOL_MAX, dsn=_DSN)


def _get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None or _pool.closed:
        with _pool_lock:
            if _pool is None or _pool.closed:
                log.info("Initialising PostgreSQL connection pool (min=%d max=%d)",
                         POOL_MIN, POOL_MAX)
                _pool = _db_breaker.call(_make_pool)
    return _pool


def _is_conn_ok(conn) -> bool:
    """Return True if ``conn`` is usable."""
    if conn is None or conn.closed:
        return False
    # A connection stuck in a failed transaction must be rolled back
    if conn.status == psycopg2.extensions.STATUS_IN_TRANSACTION:
        try:
            conn.rollback()
        except Exception:
            return False
    return True


# ── Public API ────────────────────────────────────────────────────────────────

@contextlib.contextmanager
def db_conn(autocommit: bool = True):
    """
    Context manager that yields a validated psycopg2 connection from
    the pool.  On exit the connection is returned to the pool (or
    replaced if damaged).

    Usage::

        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")

    Thread-safe — safe to call from any thread.
    """
    pool = _get_pool()
    conn = None
    try:
        conn = _db_breaker.call(pool.getconn)
        if not _is_conn_ok(conn):
            # Connection is damaged — close it and get a fresh one
            try:
                pool.putconn(conn, close=True)
            except Exception as _exc:
                log.debug("unknown: %s", _exc)
            conn = _db_breaker.call(pool.getconn)
        conn.autocommit = autocommit
        yield conn
    except CircuitOpenError:
        log.error("DB circuit is OPEN — request rejected")
        raise
    except psycopg2.OperationalError as e:
        _db_breaker._record_failure()
        log.error("DB operational error: %s", e)
        raise
    finally:
        if conn is not None:
            try:
                if not conn.closed:
                    pool.putconn(conn)
            except Exception as e:
                log.warning("Pool putconn failed: %s", e)


def get_pg():
    """
    Compatibility shim — returns a connection from the pool.

    WARNING: The caller is responsible for calling ``pool.putconn(conn)``
    via the ``release_pg(conn)`` function when done.  Prefer the
    ``db_conn()`` context manager instead.

    This shim exists so that legacy code using ``get_pg()`` keeps working
    while being migrated to ``db_conn()``.
    """
    pool = _get_pool()
    conn = _db_breaker.call(pool.getconn)
    if not _is_conn_ok(conn):
        try:
            pool.putconn(conn, close=True)
        except Exception as _exc:
            log.debug("get_pg: %s", _exc)
        conn = _db_breaker.call(pool.getconn)
    conn.autocommit = True
    return conn


def release_pg(conn) -> None:
    """Return a connection obtained via ``get_pg()`` back to the pool."""
    if conn is None:
        return
    try:
        pool = _get_pool()
        pool.putconn(conn)
    except Exception as e:
        log.warning("release_pg failed: %s", e)


def pool_stats() -> dict:
    """Return pool diagnostics for the /health endpoint."""
    if _pool is None or _pool.closed:
        return {"status": "uninitialized"}
    # ThreadedConnectionPool exposes _pool dict (implementation detail)
    # but we just report breaker state
    return {
        "status":   "ok",
        "breaker":  _db_breaker.stats,
        "pool_min": POOL_MIN,
        "pool_max": POOL_MAX,
    }


def execute_one(sql: str, params=(), *, dict_row: bool = False):
    """
    Convenience: run ``sql`` with ``params`` and return the first row,
    or ``None``.  Uses ``db_conn()``.
    """
    factory = RealDictCursor if dict_row else None
    with db_conn() as conn:
        kwargs = {"cursor_factory": factory} if factory else {}
        with conn.cursor(**kwargs) as cur:
            cur.execute(sql, params)
            return cur.fetchone()


def execute_many(sql: str, params=(), *, dict_row: bool = False) -> list:
    """Run ``sql`` and return all rows."""
    factory = RealDictCursor if dict_row else None
    with db_conn() as conn:
        kwargs = {"cursor_factory": factory} if factory else {}
        with conn.cursor(**kwargs) as cur:
            cur.execute(sql, params)
            return cur.fetchall()


def execute_write(sql: str, params=()) -> int:
    """Run a DML statement and return ``rowcount``."""
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.rowcount


__all__ = [
    "db_conn", "get_pg", "release_pg", "pool_stats",
    "execute_one", "execute_many", "execute_write",
    "_db_breaker",
]
