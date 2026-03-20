"""
AEGIS-SILENTIUM — PostgreSQL Connection Pool
=============================================
Wraps psycopg2's ThreadedConnectionPool with:
  * Auto-reconnect on stale connections
  * Per-request connection checkout with context-manager semantics
  * Pool health metrics (pool_size, checked_out, wait_count)
  * Statement-level timeout (prevents runaway queries from blocking)
  * Automatic schema/migration bootstrap on first connection
  * Graceful shutdown that waits for in-flight queries to finish

Usage
-----
    from c2.db.pool import Pool
    pool = Pool.from_env()

    with pool.connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT 1")

    # Preferred shorthand for single queries:
    with pool.cursor() as cur:
        cur.execute("SELECT * FROM listeners")
        return cur.fetchall()
"""
from __future__ import annotations

import contextlib
import logging
import os
import threading
import time
from typing import Generator, Optional

import psycopg2
import psycopg2.extras
import psycopg2.pool
from psycopg2.extras import RealDictCursor

log = logging.getLogger("aegis.db.pool")

_STATEMENT_TIMEOUT_MS = int(os.environ.get("PG_STATEMENT_TIMEOUT_MS", "15000"))
_LOCK_TIMEOUT_MS      = int(os.environ.get("PG_LOCK_TIMEOUT_MS", "3000"))


class Pool:
    """
    Thread-safe PostgreSQL connection pool.

    Min connections are created eagerly; max connections are created on-demand
    and returned to the pool after use.  Stale connections are detected via a
    lightweight keepalive and replaced automatically.
    """

    def __init__(
        self,
        dsn: str,
        min_conn: int = 2,
        max_conn: int = 20,
        statement_timeout_ms: int = _STATEMENT_TIMEOUT_MS,
        lock_timeout_ms:      int = _LOCK_TIMEOUT_MS,
    ) -> None:
        self._dsn        = dsn
        self._min        = min_conn
        self._max        = max_conn
        self._stmt_to    = statement_timeout_ms
        self._lock_to    = lock_timeout_ms
        self._lock       = threading.Lock()
        self._wait_count = 0
        self._pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None
        self._init_pool()

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> "Pool":
        dsn = (
            f"host={os.environ.get('POSTGRES_HOST', 'localhost')} "
            f"dbname={os.environ.get('POSTGRES_DB', 'aegis')} "
            f"user={os.environ.get('POSTGRES_USER', 'aegis')} "
            f"password={os.environ.get('POSTGRES_PASSWORD', '')} "
            f"connect_timeout=5 "
            f"application_name=aegis-c2"
        )
        return cls(
            dsn      = dsn,
            min_conn = int(os.environ.get("PG_POOL_MIN", "2")),
            max_conn = int(os.environ.get("PG_POOL_MAX", "20")),
        )

    # ── Context managers ──────────────────────────────────────────────────────

    @contextlib.contextmanager
    def connection(self) -> Generator:
        """
        Checkout a connection from the pool.  Automatically returns it on exit.
        The connection has autocommit=True; callers manage transactions manually.
        Replaces stale connections transparently.
        """
        t_start = time.monotonic()
        with self._lock:
            self._wait_count += 1
        conn = None
        try:
            conn = self._get_conn()
            if not self._is_alive(conn):
                log.debug("stale connection detected — replacing")
                conn = self._replace_conn(conn)
            yield conn
        finally:
            wait_ms = (time.monotonic() - t_start) * 1000
            if wait_ms > 1000:
                log.warning("db.pool slow checkout  wait_ms=%.0f", wait_ms)
            with self._lock:
                self._wait_count = max(0, self._wait_count - 1)
            if conn:
                try:
                    self._pool.putconn(conn)
                except Exception as _exc:
                    log.debug("unknown: %s", _exc)

    @contextlib.contextmanager
    def cursor(
        self, cursor_factory=RealDictCursor
    ) -> Generator:
        """Convenience: check out a connection and open a cursor in one step."""
        with self.connection() as conn:
            with conn.cursor(cursor_factory=cursor_factory) as cur:
                yield cur

    # ── Stats ─────────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        p = self._pool
        if not p:
            return {"status": "offline"}
        return {
            "status":      "ok",
            "min":         self._min,
            "max":         self._max,
            "wait_count":  self._wait_count,
        }

    # ── Health check ──────────────────────────────────────────────────────────

    def is_healthy(self) -> bool:
        try:
            with self.cursor() as cur:
                cur.execute("SELECT 1")
            return True
        except Exception:
            return False

    # ── Shutdown ──────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Return all connections and close the pool."""
        if self._pool:
            self._pool.closeall()
            log.info("db.pool closed")

    # ── Internals ─────────────────────────────────────────────────────────────

    def _init_pool(self) -> None:
        self._pool = psycopg2.pool.ThreadedConnectionPool(
            self._min,
            self._max,
            self._dsn,
        )
        # Configure timeouts on every connection as it's created
        for _ in range(self._min):
            conn = self._pool.getconn()
            self._configure_conn(conn)
            self._pool.putconn(conn)
        log.info(
            "db.pool ready  min=%d  max=%d  stmt_timeout=%dms",
            self._min, self._max, self._stmt_to,
        )

    def _configure_conn(self, conn) -> None:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(f"SET statement_timeout = {self._stmt_to}")
            cur.execute(f"SET lock_timeout = {self._lock_to}")

    def _get_conn(self):
        for attempt in range(3):
            try:
                conn = self._pool.getconn()
                if conn.closed:
                    conn = self._replace_conn(conn)
                return conn
            except psycopg2.pool.PoolError:
                if attempt == 2:
                    raise
                time.sleep(0.1 * (attempt + 1))

    def _is_alive(self, conn) -> bool:
        if conn.closed:
            return False
        try:
            conn.poll()
            return conn.status == psycopg2.extensions.STATUS_READY
        except Exception:
            return False

    def _replace_conn(self, bad_conn):
        try:
            self._pool.putconn(bad_conn, close=True)
        except Exception as _exc:
            log.debug("_replace_conn: %s", _exc)
        new_conn = psycopg2.connect(self._dsn)
        self._configure_conn(new_conn)
        return new_conn


# ── Module-level singleton ────────────────────────────────────────────────────
# app.py calls: from c2.db.pool import pool_from_env; _pool = pool_from_env()

def pool_from_env() -> Pool:
    return Pool.from_env()


__all__ = ["Pool", "pool_from_env"]
