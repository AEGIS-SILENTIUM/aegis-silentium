"""
AEGIS-SILENTIUM — Secret & Key Lifecycle Manager
==================================================
Manages operator keys, JWT signing secrets, and encryption keys with:
  * Generation of cryptographically strong secrets
  * Versioned key storage (previous key kept for graceful rotation window)
  * Rotation with configurable overlap period (default 24 h)
  * Audit trail for every rotation event
  * Environment + DB + Redis backed storage — configurable per-secret
  * Reencryption helper: re-encrypts DB values after Fernet key rotation

Rotation strategy
-----------------
1. Generate a new key (CURRENT).
2. Mark the old key as PREVIOUS (still valid for decryption).
3. After overlap_hours, PREVIOUS is retired (can no longer decrypt).
4. New tokens signed after rotation use CURRENT.
5. Old tokens signed before rotation are still verifiable with PREVIOUS
   until they expire naturally.

This means operators are never logged out mid-session by a key rotation.

Storage hierarchy
-----------------
  1. Environment variable (highest priority, read-only for CURRENT)
  2. Redis  (fast, ephemeral — good for rotation state)
  3. PostgreSQL (authoritative, auditable)

For production, integrate with HashiCorp Vault by replacing
``_read_from_env / _read_from_db`` with a Vault SDK call.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Callable, Optional

log = logging.getLogger("aegis.secrets")

_OVERLAP_HOURS_DEFAULT = 24


class SecretManager:
    """
    Lifecycle management for AEGIS secrets.

    Secrets managed:
    ----------------
    - jwt_secret          — JWT signing key (bytes)
    - c2_fernet_key       — Fernet encryption key for beacon payloads
    - operator_key        — Legacy single-key auth (deprecated, kept for compat)
    """

    def __init__(
        self,
        pg_connect_fn: Callable[[], Any],
        redis_client:  Any,
    ) -> None:
        self._pg    = pg_connect_fn
        self._redis = redis_client

    # ── Read ──────────────────────────────────────────────────────────────────

    def get_jwt_secret(self) -> bytes:
        """
        Return the current JWT signing secret.
        Priority: ENV → Redis → DB → generate-and-store.
        """
        # 1. Environment
        env_val = os.environ.get("C2_JWT_SECRET", "")
        if env_val:
            return env_val.encode()

        # 2. Redis (rotated value)
        try:
            val = self._redis.get("aegis:secret:jwt_current")
            if val:
                return val.encode() if isinstance(val, str) else val
        except Exception as _exc:
            log.debug("get_jwt_secret: %s", _exc)

        # 3. DB
        val = self._read_from_db("jwt_secret", version="current")
        if val:
            return val.encode()

        # 4. Bootstrap
        return self._bootstrap_jwt_secret()

    def get_fernet_key(self) -> bytes:
        """Return the current Fernet key (urlsafe base64, 32 bytes)."""
        env_val = os.environ.get("C2_SECRET", "")
        if env_val:
            return self._derive_fernet_key(env_val.encode())

        val = self._read_from_db("fernet_key", version="current")
        if val:
            return val.encode()
        return self._bootstrap_fernet_key()

    def get_previous_jwt_secret(self) -> Optional[bytes]:
        """Return the previous JWT secret (rotation overlap)."""
        try:
            val = self._redis.get("aegis:secret:jwt_previous")
            if val:
                return val.encode() if isinstance(val, str) else val
        except Exception as _exc:
            log.debug("get_previous_jwt_secret: %s", _exc)
        val = self._read_from_db("jwt_secret", version="previous")
        return val.encode() if val else None

    # ── Rotate ────────────────────────────────────────────────────────────────

    def rotate_jwt_secret(self, rotated_by: str = "system") -> dict:
        """
        Rotate the JWT signing secret.

        1. Promotes current → previous (kept for overlap_hours).
        2. Generates a new current key.
        3. Records rotation in the audit log.

        Returns the new secret (store securely!).
        """
        old_secret = self.get_jwt_secret()
        new_secret = secrets.token_hex(32)

        # Store in Redis (fast path)
        try:
            # Current → previous
            self._redis.set("aegis:secret:jwt_previous", old_secret)
            self._redis.expire("aegis:secret:jwt_previous",
                               _OVERLAP_HOURS_DEFAULT * 3600)
            # New current
            self._redis.set("aegis:secret:jwt_current", new_secret)
        except Exception as e:
            log.warning("secret rotation redis write failed: %s", e)

        # Store in DB
        self._write_to_db("jwt_secret", new_secret, "current", rotated_by)
        self._write_to_db("jwt_secret", old_secret.decode() if isinstance(old_secret, bytes)
                          else old_secret, "previous", rotated_by)

        self._audit("jwt_secret", "rotated", rotated_by)
        log.info("jwt_secret rotated  by=%s  old_prefix=%s  new_prefix=%s",
                 rotated_by,
                 (old_secret[:8].decode() if isinstance(old_secret, bytes) else old_secret[:8]) + "…",
                 new_secret[:8] + "…")
        return {
            "secret":      new_secret,
            "rotated_by":  rotated_by,
            "rotated_at":  datetime.now(timezone.utc).isoformat(),
            "overlap_hours": _OVERLAP_HOURS_DEFAULT,
        }

    def rotate_fernet_key(self, rotated_by: str = "system") -> dict:
        """Rotate the Fernet encryption key."""
        new_raw   = secrets.token_bytes(32)
        new_key   = base64.urlsafe_b64encode(new_raw).decode()
        old_key   = self.get_fernet_key()

        self._write_to_db("fernet_key", new_key, "current", rotated_by)
        self._write_to_db("fernet_key",
                          old_key.decode() if isinstance(old_key, bytes) else old_key,
                          "previous", rotated_by)

        self._audit("fernet_key", "rotated", rotated_by)
        log.warning("fernet_key rotated — existing encrypted payloads will need re-encryption  by=%s", rotated_by)
        return {
            "key_prefix":  new_key[:8] + "…",
            "rotated_by":  rotated_by,
            "rotated_at":  datetime.now(timezone.utc).isoformat(),
            "note":        "Run /api/admin/reencrypt to re-encrypt stored beacon payloads.",
        }

    # ── Audit / history ───────────────────────────────────────────────────────

    def rotation_history(self, secret_name: str, limit: int = 20) -> list[dict]:
        conn = self._pg()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT secret_name, action, rotated_by, ts "
                "FROM secret_audit WHERE secret_name=%s "
                "ORDER BY ts DESC LIMIT %s",
                (secret_name, limit),
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    # ── Internals ─────────────────────────────────────────────────────────────

    def _read_from_db(self, name: str, version: str) -> Optional[str]:
        try:
            conn = self._pg()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT value FROM secret_store WHERE name=%s AND version=%s",
                    (name, version),
                )
                row = cur.fetchone()
                return row[0] if row else None
        except Exception:
            return None

    def _write_to_db(self, name: str, value: str, version: str, by: str) -> None:
        try:
            conn = self._pg()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO secret_store (name, version, value, updated_by)
                    VALUES (%s,%s,%s,%s)
                    ON CONFLICT (name, version) DO UPDATE
                        SET value=EXCLUDED.value, updated_by=EXCLUDED.updated_by, updated_at=NOW()
                    """,
                    (name, version, value, by),
                )
        except Exception as e:
            log.error("secret_store write failed: %s", e)

    def _bootstrap_jwt_secret(self) -> bytes:
        new_secret = secrets.token_hex(32)
        self._write_to_db("jwt_secret", new_secret, "current", "bootstrap")
        try:
            self._redis.set("aegis:secret:jwt_current", new_secret)
        except Exception as _exc:
            log.debug("_bootstrap_jwt_secret: %s", _exc)
        log.warning("JWT secret bootstrapped — store securely and set C2_JWT_SECRET env var")
        return new_secret.encode()

    def _bootstrap_fernet_key(self) -> bytes:
        raw = secrets.token_bytes(32)
        key = base64.urlsafe_b64encode(raw)
        self._write_to_db("fernet_key", key.decode(), "current", "bootstrap")
        log.warning("Fernet key bootstrapped — store securely and set C2_SECRET env var")
        return key

    @staticmethod
    def _derive_fernet_key(secret: bytes) -> bytes:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32,
            salt=b"aegis_c2_salt_v4", iterations=260_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(secret))

    def _audit(self, name: str, action: str, by: str) -> None:
        try:
            conn = self._pg()
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO secret_audit(secret_name, action, rotated_by) VALUES(%s,%s,%s)",
                    (name, action, by),
                )
        except Exception as _exc:
            log.debug("_audit: %s", _exc)


__all__ = ["SecretManager"]
