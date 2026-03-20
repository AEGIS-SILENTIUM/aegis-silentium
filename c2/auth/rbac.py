"""
AEGIS-SILENTIUM — Identity, RBAC & Session Management
=======================================================
Design
------
Operators authenticate with their key + operator handle and receive
a short-lived JWT session token (1 hour, HS256).  Every subsequent
request carries the JWT in the ``Authorization: Bearer …`` header.

Roles (ordered by privilege):
  ghost     — read-only observer (view dashboards, logs)
  operator  — standard operator (create/run tasks, chat)
  senior    — full operational access (listeners, payloads, exploits)
  lead      — team lead (surveillance targets, manage operators)
  admin     — full system access (delete, clear, settings, key rotation)

Permission model
----------------
Each role is granted an explicit set of permissions (strings).
Route decorators call ``require_permission(perm)`` which checks the
current session's role.

Session management
------------------
Sessions are stored in Redis with a TTL.  Revoking a session (logout,
key rotation, admin revoke) simply deletes the Redis key — the JWT
becomes immediately invalid even if not expired.

The refresh token mechanism:
  - Access token:   60 min,  verified per-request
  - Refresh token: 7 days,  exchanged for a new access token

Anti-replay
-----------
Each token carries a ``jti`` (JWT ID) that is checked against a
Redis revocation set.  This set is the authoritative source;
even a valid JWT is rejected if its jti appears in the revoked set.

Audit
-----
Every login, logout, permission denial, and session event is written
to the ``operator_audit`` table with IP, user-agent, and timestamp.
"""
from __future__ import annotations

import os
import hashlib
import hmac as _hmac
import json
import logging
import secrets
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

log = logging.getLogger("aegis.rbac")

# ── Role hierarchy ────────────────────────────────────────────────────────────

ROLES: list[str] = ["ghost", "operator", "senior", "lead", "admin"]

_ROLE_RANK: dict[str, int] = {r: i for i, r in enumerate(ROLES)}

# Permissions available in the system
ALL_PERMISSIONS: set[str] = {
    # Core views
    "dashboard:view",
    "sessions:view",      "sessions:kill",
    "tasks:view",         "tasks:create",      "tasks:cancel",
    "vulns:view",
    "creds:view",
    "exfil:view",
    "logs:view",
    "campaigns:view",     "campaigns:create",  "campaigns:delete",
    "campaigns:write",    # alias for create+update combined

    # Node / implant management
    "nodes:view",         "nodes:command",     "nodes:kill",

    # New-feature pages
    "listeners:view",     "listeners:create",  "listeners:start",
    "listeners:stop",     "listeners:delete",
    "exploits:view",      "exploits:create",   "exploits:deploy",
    "exploits:retire",    "exploits:delete",
    "payloads:view",      "payloads:generate", "payloads:delete",
    "surveillance:view",  "surveillance:create","surveillance:activate",
    "surveillance:delete","surveillance:data",
    "chat:view",          "chat:post",         "chat:delete",

    # Admin (granular)
    "admin:read",         "admin:write",       "admin",
    "operators:view",     "operators:create",  "operators:deactivate",
    "operators:set_role",
    "settings:view",      "settings:edit",
    "reporting:view",     "reporting:generate",
    "secrets:rotate",
    "audit:view",
    "agent_update:push",
    "relays:manage",
}

# Role → granted permissions
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "ghost": {
        "dashboard:view", "sessions:view", "tasks:view", "vulns:view",
        "logs:view", "campaigns:view", "exploits:view", "payloads:view",
        "listeners:view", "surveillance:view", "chat:view", "reporting:view",
        "nodes:view",
    },
    "operator": set(),   # populated below
    "senior": set(),
    "lead": set(),
    "admin": set(ALL_PERMISSIONS),
}

ROLE_PERMISSIONS["operator"] = ROLE_PERMISSIONS["ghost"] | {
    "tasks:create", "tasks:cancel",
    "campaigns:create",
    "chat:post",
    "listeners:start", "listeners:stop",
    "exploits:deploy",
    "payloads:generate",
    "reporting:generate",
    "nodes:view", "nodes:command",
    "campaigns:write",
    "admin:read",
}

ROLE_PERMISSIONS["senior"] = ROLE_PERMISSIONS["operator"] | {
    "sessions:kill",
    "campaigns:delete",
    "listeners:create", "listeners:delete",
    "exploits:create", "exploits:retire", "exploits:delete",
    "payloads:delete",
    "surveillance:create", "surveillance:activate",
    "surveillance:data",
    "chat:delete",
    "creds:view", "exfil:view",
    "agent_update:push",
    "relays:manage",
    "nodes:kill",
    "admin:read", "admin:write",
}

ROLE_PERMISSIONS["lead"] = ROLE_PERMISSIONS["senior"] | {
    "surveillance:delete",
    "exploits:delete",
    "operators:view",
    "operators:create",
    "operators:deactivate",
    "settings:view",
    "audit:view",
    "operators:set_role",
}


def role_has(role: str, permission: str) -> bool:
    """Check if ``role`` has ``permission`` (exact match or wildcard ``*``)."""
    if role == "admin":
        return True
    perms = ROLE_PERMISSIONS.get(role, set())
    return permission in perms or "*" in perms


# ── JWT (pure-Python HS256, no external library required) ─────────────────────

def _b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    import base64
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def _jwt_sign(payload: dict, secret: bytes) -> str:
    header  = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body    = _b64url(json.dumps(payload).encode())
    msg     = f"{header}.{body}".encode()
    sig     = _hmac.new(secret, msg, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url(sig)}"


def _jwt_verify(token: str, secret: bytes) -> dict:
    """
    Verify and decode a JWT token.
    Raises ValueError on any tampering or expiry.
    """
    try:
        header_b64, body_b64, sig_b64 = token.split(".")
    except ValueError:
        raise ValueError("Malformed JWT.")

    msg      = f"{header_b64}.{body_b64}".encode()
    expected = _hmac.new(secret, msg, hashlib.sha256).digest()
    actual   = _b64url_decode(sig_b64)

    if not _hmac.compare_digest(expected, actual):
        raise ValueError("JWT signature invalid.")

    payload = json.loads(_b64url_decode(body_b64))
    if payload.get("exp", 0) < time.time():
        raise ValueError("JWT has expired.")
    return payload


# ── Session dataclass ─────────────────────────────────────────────────────────

@dataclass
class Session:
    jti:      str
    operator: str
    role:     str
    issued:   float  = field(default_factory=time.time)
    expires:  float  = field(default_factory=lambda: time.time() + 3600)
    ip:       str    = ""
    ua:       str    = ""


# ── RBAC Manager ──────────────────────────────────────────────────────────────

class RBACManager:
    """
    Operator identity and session management.

    Constructor arguments
    ---------------------
    pg_connect_fn : () → psycopg2 connection
    redis_client  : Redis instance
    jwt_secret    : bytes — signing secret (rotate via ``rotate_jwt_secret``)
    access_ttl    : access token lifetime in seconds (default 3 600)
    refresh_ttl   : refresh token lifetime in seconds (default 604 800 = 7 d)
    """

    # ── Class-level IP allowlist ─────────────────────────────────────────────
    # Set AEGIS_IP_ALLOWLIST=10.0.0.0/8,192.168.0.0/16 to restrict login IPs.
    _IP_ALLOWLIST: list = []

    @classmethod
    def _load_ip_allowlist(cls) -> None:
        """Parse AEGIS_IP_ALLOWLIST env var into network objects."""
        import ipaddress
        raw = os.environ.get("AEGIS_IP_ALLOWLIST", "")
        cls._IP_ALLOWLIST = []
        for cidr in raw.split(","):
            cidr = cidr.strip()
            if cidr:
                try:
                    cls._IP_ALLOWLIST.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass

    @classmethod
    def _ip_allowed(cls, ip: str) -> bool:
        """Return True if ip is in the allowlist (or allowlist is empty = allow all)."""
        if not cls._IP_ALLOWLIST:
            return True  # No restriction configured
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in cls._IP_ALLOWLIST)
        except ValueError:
            return False

    def __init__(
        self,
        pg_connect_fn: Callable[[], Any],
        redis_client:  Any,
        jwt_secret:    bytes,
        access_ttl:    int = 3_600,
        refresh_ttl:   int = 604_800,
    ) -> None:
        self._pg          = pg_connect_fn
        self._redis       = redis_client
        self._secret      = jwt_secret
        self._access_ttl  = access_ttl
        self._refresh_ttl = refresh_ttl

    # ── Operator lifecycle ────────────────────────────────────────────────────

    def create_operator(
        self,
        handle: str,
        raw_key: str,
        role: str = "operator",
        created_by: str = "system",
    ) -> dict:
        """
        Register a new operator.  Stores a bcrypt-style PBKDF2 hash of the key.
        Raises RuntimeError if the handle already exists.
        """
        if role not in ROLES:
            raise ValueError(f"Invalid role '{role}'.  Must be one of: {', '.join(ROLES)}.")
        if not handle or not raw_key:
            raise ValueError("handle and raw_key are required.")

        key_hash = _hash_key(raw_key)
        conn = self._pg()
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM operators WHERE handle = %s", (handle,))
            if cur.fetchone():
                raise RuntimeError(f"Operator '{handle}' already exists.")
            cur.execute(
                """
                INSERT INTO operators (handle, key_hash, role, created_by, active)
                VALUES (%s,%s,%s,%s,TRUE) RETURNING id, handle, role, created_at
                """,
                (handle, key_hash, role, created_by),
            )
            cols = [d[0] for d in cur.description]
            row  = dict(zip(cols, cur.fetchone()))

        self._audit(handle, "operator_created", f"Created by {created_by} with role {role}")
        log.info("operator created  handle=%s  role=%s  by=%s", handle, role, created_by)
        return row

    def authenticate(self, handle: str, raw_key: str, ip: str = "", ua: str = "") -> dict:
        # Enforce IP allowlist before anything else
        RBACManager._load_ip_allowlist()
        if ip and not RBACManager._ip_allowed(ip):
            self._audit(handle, "login_blocked_ip", {"ip": ip})
            raise PermissionError(f"Login denied from IP {ip} — not in allowlist")
        """
        Verify operator credentials and return access + refresh tokens.

        Returns
        -------
        {"access_token": ..., "refresh_token": ..., "expires_in": ...,
         "operator": ..., "role": ...}

        Raises
        ------
        PermissionError  — invalid credentials or inactive account.
        """
        conn = self._pg()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT key_hash, role, active, failed_logins, locked_until "
                "FROM operators WHERE handle = %s",
                (handle,),
            )
            row = cur.fetchone()

        if not row:
            self._audit(handle, "login_fail", f"Unknown handle from {ip}", ip=ip)
            raise PermissionError("Invalid credentials.")

        key_hash, role, active, failed_logins, locked_until = row

        if not active:
            raise PermissionError("Operator account is deactivated.")

        # Lockout check
        if locked_until and locked_until > datetime.now(timezone.utc):
            secs = int((locked_until - datetime.now(timezone.utc)).total_seconds())
            raise PermissionError(f"Account locked.  Try again in {secs}s.")

        if not _verify_key(raw_key, key_hash):
            self._increment_failed_logins(handle)
            self._audit(handle, "login_fail", f"Bad key from {ip}", ip=ip)
            raise PermissionError("Invalid credentials.")

        # Reset failed logins on success
        self._reset_failed_logins(handle)

        # Issue tokens
        jti_access  = secrets.token_hex(16)
        jti_refresh = secrets.token_hex(16)
        now         = time.time()

        access_payload = {
            "sub":  handle,
            "role": role,
            "jti":  jti_access,
            "iat":  now,
            "exp":  now + self._access_ttl,
            "type": "access",
        }
        refresh_payload = {
            "sub":  handle,
            "role": role,
            "jti":  jti_refresh,
            "iat":  now,
            "exp":  now + self._refresh_ttl,
            "type": "refresh",
        }

        access_token  = _jwt_sign(access_payload,  self._secret)
        refresh_token = _jwt_sign(refresh_payload, self._secret)

        # Store in Redis for fast revocation checks
        self._redis.setex(f"aegis:sess:access:{jti_access}",   self._access_ttl,  handle)
        self._redis.setex(f"aegis:sess:refresh:{jti_refresh}", self._refresh_ttl, handle)

        self._update_last_login(handle, ip)
        self._audit(handle, "login_ok", f"Authenticated from {ip} ({role})", ip=ip, ua=ua)
        log.info("login  handle=%s  role=%s  ip=%s", handle, role, ip)

        return {
            "access_token":  access_token,
            "refresh_token": refresh_token,
            "token_type":    "Bearer",
            "expires_in":    self._access_ttl,
            "operator":      handle,
            "role":          role,
        }

    def verify_access_token(self, token: str) -> Session:
        """
        Verify an access token and return a ``Session``.
        Raises ``PermissionError`` on any failure.
        """
        try:
            payload = _jwt_verify(token, self._secret)
        except ValueError as e:
            raise PermissionError(str(e))

        if payload.get("type") != "access":
            raise PermissionError("Not an access token.")

        jti = payload["jti"]
        # Revocation check
        if not self._redis.exists(f"aegis:sess:access:{jti}"):
            raise PermissionError("Session revoked or expired.")

        return Session(
            jti      = jti,
            operator = payload["sub"],
            role     = payload["role"],
            issued   = payload["iat"],
            expires  = payload["exp"],
        )

    def refresh(self, refresh_token: str, ip: str = "") -> dict:
        """Exchange a valid refresh token for a new access token."""
        try:
            payload = _jwt_verify(refresh_token, self._secret)
        except ValueError as e:
            raise PermissionError(str(e))

        if payload.get("type") != "refresh":
            raise PermissionError("Not a refresh token.")

        jti = payload["jti"]
        if not self._redis.exists(f"aegis:sess:refresh:{jti}"):
            raise PermissionError("Refresh token revoked or expired.")

        handle = payload["sub"]
        # Verify operator is still active
        conn = self._pg()
        with conn.cursor() as cur:
            cur.execute("SELECT role, active FROM operators WHERE handle = %s", (handle,))
            row = cur.fetchone()
        if not row or not row[1]:
            raise PermissionError("Operator deactivated.")

        role = row[0]
        now  = time.time()
        jti_new     = secrets.token_hex(16)
        new_payload = {
            "sub":  handle,
            "role": role,
            "jti":  jti_new,
            "iat":  now,
            "exp":  now + self._access_ttl,
            "type": "access",
        }
        new_token = _jwt_sign(new_payload, self._secret)
        self._redis.setex(f"aegis:sess:access:{jti_new}", self._access_ttl, handle)

        self._audit(handle, "token_refreshed", f"New token issued from {ip}", ip=ip)
        return {
            "access_token": new_token,
            "token_type":   "Bearer",
            "expires_in":   self._access_ttl,
            "operator":     handle,
            "role":         role,
        }

    def revoke(self, jti: str, handle: str) -> None:
        """Revoke a specific session by JTI."""
        self._redis.delete(f"aegis:sess:access:{jti}")
        self._audit(handle, "session_revoked", f"Session {jti[:8]}… revoked")

    def revoke_all(self, handle: str, by: str) -> int:
        """Revoke all active sessions for an operator."""
        pattern = f"aegis:sess:access:*"
        count   = 0
        for key in self._redis.scan_iter(pattern):
            val = self._redis.get(key)
            if val == handle:
                self._redis.delete(key)
                count += 1
        self._audit(handle, "all_sessions_revoked", f"All sessions revoked by {by}")
        log.info("revoked all sessions  handle=%s  count=%d  by=%s", handle, count, by)
        return count

    def set_role(self, handle: str, new_role: str, by: str) -> None:
        if new_role not in ROLES:
            raise ValueError(f"Invalid role '{new_role}'.")
        conn = self._pg()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE operators SET role=%s WHERE handle=%s RETURNING handle",
                (new_role, handle),
            )
            if not cur.fetchone():
                raise KeyError(f"Operator '{handle}' not found.")
        # Force re-login for new permissions to take effect
        self.revoke_all(handle, by)
        self._audit(handle, "role_changed", f"Role → {new_role} by {by}")

    def deactivate(self, handle: str, by: str) -> None:
        conn = self._pg()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE operators SET active=FALSE WHERE handle=%s", (handle,)
            )
        self.revoke_all(handle, by)
        self._audit(handle, "operator_deactivated", f"Deactivated by {by}")

    def list_operators(self) -> list[dict]:
        conn = self._pg()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, handle, role, active, last_login_at, failed_logins, "
                "       locked_until, created_at, created_by "
                "FROM operators ORDER BY created_at DESC"
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def get_audit_trail(
        self,
        handle:   Optional[str] = None,
        limit:    int = 200,
        offset:   int = 0,
        action:   Optional[str] = None,
    ) -> list[dict]:
        clauses, params = [], []
        if handle:
            clauses.append("operator = %s"); params.append(handle)
        if action:
            clauses.append("action = %s"); params.append(action)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        conn = self._pg()
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT * FROM operator_audit {where} "
                f"ORDER BY ts DESC LIMIT %s OFFSET %s",
                params + [limit, offset],
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _audit(
        self, operator: str, action: str, detail: str = "",
        ip: str = "", ua: str = "",
    ) -> None:
        try:
            conn = self._pg()
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO operator_audit(operator, action, detail, ip, user_agent) "
                    "VALUES(%s,%s,%s,%s,%s)",
                    (operator, action, detail[:500], ip[:64], ua[:256]),
                )
        except Exception as _e: log.debug("suppressed exception: %s", _e)   # Audit failures must never break the request

    def _increment_failed_logins(self, handle: str) -> None:
        conn = self._pg()
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE operators SET
                    failed_logins = failed_logins + 1,
                    locked_until  = CASE
                        WHEN failed_logins + 1 >= 5
                        THEN NOW() + INTERVAL '15 minutes'
                        ELSE locked_until
                    END
                WHERE handle = %s
                """,
                (handle,),
            )

    def _reset_failed_logins(self, handle: str) -> None:
        conn = self._pg()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE operators SET failed_logins=0, locked_until=NULL WHERE handle=%s",
                (handle,),
            )

    def _update_last_login(self, handle: str, ip: str) -> None:
        conn = self._pg()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE operators SET last_login_at=NOW(), last_ip=%s WHERE handle=%s",
                (ip, handle),
            )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hash_key(raw_key: str) -> str:
    """PBKDF2-HMAC-SHA256 with a per-key salt.  Format: ``salt$hash``."""
    salt = secrets.token_hex(16)
    dk   = hashlib.pbkdf2_hmac(
        "sha256", raw_key.encode(), salt.encode(), iterations=260_000
    )
    return f"{salt}${dk.hex()}"


def _verify_key(raw_key: str, stored: str) -> bool:
    try:
        salt, expected_hex = stored.split("$", 1)
        dk = hashlib.pbkdf2_hmac(
            "sha256", raw_key.encode(), salt.encode(), iterations=260_000
        )
        return _hmac.compare_digest(dk.hex(), expected_hex)
    except Exception:
        return False


__all__ = [
    "RBACManager", "Session",
    "ROLES", "ROLE_PERMISSIONS", "ALL_PERMISSIONS",
    "role_has",
]


# ══════════════════════════════════════════════════════════════════════════════
# PER-OPERATOR API KEY MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

import hashlib as _hs
import hmac as _hmac
import secrets as _sec
import json as _json_rb
import time as _time_rb


class OperatorKeyStore:
    """
    Per-operator API keys — each operator gets their own unique key
    with independent rotation, expiry, and revocation.
    Keys are stored in Redis as SHA-256 hashes (never the raw key).
    """

    _PREFIX = "api_key:"

    def __init__(self, redis_client) -> None:
        self._r = redis_client

    def issue(self, operator: str, role: str = "operator",
              expires_in: int = 86400 * 30, label: str = "") -> str:
        raw_key  = "aegis_" + _sec.token_urlsafe(36)
        salt     = _sec.token_hex(16)
        key_hash = _hs.sha256((salt + raw_key).encode()).hexdigest()
        record   = {
            "operator": operator, "role": role,
            "key_hash": key_hash, "salt": salt,
            "label":    label or f"key-{raw_key[:8]}",
            "issued_at": int(_time_rb.time()),
            "expires_at": int(_time_rb.time()) + expires_in,
            "revoked": "0",
        }
        if self._r:
            try:
                self._r.setex(
                    f"{self._PREFIX}{operator}:{key_hash[:16]}",
                    expires_in, _json_rb.dumps(record)
                )
            except Exception as _e:
                import logging; logging.getLogger("aegis.rbac").debug("key store: %s", _e)
        return raw_key

    def verify(self, raw_key: str) -> tuple:
        if not self._r:
            raise ValueError("No Redis")
        try:
            all_keys = self._r.keys(f"{self._PREFIX}*") or []
        except Exception as e:
            raise ValueError(f"Redis scan failed: {e}")
        for rk in all_keys:
            try:
                raw = self._r.get(rk)
                if not raw:
                    continue
                rec  = _json_rb.loads(raw)
                exp  = _hs.sha256((rec["salt"] + raw_key).encode()).hexdigest()
                if _hmac.compare_digest(exp, rec["key_hash"]):
                    if rec.get("revoked") == "1":
                        raise ValueError("Key revoked")
                    if _time_rb.time() > rec.get("expires_at", float("inf")):
                        raise ValueError("Key expired")
                    return rec["operator"], rec["role"]
            except ValueError:
                raise
            except Exception as _e:
                import logging as _l; _l.getLogger("aegis.rbac").debug("rbac error: %s", _e)
        raise ValueError("Invalid API key")

    def revoke(self, operator: str, raw_key: str) -> bool:
        if not self._r:
            return False
        try:
            for rk in (self._r.keys(f"{self._PREFIX}{operator}:*") or []):
                raw = self._r.get(rk)
                if not raw:
                    continue
                rec  = _json_rb.loads(raw)
                exp  = _hs.sha256((rec["salt"] + raw_key).encode()).hexdigest()
                if _hmac.compare_digest(exp, rec["key_hash"]):
                    rec["revoked"] = "1"
                    ttl = max(self._r.ttl(rk), 3600)
                    self._r.setex(rk, ttl, _json_rb.dumps(rec))
                    return True
        except Exception as _e:
            import logging as _l; _l.getLogger("aegis.rbac").debug("rbac error: %s", _e)
        return False

    def revoke_all(self, operator: str) -> int:
        if not self._r:
            return 0
        count = 0
        try:
            for rk in (self._r.keys(f"{self._PREFIX}{operator}:*") or []):
                raw = self._r.get(rk)
                if not raw:
                    continue
                rec = _json_rb.loads(raw)
                rec["revoked"] = "1"
                ttl = max(self._r.ttl(rk), 3600)
                self._r.setex(rk, ttl, _json_rb.dumps(rec))
                count += 1
        except Exception as _e:
            import logging as _l; _l.getLogger("aegis.rbac").debug("rbac error: %s", _e)
        return count

    def list_keys(self, operator: str) -> list:
        if not self._r:
            return []
        result = []
        try:
            for rk in (self._r.keys(f"{self._PREFIX}{operator}:*") or []):
                raw = self._r.get(rk)
                if not raw:
                    continue
                rec = _json_rb.loads(raw)
                result.append({
                    "label":      rec.get("label", ""),
                    "role":       rec.get("role", "operator"),
                    "issued_at":  rec.get("issued_at"),
                    "expires_at": rec.get("expires_at"),
                    "revoked":    rec.get("revoked") == "1",
                    "expired":    _time_rb.time() > rec.get("expires_at", float("inf")),
                })
        except Exception as _e:
            import logging as _l; _l.getLogger("aegis.rbac").debug("rbac error: %s", _e)
        return result


class TOTPManager:
    """
    RFC 6238 TOTP — 6-digit codes, 30-second window, SHA-1.
    No external dependencies beyond Python stdlib.
    """

    _DIGITS   = 6
    _INTERVAL = 30

    @staticmethod
    def generate_secret() -> str:
        import base64
        return base64.b32encode(_sec.token_bytes(20)).decode()

    def current_code(self, secret: str) -> str:
        return self._hotp(secret, int(_time_rb.time()) // self._INTERVAL)

    def verify(self, secret: str, code: str, window: int = 1) -> bool:
        ts = int(_time_rb.time()) // self._INTERVAL
        for step in range(-window, window + 1):
            expected = self._hotp(secret, ts + step)
            if _hmac.compare_digest(expected.encode(), code.strip().encode()):
                return True
        return False

    @staticmethod
    def _hotp(secret: str, counter: int) -> str:
        import base64, struct, hmac, hashlib
        key    = base64.b32decode(secret.upper())
        msg    = struct.pack(">Q", counter)
        h      = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code   = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
        return str(code % (10 ** TOTPManager._DIGITS)).zfill(TOTPManager._DIGITS)

    def provisioning_uri(self, secret: str, operator: str,
                          issuer: str = "AEGIS-SILENTIUM") -> str:
        from urllib.parse import quote
        return (
            f"otpauth://totp/{quote(issuer)}:{quote(operator)}"
            f"?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
        )
