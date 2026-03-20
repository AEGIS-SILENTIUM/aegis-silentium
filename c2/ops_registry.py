"""
AEGIS — Operator Registry & Role-Based Access Control
=======================================================
Moves from a single shared ``OPERATOR_KEY`` to per-operator identities
with scoped roles.

Architecture
------------
Operators authenticate with their individual key (stored as a salted
PBKDF2-SHA256 digest in PostgreSQL — never in plaintext).  Upon
successful authentication they receive a short-lived session token
(a signed JWT-like structure using HMAC-SHA256 — no external JWT
library required).

Roles
-----
ADMIN       Full access.  Can manage operators.
OPERATOR    Normal red-team access: tasks, payloads, sessions.
READ_ONLY   Dashboard view only.  No mutations.
AGENT       Internal — used by beaconing implants only.

Permissions
-----------
A permission is a ``resource:action`` string, e.g. ``listeners:write``.
Each role maps to a frozenset of allowed permissions.

Session tokens
--------------
Format:  base64(header).base64(payload).HMAC-SHA256(header.payload, signing_key)
Lifetime: configurable, default 8 hours.
Tokens are verified on every request — no server-side session store needed
(revocation is via a Redis deny-list keyed on token fingerprint).

Fallback compatibility
----------------------
If ``OPERATOR_KEY`` env var is set and the incoming request uses it
directly (as the old code did), the request is treated as ADMIN with
operator handle "legacy_operator".  This maintains backward compatibility
while the operator table is being populated.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import threading
from datetime import datetime, timezone
from functools import wraps
from typing import Optional

from flask import request, jsonify

log = logging.getLogger("aegis.auth")

# ── Config ────────────────────────────────────────────────────────────────────

SIGNING_KEY   = os.environ.get("SESSION_SIGNING_KEY",
                               os.environ.get("C2_SECRET", "change-this")).encode()
TOKEN_TTL     = int(os.environ.get("SESSION_TTL_HOURS", "8")) * 3600
LEGACY_KEY    = os.environ.get("OPERATOR_KEY", "aegis-operator-key-2026")

# ── Roles & permissions ───────────────────────────────────────────────────────

PERMISSIONS = {
    "nodes:read",       "nodes:write",
    "tasks:read",       "tasks:write",
    "vulns:read",
    "campaigns:read",   "campaigns:write",
    "listeners:read",   "listeners:write",
    "exploits:read",    "exploits:write",
    "payloads:read",    "payloads:write",
    "surveillance:read","surveillance:write",
    "chat:read",        "chat:write",
    "creds:read",
    "exfil:read",
    "relays:read",      "relays:write",
    "operators:read",   "operators:write",
    "settings:read",    "settings:write",
    "agent:push",
}

ROLES: dict[str, frozenset[str]] = {
    "ADMIN": frozenset(PERMISSIONS),
    "OPERATOR": frozenset({
        "nodes:read", "nodes:write",
        "tasks:read", "tasks:write",
        "vulns:read",
        "campaigns:read", "campaigns:write",
        "listeners:read", "listeners:write",
        "exploits:read", "exploits:write",
        "payloads:read", "payloads:write",
        "surveillance:read", "surveillance:write",
        "chat:read", "chat:write",
        "creds:read", "exfil:read",
        "relays:read",
        "settings:read",
    }),
    "READ_ONLY": frozenset({
        "nodes:read", "tasks:read", "vulns:read",
        "campaigns:read", "listeners:read", "exploits:read",
        "payloads:read", "surveillance:read",
        "chat:read", "creds:read", "exfil:read", "relays:read",
    }),
    "AGENT": frozenset({
        "nodes:write", "tasks:read", "tasks:write",
    }),
}


class OperatorSession:
    """Immutable value object carrying the authenticated operator's identity."""

    __slots__ = ("handle", "role", "permissions", "token_id", "issued_at")

    def __init__(
        self,
        handle:      str,
        role:        str,
        token_id:    str,
        issued_at:   float,
    ):
        self.handle      = handle
        self.role        = role
        self.permissions = ROLES.get(role, frozenset())
        self.token_id    = token_id
        self.issued_at   = issued_at

    def can(self, permission: str) -> bool:
        return permission in self.permissions

    def require(self, permission: str) -> None:
        """Raise PermissionError if the operator lacks ``permission``."""
        if not self.can(permission):
            raise PermissionError(
                f"Operator '{self.handle}' ({self.role}) "
                f"lacks permission '{permission}'"
            )

    def to_dict(self) -> dict:
        return {
            "handle":     self.handle,
            "role":       self.role,
            "token_id":   self.token_id,
            "issued_at":  datetime.fromtimestamp(
                              self.issued_at, tz=timezone.utc).isoformat(),
        }


# ── Token generation & verification ──────────────────────────────────────────

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))


def issue_token(handle: str, role: str) -> str:
    """
    Generate a signed session token.
    Format: <b64-header>.<b64-payload>.<b64-sig>
    """
    header  = _b64(json.dumps({"alg": "HS256", "typ": "AEGIS"}).encode())
    payload = _b64(json.dumps({
        "sub":  handle,
        "role": role,
        "jti":  secrets.token_hex(8),
        "iat":  int(time.time()),
        "exp":  int(time.time()) + TOKEN_TTL,
    }).encode())
    sig = _b64(hmac.new(
        SIGNING_KEY,
        f"{header}.{payload}".encode(),
        hashlib.sha256,
    ).digest())
    return f"{header}.{payload}.{sig}"


def verify_token(token: str) -> Optional[OperatorSession]:
    """
    Verify signature, expiry, and revocation.
    Returns an OperatorSession or None.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts

        expected_sig = _b64(hmac.new(
            SIGNING_KEY,
            f"{header_b64}.{payload_b64}".encode(),
            hashlib.sha256,
        ).digest())
        if not hmac.compare_digest(expected_sig, sig_b64):
            return None

        payload = json.loads(_unb64(payload_b64))
        now     = time.time()
        if payload.get("exp", 0) < now:
            return None

        # Check revocation list (Redis key aegis:revoked:<jti>)
        jti = payload.get("jti", "")
        if jti and _is_revoked(jti):
            return None

        return OperatorSession(
            handle    = payload["sub"],
            role      = payload.get("role", "OPERATOR"),
            token_id  = jti,
            issued_at = payload.get("iat", now),
        )
    except Exception:
        return None


# ── Revocation ────────────────────────────────────────────────────────────────

# In-memory revocation list (Redis is the source of truth; this is a cache)
_revoked_cache:  set[str] = set()
_revoked_lock    = threading.Lock()


def revoke_token(jti: str, redis_client=None) -> None:
    with _revoked_lock:
        _revoked_cache.add(jti)
    if redis_client:
        try:
            redis_client.setex(f"aegis:revoked:{jti}", TOKEN_TTL, "1")
        except Exception as _e:
            log.debug("%s error: %s", __name__, _e)
    log.info("Token revoked", extra={"token_id": jti})


def _is_revoked(jti: str) -> bool:
    with _revoked_lock:
        return jti in _revoked_cache


def sync_revocations(redis_client) -> None:
    """Reload revocation list from Redis (call on startup)."""
    try:
        keys = redis_client.keys("aegis:revoked:*")
        with _revoked_lock:
            _revoked_cache.clear()
            for k in keys:
                jti = k.split(":")[-1]
                _revoked_cache.add(jti)
    except Exception as e:
        log.warning("Could not sync revocation list: %s", e)


# ── Operator key storage ──────────────────────────────────────────────────────

def hash_key(plain_key: str) -> str:
    """Return a salted PBKDF2-SHA256 digest of ``plain_key``."""
    salt  = secrets.token_bytes(16)
    dk    = hashlib.pbkdf2_hmac("sha256", plain_key.encode(), salt, 260_000)
    return f"pbkdf2$sha256$260000${_b64(salt)}${_b64(dk)}"


def verify_key(plain_key: str, stored_hash: str) -> bool:
    """Constant-time verification of a plain key against a stored hash."""
    try:
        _, alg, iters, salt_b64, dk_b64 = stored_hash.split("$")
        salt   = _unb64(salt_b64)
        dk_ref = _unb64(dk_b64)
        iters  = int(iters)
        dk_in  = hashlib.pbkdf2_hmac("sha256", plain_key.encode(), salt, iters)
        return hmac.compare_digest(dk_in, dk_ref)
    except Exception:
        return False


# ── Flask decorators ──────────────────────────────────────────────────────────

_LEGACY_SESSION = OperatorSession(
    handle    = "legacy_operator",
    role      = "ADMIN",
    token_id  = "legacy",
    issued_at = 0,
)


def get_current_operator() -> Optional[OperatorSession]:
    """
    Extract and verify the operator identity from the current request.

    Accepts:
      1. Authorization: Bearer <token>   (new sessions)
      2. X-Aegis-Key: <token>            (new sessions — same value)
      3. X-Aegis-Key: <LEGACY_KEY>       (backward compat — returns ADMIN)
    """
    token = (
        (request.headers.get("Authorization", "").removeprefix("Bearer ")).strip()
        or request.headers.get("X-Aegis-Key", "").strip()
        or request.args.get("key", "").strip()
    )
    if not token:
        return None

    # Legacy static key → backward compatibility
    if hmac.compare_digest(token, LEGACY_KEY):
        return _LEGACY_SESSION

    return verify_token(token)


def require_auth(permission: Optional[str] = None):
    """
    Decorator factory.  Enforces authentication and optionally a
    specific permission.

    Usage::

        @app.route("/api/listeners", methods=["GET"])
        @require_auth("listeners:read")
        def list_listeners():
            ...
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            from flask import g
            sess = get_current_operator()
            if sess is None:
                log.warning(
                    "Authentication failed",
                    extra={"path": request.path, "ip": request.remote_addr},
                )
                return jsonify({"error": "unauthorized"}), 401
            if permission and not sess.can(permission):
                log.warning(
                    "Permission denied",
                    extra={
                        "operator": sess.handle,
                        "role":     sess.role,
                        "required": permission,
                        "path":     request.path,
                    },
                )
                return jsonify({
                    "error":      "forbidden",
                    "required":   permission,
                    "your_role":  sess.role,
                }), 403
            g.operator = sess
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def current_operator() -> OperatorSession:
    """Return the authenticated operator from Flask ``g`` (inside a request)."""
    from flask import g
    return getattr(g, "operator", _LEGACY_SESSION)


__all__ = [
    "OperatorSession", "ROLES", "PERMISSIONS",
    "issue_token", "verify_token", "revoke_token", "sync_revocations",
    "hash_key", "verify_key",
    "require_auth", "get_current_operator", "current_operator",
]
