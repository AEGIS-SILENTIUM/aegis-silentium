#!/usr/bin/env python3
"""
AEGIS-SILENTIUM Operator Dashboard v12.0
Fully functional — all data fetched live from C2 API.
"""

import os, json, time, functools, threading, secrets, hashlib, logging
from collections import defaultdict

from flask import Flask, Response, request, jsonify
from flask_cors import CORS

try:
    import requests as _requests; HAS_REQUESTS = True
except ImportError:
    _requests = None; HAS_REQUESTS = False

try:
    import redis as _redis_lib; HAS_REDIS_LIB = True
except ImportError:
    _redis_lib = None; HAS_REDIS_LIB = False

log = logging.getLogger("dashboard")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

C2_URL          = os.environ.get("C2_URL",          "http://c2:5000")
# SECURITY: no default - must be set explicitly
_raw_op_key = os.environ.get("OPERATOR_KEY", "")
if not _raw_op_key:
    import logging as _dlog, sys as _dsys
    _dlog.getLogger("aegis.dashboard").critical(
        "OPERATOR_KEY not set — dashboard cannot authenticate to C2. "
        "Set the OPERATOR_KEY environment variable and restart."
    )
    _dsys.exit(1)
if len(_raw_op_key) < 32 or _raw_op_key in ("aegis-operator-key-2026", "changeme", "default"):
    import logging as _dlog, sys as _dsys
    _dlog.getLogger("aegis.dashboard").critical(
        "OPERATOR_KEY is a placeholder or too short — "
        "generate with: openssl rand -hex 32"
    )
    _dsys.exit(1)
OP_KEY = _raw_op_key
REDIS_HOST      = os.environ.get("REDIS_HOST",      "redis")
REDIS_PASS      = os.environ.get("REDIS_PASSWORD",  "")
REDIS_PORT      = int(os.environ.get("REDIS_PORT",  "6379"))
_raw_origins = os.environ.get("ALLOWED_ORIGINS", "")
if _raw_origins == "*":
    import logging as _olog
    _olog.getLogger("aegis.dashboard").warning(
        "ALLOWED_ORIGINS=* is wildcard — restrict to specific origins in production"
    )
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()] if _raw_origins else []

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app, origins=ALLOWED_ORIGINS)

R = None; HAS_REDIS = False
if HAS_REDIS_LIB:
    try:
        _rkw = dict(host=REDIS_HOST, port=REDIS_PORT, db=0,
                    decode_responses=True, socket_connect_timeout=2)
        if REDIS_PASS: _rkw["password"] = REDIS_PASS
        R = _redis_lib.Redis(**_rkw)
        R.ping(); HAS_REDIS = True
        log.info("Redis connected at %s:%s", REDIS_HOST, REDIS_PORT)
    except Exception as exc:
        log.warning("Redis unavailable: %s", exc)

_rate_buckets: dict = defaultdict(lambda: {"count": 0, "reset": 0.0})
_rate_lock = threading.Lock()

def _rate_ok(key: str, limit: int = 180, window: int = 60) -> bool:
    now = time.time()
    with _rate_lock:
        b = _rate_buckets[key]
        if now > b["reset"]: b["count"] = 0; b["reset"] = now + window
        b["count"] += 1
        return b["count"] <= limit

@app.after_request
def _sec_headers(resp: Response) -> Response:
    resp.headers.update({
        "X-Frame-Options":        "DENY",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection":       "1; mode=block",
        "Referrer-Policy":        "no-referrer",
        "Permissions-Policy":     "geolocation=(), microphone=(), camera=()",
        "Content-Security-Policy": (
            "default-src 'self'; "
            # Scripts: self only — no unsafe-inline. Use nonces for inline scripts if needed.
            "script-src 'self' cdn.jsdelivr.net; "
            # Styles: self + specific CDN (no unsafe-inline)
            "style-src 'self' fonts.googleapis.com fonts.gstatic.com cdn.jsdelivr.net; "
            "font-src 'self' fonts.gstatic.com data:; "
            "img-src 'self' data: blob:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none'"
        ),
    })
    return resp

def require_key(f):
    @functools.wraps(f)
    def _wrap(*args, **kwargs):
        key = (request.headers.get("X-Aegis-Key")
               or request.args.get("key")
               or request.cookies.get("aegis_key"))
        if not key or key != OP_KEY:
            return jsonify({"error": "unauthorized"}), 401
        k_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        if not _rate_ok(k_hash):
            return jsonify({"error": "rate limit exceeded"}), 429
        return f(*args, **kwargs)
    return _wrap

def _strip_headers() -> dict:
    _STRIP = frozenset({"host","content-length","connection","transfer-encoding",
                        "cookie","authorization","x-forwarded-for","x-real-ip"})
    hdrs = {k: v for k, v in request.headers if k.lower() not in _STRIP}
    hdrs["X-Aegis-Key"] = OP_KEY
    return hdrs

def _c2_get(path: str) -> dict:
    if not HAS_REQUESTS or _requests is None: return {}
    try:
        r = _requests.get(C2_URL + path, headers={"X-Aegis-Key": OP_KEY}, timeout=3)
        return r.json() if r.ok else {}
    except Exception: return {}


# Read the HTML template from a separate file
_HERE = os.path.dirname(os.path.abspath(__file__))
_HTML_PATH = os.path.join(_HERE, "dashboard.html")

def _load_html():
    try:
        with open(_HTML_PATH, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>dashboard.html not found</h1>"

@app.route("/")
def index():
    return _load_html()

@app.route("/health")
def health():
    key = (request.headers.get("X-Aegis-Key")
           or request.args.get("key")
           or request.cookies.get("aegis_key"))
    if not key or key != OP_KEY:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"status": "ok", "redis": HAS_REDIS, "c2_url": C2_URL, "ts": int(time.time())})

@app.route("/stream")
@require_key
def sse_stream():
    def generate():
        ps = None
        if HAS_REDIS and R is not None:
            try:
                ps = R.pubsub()
                ps.subscribe("aegis_events", "beacon_in", "mesh",
                             "vuln_found", "exfil_received")
            except Exception as exc:
                log.warning("pubsub subscribe failed: %s", exc)
                ps = None
        yield "retry: 2000\n\n"
        last_ping = time.time()
        try:
            while True:
                if HAS_REDIS and ps is not None:
                    try:
                        msg = ps.get_message(ignore_subscribe_messages=True, timeout=0.8)
                        if msg and msg.get("data"):
                            yield "data: {}\n\n".format(msg["data"])
                    except Exception:
                        time.sleep(0.5)
                now = time.time()
                if now - last_ping > 12:
                    try:
                        stats = _c2_get("/api/stats")
                        yield "data: {}\n\n".format(json.dumps({
                            "event_type": "heartbeat", "ts": int(now), **stats}))
                    except Exception:
                        yield ": ping\n\n"
                    last_ping = time.time()
                else:
                    if not HAS_REDIS or ps is None:
                        time.sleep(1.0)
        except GeneratorExit:
            if ps is not None:
                try: ps.unsubscribe(); ps.close()
                except Exception as _e: log.debug("suppressed exception: %s", _e)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache, no-transform",
                             "X-Accel-Buffering": "no", "Connection": "keep-alive"})

@app.route("/api/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@require_key
def proxy_c2(path: str):
    if not HAS_REQUESTS or _requests is None:
        return jsonify({"error": "requests library not available"}), 503
    url    = "{}/api/{}".format(C2_URL, path)
    params = dict(request.args)
    hdrs   = _strip_headers()
    try:
        if request.method == "GET":
            r = _requests.get(url, headers=hdrs, params=params, timeout=20)
        else:
            r = _requests.request(request.method, url, headers=hdrs,
                                  data=request.get_data(), params=params, timeout=20)
        return Response(r.content, status=r.status_code,
                        content_type=r.headers.get("Content-Type", "application/json"))
    except _requests.exceptions.Timeout:
        return jsonify({"error": "C2 request timed out"}), 504
    except Exception as exc:
        return jsonify({"error": str(exc), "detail": "C2 unreachable at " + C2_URL}), 502

if __name__ == "__main__":
    log.info("Starting dashboard on 0.0.0.0:7331")
    app.run(host="0.0.0.0", port=7331, debug=False, threaded=True)
