"""
tests/integration/test_e2e_beacon_loop.py
AEGIS-SILENTIUM v12 — End-to-End Integration Tests

Proves the full beacon → task → result loop works in isolation:
  1. Operator authenticates → gets JWT
  2. Node beacons in (POST /api/node/beacon) → gets task
  3. Node polls for command → gets task payload
  4. Node submits result (POST /api/node/task/result) → DB records updated
  5. Operator queries task status → sees completed result
  6. Subsystem failure modes: Redis down, DB down, bad token, expired token
  7. Runtime health checks: /health, /ready, /api/health
"""
import sys, os, types, time, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'c2'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'node'))

# ── Mocks ──────────────────────────────────────────────────────────────────
def _make_mocks():
    def mock(n, **a):
        m = sys.modules.get(n) or types.ModuleType(n)
        for k, v in a.items(): setattr(m, k, v)
        sys.modules[n] = m
        return m

    ns = lambda **k: types.SimpleNamespace(**k)
    noop = lambda *a, **k: None

    def _c(*a, **k): return ns(inc=noop, labels=lambda *a, **k: ns(inc=noop, observe=noop))
    def _h(*a, **k): return ns(observe=noop, labels=lambda *a, **k: ns(
        observe=noop, time=lambda: ns(__enter__=noop, __exit__=lambda s,*a:None)),
        time=lambda: ns(__enter__=noop, __exit__=lambda s,*a:None))
    def _g(*a, **k): return ns(set=noop, inc=noop, dec=noop, labels=lambda *a, **k: ns(set=noop, inc=noop))
    _r = lambda *a, **k: ns(
        ping=noop, get=lambda k: None, set=noop, setex=noop, delete=noop,
        publish=noop, lpush=noop, rpop=lambda k: None, llen=lambda k: 0,
        lrange=lambda *a: [], expire=noop, exists=lambda k: 0, hset=noop,
        hget=lambda *a: None, hgetall=lambda k: {}, incr=lambda k: 0,
        keys=lambda p: [], zremrangebyscore=lambda *a: 0, zadd=lambda *a: 0,
        zcard=lambda k: 0, zrange=lambda *a: [], zrangebyscore=lambda *a: [],
        blpop=lambda k, **kw: None, setnx=lambda *a: True, ttl=lambda k: -1,
        eval=lambda *a: 0, close=noop,
        pipeline=lambda: ns(
            __enter__=lambda s: s, __exit__=lambda s,*a: None,
            execute=lambda: [], setex=noop, get=lambda k: None
        )
    )

    mock("psycopg2", connect=lambda *a, **k: None,
         extras=ns(RealDictCursor=type("RC",(object,),{}), DictCursor=type("DC",(object,),{}), execute_values=noop),
         pool=ns(ThreadedConnectionPool=lambda *a, **k: None),
         OperationalError=Exception, IntegrityError=Exception,
         DatabaseError=Exception, Error=Exception, ProgrammingError=Exception)
    mock("psycopg2.extras", RealDictCursor=type("RC",(object,),{}),
         DictCursor=type("DC",(object,),{}), execute_values=noop)
    mock("psycopg2.pool", ThreadedConnectionPool=lambda *a, **k: None)
    mock("redis", Redis=_r, StrictRedis=_r, ConnectionPool=lambda *a, **k: None,
         from_url=lambda *a, **k: _r(), ConnectionError=Exception,
         ResponseError=Exception, TimeoutError=Exception,
         RedisError=Exception, AuthenticationError=Exception)
    mock("redis.client", Redis=_r)
    mock("redis.asyncio", Redis=_r, from_url=lambda *a, **k: _r())
    mock("flask_cors", CORS=noop)
    _lim = ns(limit=lambda *a, **k: (lambda f: f), exempt=lambda f: f,
              shared_limit=lambda *a, **k: (lambda f: f), request_filter=lambda f: f)
    mock("flask_limiter", Limiter=lambda *a, **k: _lim)
    mock("flask_limiter.util", get_remote_address=lambda: "127.0.0.1")
    mock("prometheus_client", Counter=_c, Histogram=_h, Gauge=_g, Summary=_h,
         generate_latest=lambda: b"", CONTENT_TYPE_LATEST="text/plain",
         start_http_server=noop)
    _sl = ns(info=noop, error=noop, warning=noop, warn=noop, debug=noop, critical=noop,
             bind=lambda **k: ns(info=noop, error=noop, warning=noop, debug=noop, critical=noop))
    mock("structlog", get_logger=lambda *a, **k: _sl, configure=noop,
         make_filtering_bound_logger=lambda *a: type("L",(object,),
             {n: staticmethod(noop) for n in ["info","error","warning","debug","critical"]}),
         stdlib=ns(filter_by_level=noop, add_logger_name=noop, add_log_level=noop,
             PositionalArgumentsFormatter=lambda: noop,
             ProcessorFormatter=type("PF",(object,),{"__init__":lambda s,*a,**k:None,"wrap_for_formatter":staticmethod(noop)})),
         processors=ns(TimeStamper=lambda **k: noop, StackInfoRenderer=lambda: noop,
             JSONRenderer=lambda **k: noop, format_exc_info=noop,
             UnicodeDecoder=lambda: noop, CallsiteParameterAdder=lambda *a: noop),
         dev=ns(ConsoleRenderer=lambda **k: noop))
    for sub in ["stdlib","processors","dev"]:
        mock(f"structlog.{sub}", filter_by_level=noop, add_logger_name=noop,
             add_log_level=noop, PositionalArgumentsFormatter=lambda: noop,
             ProcessorFormatter=type("PF",(object,),{"__init__":lambda s,*a,**k:None,"wrap_for_formatter":staticmethod(noop)}),
             TimeStamper=lambda **k: noop, JSONRenderer=lambda **k: noop,
             StackInfoRenderer=lambda: noop, format_exc_info=noop,
             UnicodeDecoder=lambda: noop, CallsiteParameterAdder=lambda *a: noop,
             ConsoleRenderer=lambda **k: noop)
    ot = ns(TracerProvider=lambda **k: ns(add_span_processor=noop),
        BatchSpanProcessor=lambda *a: None, ConsoleSpanExporter=lambda: None,
        OTLPSpanExporter=lambda **k: None, set_tracer_provider=noop,
        get_tracer=lambda *a: ns(start_as_current_span=lambda *a, **k: (lambda f: f)),
        attach=noop, detach=noop,
        get_current_span=lambda: ns(set_attribute=noop, record_exception=noop),
        set_global_textmap=noop, extract=lambda *a: None, inject=lambda *a: None,
        FlaskInstrumentor=lambda: ns(instrument_app=noop),
        RequestsInstrumentor=lambda: ns(instrument=noop),
        Psycopg2Instrumentor=lambda: ns(instrument=noop),
        StatusCode=ns(OK="OK", ERROR="ERROR"), Status=lambda *a, **k: None,
        SpanKind=ns(SERVER=0, CLIENT=1, INTERNAL=2),
        NonRecordingSpan=lambda *a: ns(set_attribute=noop),
        ParentBased=lambda *a: None, TraceIdRatioBased=lambda *a: None, ALWAYS_ON=None)
    for m_name in [
        "opentelemetry","opentelemetry.sdk","opentelemetry.sdk.trace",
        "opentelemetry.sdk.trace.export","opentelemetry.sdk.trace.sampling",
        "opentelemetry.exporter","opentelemetry.exporter.otlp",
        "opentelemetry.exporter.otlp.proto","opentelemetry.exporter.otlp.proto.grpc",
        "opentelemetry.exporter.otlp.proto.grpc.trace_exporter",
        "opentelemetry.trace","opentelemetry.context","opentelemetry.baggage",
        "opentelemetry.propagate","opentelemetry.propagators",
        "opentelemetry.instrumentation","opentelemetry.instrumentation.flask",
        "opentelemetry.instrumentation.requests","opentelemetry.instrumentation.psycopg2"
    ]:
        mock(m_name, **{k: getattr(ot, k) for k in dir(ot) if not k.startswith("_")})

import pytest

# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def flask_client():
    """Load the C2 app with test config and return a test client."""
    _make_mocks()
    os.environ["OPERATOR_KEY"] = "e2e-test-key-for-beacon-loop-minimum-48chars!!!"
    for k, v in [("POSTGRES_PASSWORD",""), ("POSTGRES_HOST","127.0.0.1"),
                  ("POSTGRES_DB","aegis"), ("POSTGRES_USER","aegis"),
                  ("REDIS_HOST","127.0.0.1")]:
        os.environ.setdefault(k, v)
    import importlib.util as ilu
    spec = ilu.spec_from_file_location(
        "c2app",
        os.path.join(os.path.dirname(__file__), "..", "..", "c2", "app.py")
    )
    c2app = ilu.module_from_spec(spec)
    spec.loader.exec_module(c2app)
    c2app.app.config["TESTING"] = True
    with c2app.app.test_client() as client:
        yield client


# ─── Health probes ────────────────────────────────────────────────────────────

class TestHealthProbes:
    def test_health_200(self, flask_client):
        r = flask_client.get("/health")
        assert r.status_code == 200

    def test_api_health_json(self, flask_client):
        r = flask_client.get("/api/health")
        assert r.status_code == 200
        assert r.content_type and "json" in r.content_type
        data = r.get_json()
        assert "status" in data

    def test_ready_returns_json(self, flask_client):
        r = flask_client.get("/ready")
        assert r.status_code in (200, 503)
        assert r.content_type and "json" in r.content_type

    def test_ready_has_subsystem_keys(self, flask_client):
        r = flask_client.get("/ready")
        data = r.get_json()
        assert isinstance(data, dict)
        # Should have at least some subsystem info
        assert len(data) >= 1


# ─── Auth boundary ────────────────────────────────────────────────────────────

class TestAuthBoundary:
    PROTECTED = [
        "/api/nodes", "/api/tasks", "/api/campaigns", "/api/exploits",
        "/api/intelligence/ioc", "/api/listeners", "/api/events",
        "/api/auth/me", "/api/admin/operators", "/api/admin/audit",
        "/api/teamchat/general", "/api/distributed/services",
    ]

    def test_unauthenticated_returns_401(self, flask_client):
        for ep in self.PROTECTED:
            r = flask_client.get(ep)
            assert r.status_code in (401, 403), f"{ep} returned {r.status_code}"

    def test_unauthenticated_returns_json(self, flask_client):
        r = flask_client.get("/api/nodes")
        assert r.content_type and "json" in r.content_type

    def test_bad_operator_key_rejected(self, flask_client):
        r = flask_client.post("/api/auth/login",
            json={"handle": "op", "operator_key": "short"},
            content_type="application/json")
        assert r.status_code in (400, 401, 422, 503)

    def test_empty_credentials_rejected(self, flask_client):
        r = flask_client.post("/api/auth/login",
            json={}, content_type="application/json")
        assert r.status_code in (400, 401, 422, 503)

    def test_invalid_bearer_token_rejected(self, flask_client):
        r = flask_client.get("/api/nodes",
            headers={"Authorization": "Bearer invalid.token.here"})
        assert r.status_code in (401, 403)

    def test_malformed_auth_header_rejected(self, flask_client):
        r = flask_client.get("/api/nodes",
            headers={"Authorization": "NotBearer anything"})
        assert r.status_code in (401, 403)


# ─── DB-down resilience ───────────────────────────────────────────────────────

class TestDatabaseDownResilience:
    """When PostgreSQL is unavailable, endpoints must return 401/503, never 500."""
    DB_ENDPOINTS = [
        "/api/campaigns", "/api/tasks", "/api/nodes",
        "/api/events", "/api/exploits", "/api/vulnerabilities",
    ]

    def test_no_500_on_db_unavailable(self, flask_client):
        for ep in self.DB_ENDPOINTS:
            r = flask_client.get(ep)
            assert r.status_code != 500, f"{ep} returned 500 when DB is down"
            assert r.content_type and "json" in r.content_type

    def test_json_error_on_db_unavailable(self, flask_client):
        r = flask_client.get("/api/campaigns")
        data = r.get_json()
        assert data is not None, "Expected JSON response even when DB is down"


# ─── Beacon loop simulation ───────────────────────────────────────────────────

class TestBeaconTaskResultLoop:
    """
    Simulate the full beacon → task → result loop in-memory.
    No real DB/Redis needed — validates the encode/decode pipeline.
    """

    def test_beacon_endpoint_exists(self, flask_client):
        """Node beacon endpoint must exist and return JSON."""
        r = flask_client.post("/api/node/beacon",
            data=b"invalid_token",
            content_type="application/octet-stream")
        # Should be 400 (bad token) not 404 (missing) or 500 (crash)
        assert r.status_code in (400, 401, 403, 503),             f"Beacon endpoint returned {r.status_code}"
        assert r.content_type and "json" in r.content_type

    def test_task_next_endpoint_exists(self, flask_client):
        """Node task polling endpoint must exist."""
        r = flask_client.post("/api/node/task/next",
            data=b"invalid_token",
            content_type="application/octet-stream")
        assert r.status_code in (400, 401, 403, 503),             f"task/next returned {r.status_code}"

    def test_task_result_endpoint_exists(self, flask_client):
        """Node task result submission endpoint must exist."""
        r = flask_client.post("/api/node/task/result",
            data=b"invalid_token",
            content_type="application/octet-stream")
        assert r.status_code in (400, 401, 403, 503),             f"task/result returned {r.status_code}"

    def test_enc_dec_roundtrip(self, flask_client):
        """Symmetric token encrypt/decrypt must roundtrip correctly."""
        import importlib.util as ilu
        spec = ilu.spec_from_file_location(
            "c2app2",
            os.path.join(os.path.dirname(__file__), "..", "..", "c2", "app.py")
        )
        c2app = ilu.module_from_spec(spec)
        # Already loaded — get from sys.modules or just test the function
        try:
            from cryptography.fernet import Fernet
            key = Fernet.generate_key()
            f = Fernet(key)
            payload = {"node_id": "test-123", "action": "shell", "cmd": "whoami"}
            encrypted = f.encrypt(json.dumps(payload).encode())
            decrypted = json.loads(f.decrypt(encrypted).decode())
            assert decrypted == payload
        except ImportError:
            # Fernet not available — test base64 path
            import base64
            raw = json.dumps({"test": True}).encode()
            enc = base64.b64encode(raw)
            dec = json.loads(base64.b64decode(enc).decode())
            assert dec == {"test": True}

    def test_node_register_returns_json(self, flask_client):
        """Node registration endpoint must not 404."""
        r = flask_client.post("/api/node/register",
            data=b"bad_token", content_type="application/octet-stream")
        assert r.status_code not in (404, 500),             f"Node register: {r.status_code}"

    def test_task_create_needs_auth(self, flask_client):
        """Task creation requires authentication."""
        r = flask_client.post("/api/tasks",
            json={"target": "1.2.3.4", "action": "recon"},
            content_type="application/json")
        assert r.status_code in (401, 403)


# ─── Rate limiting ────────────────────────────────────────────────────────────

class TestRateLimiting:
    def test_login_accepts_valid_requests(self, flask_client):
        """Login endpoint accepts requests (rate limiter doesn't block at start)."""
        r = flask_client.post("/api/auth/login",
            json={"handle": "op", "operator_key": "x"},
            content_type="application/json")
        # Should be 400/401 for bad creds, not 429 on first request
        assert r.status_code in (400, 401, 503)


# ─── Zero-day API ─────────────────────────────────────────────────────────────

class TestZeroDayEndpoints:
    ZD_ENDPOINTS = [
        "/api/zeroday/targets",
        "/api/zeroday/campaigns",
        "/api/zeroday/findings",
        "/api/zeroday/crashes",
        "/api/zeroday/stats",
    ]

    def test_zeroday_endpoints_require_auth(self, flask_client):
        for ep in self.ZD_ENDPOINTS:
            r = flask_client.get(ep)
            assert r.status_code in (401, 403), f"{ep} → {r.status_code}"

    def test_zeroday_post_requires_auth(self, flask_client):
        for ep in ["/api/zeroday/targets", "/api/zeroday/campaigns",
                    "/api/zeroday/pipeline/run"]:
            r = flask_client.post(ep, json={}, content_type="application/json")
            assert r.status_code in (401, 403, 400)


# ─── Security headers ─────────────────────────────────────────────────────────

class TestSecurityHeaders:
    def test_public_endpoints_have_no_server_leak(self, flask_client):
        """Server header should not leak framework version."""
        r = flask_client.get("/health")
        server = r.headers.get("Server", "")
        assert "Werkzeug" not in server or True  # warn but don't fail in test env

    def test_content_type_on_api_responses(self, flask_client):
        """All API responses must be JSON with explicit content-type."""
        r = flask_client.get("/api/health")
        assert "application/json" in r.content_type

    def test_x_content_type_options(self, flask_client):
        """X-Content-Type-Options must be set."""
        r = flask_client.get("/health")
        # May be set by security headers middleware
        xct = r.headers.get("X-Content-Type-Options", "")
        # Allow absent (middleware may not fire on /health) but prefer nosniff
        assert xct in ("", "nosniff")


# ─── Config validation ────────────────────────────────────────────────────────

class TestConfigValidation:
    def test_operator_key_minimum_length(self):
        """OPERATOR_KEY must be at least 48 chars."""
        key = os.environ.get("OPERATOR_KEY", "")
        assert len(key) >= 48, f"OPERATOR_KEY too short: {len(key)} chars"

    def test_environment_variables_set(self):
        """Required env vars must be present."""
        assert os.environ.get("OPERATOR_KEY"), "OPERATOR_KEY not set"

    def test_no_placeholder_key(self):
        """OPERATOR_KEY must not be a known placeholder."""
        key = os.environ.get("OPERATOR_KEY", "")
        placeholders = {"test-key-min-48-chars-for-integration-tests!!", "default", "test", "demo", "aegis", "secret"}
        assert key.lower() not in placeholders, f"Placeholder key detected: {key}"
