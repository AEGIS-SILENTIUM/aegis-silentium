"""
AEGIS-Advanced Shared Utilities Package
=========================================
Network helpers, URL parsing, IP enumeration, target validation,
rate limiting, retry logic, data formatting, logging, user-agent
rotation, and general-purpose utilities used across the framework.
"""
import os
import re
import sys
import time
import socket
import struct
import ipaddress
import hashlib
import random
import urllib.parse
import logging
import threading
from typing import List, Optional, Iterator, Tuple, Dict, Union
from datetime import datetime, timezone


# ══════════════════════════════════════════════
# Logging
# ══════════════════════════════════════════════

def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Create a colored, timestamped logger."""
    log = logging.getLogger("aegis." + name)
    if not log.handlers:
        h = logging.StreamHandler(sys.stdout)
        fmt = logging.Formatter(
            "%(asctime)s [%(name)s] %(levelname)s %(message)s",
            datefmt="%H:%M:%S")
        h.setFormatter(fmt)
        log.addHandler(h)
    log.setLevel(getattr(logging, level.upper(), logging.INFO))
    return log


# ══════════════════════════════════════════════
# URL / target helpers
# ══════════════════════════════════════════════

def normalize_url(url: str) -> str:
    """Ensure URL has scheme and no trailing slash."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def extract_domain(url: str) -> str:
    """Extract hostname from URL."""
    try:
        return urllib.parse.urlparse(normalize_url(url)).netloc.split(":")[0]
    except Exception:
        return url


def is_valid_url(url: str) -> bool:
    """Check if string is a valid HTTP(S) URL."""
    try:
        p = urllib.parse.urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def is_valid_ip(s: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_valid_cidr(s: str) -> bool:
    """Check if string is a valid CIDR block."""
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def expand_cidr(cidr: str) -> List[str]:
    """Expand a CIDR block to list of IP strings (max 65536)."""
    try:
        net  = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
        if len(hosts) > 65536:
            hosts = hosts[:65536]
        return [str(h) for h in hosts]
    except ValueError:
        return [cidr]


def parse_target(target: str) -> List[str]:
    """
    Parse target string which may be:
    - URL: https://example.com
    - IP: 192.168.1.1
    - CIDR: 10.0.0.0/24
    - Host: example.com
    - Range: 10.0.0.1-10.0.0.50
    Returns list of targets.
    """
    target = target.strip()

    # IP range: 10.0.0.1-10.0.0.50
    m = re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d+)-(\d+)$", target)
    if m:
        prefix = m.group(1)
        start  = int(m.group(2))
        end    = int(m.group(3))
        return ["{}.{}".format(prefix, i) for i in range(start, end + 1)]

    # CIDR
    if is_valid_cidr(target) and "/" in target:
        return expand_cidr(target)

    # URL with comma-separated
    if "," in target:
        return [t.strip() for t in target.split(",") if t.strip()]

    return [target]


def url_join(base: str, path: str) -> str:
    """Join base URL and path handling edge cases."""
    base = base.rstrip("/")
    path = path.lstrip("/")
    return "{}/{}".format(base, path) if path else base


def get_url_params(url: str) -> Dict[str, str]:
    """Extract query parameters from URL."""
    try:
        qs = urllib.parse.urlparse(url).query
        return dict(urllib.parse.parse_qsl(qs))
    except Exception:
        return {}


def replace_url_params(url: str, params: Dict[str, str]) -> str:
    """Replace/add query parameters in a URL."""
    parsed  = urllib.parse.urlparse(url)
    existing= dict(urllib.parse.parse_qsl(parsed.query))
    existing.update(params)
    new_qs  = urllib.parse.urlencode(existing)
    return urllib.parse.urlunparse(parsed._replace(query=new_qs))


# ══════════════════════════════════════════════
# Network helpers
# ══════════════════════════════════════════════

def resolve_host(hostname: str, timeout: float = 3.0) -> Optional[str]:
    """Resolve hostname to IP. Returns None on failure."""
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        result = socket.gethostbyname(hostname)
        socket.setdefaulttimeout(old)
        return result
    except Exception:
        return None


def reverse_lookup(ip: str, timeout: float = 3.0) -> Optional[str]:
    """Reverse DNS lookup for an IP."""
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        result = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(old)
        return result
    except Exception:
        return None


def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """TCP connect check."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False


def scan_ports(host: str, ports: List[int],
               timeout: float = 1.5,
               max_threads: int = 50) -> Dict[int, bool]:
    """Scan a list of ports concurrently. Returns {port: is_open}."""
    results   = {}
    lock      = threading.Lock()
    sem       = threading.Semaphore(max_threads)

    def _check(p: int):
        with sem:
            open_ = is_port_open(host, p, timeout)
            with lock:
                results[p] = open_

    threads = [threading.Thread(target=_check, args=(p,)) for p in ports]
    for t in threads: t.start()
    for t in threads: t.join()
    return results


def get_local_ip() -> str:
    """Get primary local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_external_ip(timeout: int = 5) -> str:
    """Fetch external/public IP."""
    import urllib.request, ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    for svc in ["https://api.ipify.org", "https://ifconfig.me",
                 "https://ipecho.net/plain", "https://icanhazip.com"]:
        try:
            req  = urllib.request.Request(svc, headers={"User-Agent": "curl/7.0"})
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
                return r.read().decode().strip()[:45]
        except Exception as _exc:
            log.debug("get_external_ip: %s", _exc)
    return "unknown"


# ══════════════════════════════════════════════
# Rate limiter
# ══════════════════════════════════════════════

class RateLimiter:
    """Token-bucket rate limiter."""

    def __init__(self, rate: float = 10.0, burst: int = 20):
        """
        rate: tokens per second
        burst: max bucket capacity
        """
        self._rate     = rate
        self._burst    = burst
        self._tokens   = float(burst)
        self._last     = time.monotonic()
        self._lock     = threading.Lock()

    def acquire(self, tokens: float = 1.0, block: bool = True) -> bool:
        """Consume tokens. If block=True, sleeps until available."""
        while True:
            with self._lock:
                now   = time.monotonic()
                delta = now - self._last
                self._tokens = min(self._burst,
                                    self._tokens + delta * self._rate)
                self._last   = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return True
            if not block:
                return False
            time.sleep(1.0 / self._rate)

    def __call__(self, tokens: float = 1.0):
        return self.acquire(tokens)


# ══════════════════════════════════════════════
# Retry with backoff
# ══════════════════════════════════════════════

def retry(fn, attempts: int = 3, delay: float = 1.0,
           backoff: float = 2.0, exceptions=(Exception,)):
    """
    Retry fn up to `attempts` times with exponential backoff.
    Returns result or raises last exception.
    """
    last_exc = None
    for i in range(attempts):
        try:
            return fn()
        except exceptions as e:
            last_exc = e
            if i < attempts - 1:
                time.sleep(delay * (backoff ** i))
    raise last_exc


# ══════════════════════════════════════════════
# User-agent rotation
# ══════════════════════════════════════════════

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:109.0) Gecko/114.0 Firefox/119.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "curl/8.4.0",
    "python-requests/2.31.0",
]

def random_ua() -> str:
    """Return a random user-agent string."""
    return random.choice(USER_AGENTS)


# ══════════════════════════════════════════════
# Data formatting
# ══════════════════════════════════════════════

def human_size(n: int) -> str:
    """Format byte count as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024.0:
            return "{:.1f} {}".format(n, unit)
        n /= 1024.0
    return "{:.1f} PB".format(n)


def human_duration(seconds: float) -> str:
    """Format seconds as human-readable duration."""
    if seconds < 1:
        return "{:.0f}ms".format(seconds * 1000)
    if seconds < 60:
        return "{:.1f}s".format(seconds)
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return "{}h{}m{}s".format(h, m, s)
    return "{}m{}s".format(m, s)


def truncate(s: str, max_len: int = 100, suffix: str = "…") -> str:
    """Truncate string to max_len chars."""
    if len(s) <= max_len:
        return s
    return s[:max_len - len(suffix)] + suffix


def strip_ansi(s: str) -> str:
    """Remove ANSI escape codes from string."""
    return re.sub(r"\x1b\[[0-9;]*[mGKHF]", "", s)


def safe_json(obj) -> str:
    """JSON-serialize object with fallback for non-serializable types."""
    import json

    def default(o):
        if isinstance(o, bytes):
            import base64
            return base64.b64encode(o).decode()
        if hasattr(o, "__dict__"):
            return {k: v for k, v in o.__dict__.items() if not k.startswith("_")}
        return str(o)

    return json.dumps(obj, default=default, indent=2)


def flatten_dict(d: dict, sep: str = ".", prefix: str = "") -> dict:
    """Flatten nested dict: {'a': {'b': 1}} → {'a.b': 1}"""
    out = {}
    for k, v in d.items():
        key = (prefix + sep + str(k)) if prefix else str(k)
        if isinstance(v, dict):
            out.update(flatten_dict(v, sep, key))
        else:
            out[key] = v
    return out


# ══════════════════════════════════════════════
# Hashing helpers
# ══════════════════════════════════════════════

def hash_target(target: str) -> str:
    """Generate a consistent short hash for a target URL."""
    return hashlib.sha256(target.encode()).hexdigest()[:12]


def fingerprint(data: bytes) -> str:
    """SHA-256 fingerprint as hex."""
    return hashlib.sha256(data).hexdigest()


# ══════════════════════════════════════════════
# Environment helpers
# ══════════════════════════════════════════════

def env(key: str, default: str = "") -> str:
    """Get env var with default."""
    return os.environ.get(key, default)


def env_int(key: str, default: int = 0) -> int:
    """Get env var as int."""
    try:
        return int(os.environ.get(key, str(default)))
    except (ValueError, TypeError):
        return default


def env_bool(key: str, default: bool = False) -> bool:
    """Get env var as bool (true/yes/1)."""
    v = os.environ.get(key, "")
    if v.lower() in ("1", "true", "yes", "on"):
        return True
    if v.lower() in ("0", "false", "no", "off"):
        return False
    return default


def require_env(key: str) -> str:
    """Get env var or raise."""
    v = os.environ.get(key)
    if v is None:
        raise EnvironmentError("Required environment variable '{}' not set".format(key))
    return v


# ══════════════════════════════════════════════
# Chunking
# ══════════════════════════════════════════════

def chunks(lst: list, n: int) -> Iterator[list]:
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def batched(items: list, batch_size: int, delay: float = 0.0) -> Iterator[list]:
    """Yield batches with optional inter-batch delay."""
    for batch in chunks(items, batch_size):
        yield batch
        if delay > 0:
            time.sleep(delay)


# ══════════════════════════════════════════════
# Timestamp helpers
# ══════════════════════════════════════════════

def utcnow() -> str:
    """ISO 8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def epoch() -> int:
    """Current Unix timestamp as int."""
    return int(time.time())


def since(ts: float) -> float:
    """Seconds elapsed since timestamp."""
    return time.time() - ts


# ══════════════════════════════════════════════
# Thread-safe counter
# ══════════════════════════════════════════════

class Counter:
    def __init__(self, start: int = 0):
        self._v    = start
        self._lock = threading.Lock()

    def increment(self, by: int = 1) -> int:
        with self._lock:
            self._v += by
            return self._v

    def get(self) -> int:
        with self._lock:
            return self._v

    def reset(self) -> int:
        with self._lock:
            v, self._v = self._v, 0
            return v


# ══════════════════════════════════════════════
# Progress bar (no deps)
# ══════════════════════════════════════════════

class Progress:
    """Simple terminal progress bar."""

    def __init__(self, total: int, label: str = "",
                  width: int = 40, stream=sys.stderr):
        self.total  = max(1, total)
        self.label  = label
        self.width  = width
        self.stream = stream
        self._lock  = threading.Lock()
        self._done  = 0
        self._start = time.monotonic()

    def update(self, n: int = 1):
        with self._lock:
            self._done = min(self._done + n, self.total)
            self._render()

    def _render(self):
        pct   = self._done / self.total
        filled= int(self.width * pct)
        bar   = "█" * filled + "░" * (self.width - filled)
        ela   = time.monotonic() - self._start
        rps   = self._done / ela if ela > 0 else 0
        self.stream.write(
            "\r{} [{}] {}/{} ({:.0f}%) {:.1f}/s   ".format(
                self.label, bar, self._done, self.total,
                pct * 100, rps))
        self.stream.flush()
        if self._done >= self.total:
            self.stream.write("\n")
            self.stream.flush()

    def finish(self):
        with self._lock:
            self._done = self.total
            self._render()


__all__ = [
    "get_logger", "normalize_url", "extract_domain", "is_valid_url",
    "is_valid_ip", "is_valid_cidr", "expand_cidr", "parse_target",
    "url_join", "get_url_params", "replace_url_params",
    "resolve_host", "reverse_lookup", "is_port_open", "scan_ports",
    "get_local_ip", "get_external_ip",
    "RateLimiter", "retry",
    "USER_AGENTS", "random_ua",
    "human_size", "human_duration", "truncate", "strip_ansi",
    "safe_json", "flatten_dict",
    "hash_target", "fingerprint",
    "env", "env_int", "env_bool", "require_env",
    "chunks", "batched",
    "utcnow", "epoch", "since",
    "Counter", "Progress",
]
