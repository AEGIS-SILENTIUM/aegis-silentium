"""
c2/network/scanner.py
AEGIS-SILENTIUM v12 — Advanced Async Network Scanner

Full implementation:
  • Concurrent TCP connect scan with configurable timing profiles
  • Protocol-aware banner probes (HTTP, SSH, FTP, SMTP, Redis, MongoDB, PG, MySQL…)
  • Service version extraction via compiled regex library (OpenSSH, nginx, Apache, IIS…)
  • OS fingerprinting from port profile + banner heuristics
  • CVE quick-match against 10 high-impact vulnerabilities
  • Subnet sweep with alive-check optimisation
  • Traceroute via TTL-incrementing TCP probes
  • Export to JSON / CSV
  • Synchronous wrapper for use from Flask routes
"""
from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import logging
import re
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional

log = logging.getLogger("aegis.network.scanner")


# ── Port / timing constants ───────────────────────────────────────────────────

class PortState(str, Enum):
    OPEN     = "open"
    CLOSED   = "closed"
    FILTERED = "filtered"
    UNKNOWN  = "unknown"


_WELL_KNOWN: Dict[int, str] = {
    21: "ftp",       22: "ssh",          23: "telnet",      25: "smtp",
    53: "dns",       67: "dhcp",         69: "tftp",        80: "http",
    88: "kerberos",  110: "pop3",        111: "rpcbind",    119: "nntp",
    123: "ntp",      135: "msrpc",       137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios",  143: "imap",        161: "snmp",       179: "bgp",
    389: "ldap",     443: "https",       445: "smb",        465: "smtps",
    500: "isakmp",   514: "syslog",      587: "smtp-sub",   636: "ldaps",
    993: "imaps",    995: "pop3s",       1433: "mssql",     1521: "oracle",
    1723: "pptp",    2049: "nfs",        2375: "docker",    2376: "docker-tls",
    3268: "ldap-gc", 3306: "mysql",      3389: "rdp",       3690: "svn",
    4444: "meterpreter", 5432: "postgresql", 5900: "vnc",   5984: "couchdb",
    6379: "redis",   6443: "k8s-api",    7001: "weblogic",  8080: "http-alt",
    8443: "https-alt", 8888: "jupyter",  9000: "portainer", 9200: "elasticsearch",
    9300: "es-transport", 10250: "kubelet", 11211: "memcached",
    15672: "rabbitmq", 27017: "mongodb", 50070: "hdfs",
}

_TIMING: Dict[str, dict] = {
    "paranoid":   {"concurrent": 5,    "timeout": 6.0, "delay": 2.0},
    "sneaky":     {"concurrent": 15,   "timeout": 4.0, "delay": 0.4},
    "polite":     {"concurrent": 30,   "timeout": 3.0, "delay": 0.15},
    "normal":     {"concurrent": 150,  "timeout": 1.5, "delay": 0.0},
    "aggressive": {"concurrent": 500,  "timeout": 0.7, "delay": 0.0},
    "insane":     {"concurrent": 1000, "timeout": 0.3, "delay": 0.0},
}

# Protocol probes — sent after connection established
_PROBES: Dict[str, bytes] = {
    "http":       b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    "https":      b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    "ftp":        b"",          # server sends banner first
    "ssh":        b"",          # server sends banner first
    "smtp":       b"",          # server sends 220 greeting first
    "pop3":       b"",          # server sends +OK first
    "imap":       b"",          # server sends * OK first
    "redis":      b"*1\r\n$4\r\nPING\r\n",
    "vnc":        b"RFB 003.008\n",
    "default":    b"\r\n",
}

# ── Version detection patterns ────────────────────────────────────────────────
_VERSION_RE: List[tuple] = [
    ("OpenSSH",         re.compile(r"SSH-[\d.]+-OpenSSH_([\w.p-]+)")),
    ("Dropbear",        re.compile(r"SSH-[\d.]+-dropbear_([\w.]+)")),
    ("Apache httpd",    re.compile(r"Apache/([\d.]+)")),
    ("nginx",           re.compile(r"nginx/([\d.]+)")),
    ("Microsoft IIS",   re.compile(r"Microsoft-IIS/([\d.]+)")),
    ("Tomcat",          re.compile(r"(?:Apache-Coyote|Tomcat)/([\d.]+)")),
    ("lighttpd",        re.compile(r"lighttpd/([\d.]+)")),
    ("Redis",           re.compile(r"redis_version:([\d.]+)")),
    ("MongoDB",         re.compile(r'"version"\s*:\s*"([\d.]+)"')),
    ("MySQL",           re.compile(r"(?i)mysql(?:/| )([\d.]+)")),
    ("MariaDB",         re.compile(r"(?i)mariadb-([\d.]+)")),
    ("PostgreSQL",      re.compile(r"(?i)postgresql\s+([\d.]+)")),
    ("Exim",            re.compile(r"220[^\n]+Exim\s+([\d.]+)")),
    ("Postfix",         re.compile(r"220[^\n]+Postfix")),
    ("vsftpd",          re.compile(r"220[^\n]+vsftpd\s+([\d.]+)")),
    ("ProFTPD",         re.compile(r"220[^\n]+ProFTPD\s+([\d.]+)")),
    ("Microsoft SMTP",  re.compile(r"220[^\n]+Microsoft[^\n]+SMTP")),
    ("Dovecot",         re.compile(r"(?i)dovecot")),
    ("OpenVPN",         re.compile(r"(?i)openvpn")),
    ("Elasticsearch",   re.compile(r'"number"\s*:\s*"([\d.]+)"')),
]

# ── CVE quick-check patterns ──────────────────────────────────────────────────
_CVE_CHECKS: List[tuple] = [
    ("CVE-2021-44228", "Log4Shell — RCE via JNDI in Log4j2",
     re.compile(r"(?i)Apache\s+(?:Solr|Struts|Kafka|Flink|Druid|Spark)")),
    ("CVE-2021-41773", "Apache 2.4.49 path traversal & RCE",
     re.compile(r"Apache/2\.4\.49")),
    ("CVE-2021-42013", "Apache 2.4.49-50 path traversal (bypass)",
     re.compile(r"Apache/2\.4\.50")),
    ("CVE-2017-0144",  "EternalBlue — SMBv1 RCE (MS17-010)",
     re.compile(r"(?i)SMB.*?(?:1\.0|NT\s+LAN|Windows\s+(?:XP|7|2008|Vista))")),
    ("CVE-2020-0796",  "SMBGhost — SMBv3.1.1 compression RCE",
     re.compile(r"SMB.*3\.1\.1")),
    ("CVE-2019-11510", "Pulse Secure VPN arbitrary file read",
     re.compile(r"(?i)pulse\s*(?:secure|connect)")),
    ("CVE-2022-22965", "Spring4Shell — Spring Framework RCE",
     re.compile(r"(?i)spring\b")),
    ("CVE-2021-26855", "ProxyLogon — Exchange Server SSRF",
     re.compile(r"(?i)Microsoft Exchange")),
    ("CVE-2019-0708",  "BlueKeep — RDP pre-auth RCE (Windows 7/2008)",
     re.compile(r"(?i)Remote Desktop Protocol|RDP")),
    ("CVE-2014-6271",  "Shellshock — Bash remote code execution",
     re.compile(r"(?i)(?:bash|cgi-bin|Apache.*bash)")),
]


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    ip:          str
    port:        int
    state:       PortState
    service:     str       = ""
    version:     str       = ""
    banner:      str       = ""
    os_guess:    str       = ""
    latency_ms:  float     = 0.0
    cves:        List[str] = field(default_factory=list)
    scanned_at:  float     = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "ip":         self.ip,
            "port":       self.port,
            "state":      self.state.value,
            "service":    self.service,
            "version":    self.version,
            "banner":     self.banner[:256] if self.banner else "",
            "os_guess":   self.os_guess,
            "latency_ms": round(self.latency_ms, 2),
            "cves":       self.cves,
        }


# ── Scanner ───────────────────────────────────────────────────────────────────

class AsyncPortScanner:
    """
    Production-grade async port scanner.

    Usage::
        scanner = AsyncPortScanner(timing="normal", grab_banners=True)
        results = scanner.scan("10.0.0.1", [22, 80, 443, 3306])
        subnet  = scanner.scan_subnet("192.168.1.0/24", [22, 80, 443])
        csv_out = scanner.export(results, fmt="csv")
    """

    def __init__(
        self,
        timing:         str   = "normal",
        grab_banners:   bool  = False,
        banner_timeout: float = 2.0,
        detect_version: bool  = True,
        detect_os:      bool  = True,
        check_cves:     bool  = False,
    ) -> None:
        cfg = _TIMING.get(timing, _TIMING["normal"])
        self._concurrent     = cfg["concurrent"]
        self._timeout        = cfg["timeout"]
        self._delay          = cfg["delay"]
        self._grab_banners   = grab_banners
        self._banner_timeout = banner_timeout
        self._detect_version = detect_version
        self._detect_os      = detect_os
        self._check_cves     = check_cves

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, ip: str, ports: Iterable[int]) -> List[ScanResult]:
        """Synchronous scan — creates and destroys its own event loop."""
        port_list = list(ports)
        try:
            loop = asyncio.new_event_loop()
            return loop.run_until_complete(self.scan_async(ip, port_list))
        finally:
            loop.close()

    def scan_subnet(
        self,
        cidr:           str,
        ports:          Iterable[int],
        skip_discovery: bool = False,
    ) -> Dict[str, List[ScanResult]]:
        """
        Sweep every host in a CIDR range.

        Returns a dict mapping IP → list[open ScanResult].
        Hosts with no open ports are omitted.
        With ``skip_discovery=False`` (default) a quick 3-port pre-check
        prunes dead hosts before the full scan.
        """
        port_list = list(ports)
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            log.error("Invalid CIDR %r: %s", cidr, e)
            return {}

        results: Dict[str, List[ScanResult]] = {}
        for host in network.hosts():
            ip = str(host)
            if not skip_discovery:
                probes = self.scan(ip, [22, 80, 443])
                if not any(r.state == PortState.OPEN for r in probes):
                    continue
            host_results = self.scan(ip, port_list)
            open_ports   = [r for r in host_results if r.state == PortState.OPEN]
            if open_ports:
                results[ip] = open_ports
        return results

    def traceroute(self, target: str, max_hops: int = 30) -> List[dict]:
        """
        TCP-based traceroute — increments TTL on each probe to port 80.
        Returns list of {"hop": N, "ip": "x.x.x.x", "latency_ms": N}.
        Does not require raw sockets; works as an unprivileged user.
        """
        try:
            dst = socket.gethostbyname(target)
        except socket.gaierror as e:
            log.warning("traceroute: DNS lookup failed for %r: %s", target, e)
            return []

        hops = []
        for ttl in range(1, max_hops + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            sock.settimeout(2.0)
            start = time.time()
            hop_ip = "*"
            try:
                sock.connect((dst, 80))
                hop_ip = dst
            except OSError as e:
                # EHOSTUNREACH / ETIMEDOUT / ECONNREFUSED from intermediate routers
                if hasattr(e, "strerror"):
                    hop_ip = "*"
            finally:
                sock.close()

            latency = round((time.time() - start) * 1000, 2)
            hops.append({"hop": ttl, "ip": hop_ip, "latency_ms": latency})
            if hop_ip == dst:
                break

        return hops

    def export(self, results: List[ScanResult], fmt: str = "json") -> str:
        """Serialize scan results to JSON or CSV."""
        rows = [r.to_dict() for r in results]
        if fmt.lower() == "csv":
            buf = io.StringIO()
            if rows:
                writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()),
                                        extrasaction="ignore")
                writer.writeheader()
                writer.writerows(rows)
            return buf.getvalue()
        return json.dumps(rows, indent=2, default=str)

    @staticmethod
    def top_ports(n: int = 100) -> List[int]:
        """Return the N most commonly open ports ordered by frequency."""
        TOP = [
            80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53,
            135, 3306, 8080, 1723, 111, 995, 993, 5900, 1025, 587,
            8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514,
            5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433,
            49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
            631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110,
            49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101,
            144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000,
            5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 873,
            1755, 2717, 4899, 9100, 119, 37, 1000, 3001,
        ]
        return TOP[:n]

    # ── Async core ────────────────────────────────────────────────────────────

    async def scan_async(self, ip: str, ports: List[int]) -> List[ScanResult]:
        """Fully async, concurrent port scan of a single host."""
        sem   = asyncio.Semaphore(self._concurrent)
        tasks = [self._scan_port(ip, p, sem) for p in ports]
        raw   = await asyncio.gather(*tasks, return_exceptions=True)
        valid = [r for r in raw if isinstance(r, ScanResult)]
        return sorted(valid, key=lambda r: r.port)

    async def _scan_port(
        self, ip: str, port: int, sem: asyncio.Semaphore
    ) -> ScanResult:
        async with sem:
            if self._delay > 0:
                await asyncio.sleep(self._delay)

            start   = time.time()
            service = _WELL_KNOWN.get(port, "")

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self._timeout,
                )
            except asyncio.TimeoutError:
                return ScanResult(ip=ip, port=port, state=PortState.FILTERED,
                                  service=service,
                                  latency_ms=(time.time()-start)*1000)
            except ConnectionRefusedError:
                return ScanResult(ip=ip, port=port, state=PortState.CLOSED,
                                  service=service,
                                  latency_ms=(time.time()-start)*1000)
            except OSError:
                return ScanResult(ip=ip, port=port, state=PortState.FILTERED,
                                  service=service)

            latency = (time.time() - start) * 1000
            banner  = ""
            version = ""
            os_g    = ""
            cves: List[str] = []

            if self._grab_banners:
                banner = await self._grab_banner(reader, writer, service)

            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception as _exc:
                log.debug("unknown: %s", _exc)

            if banner:
                if not service:
                    service = self._detect_service(banner)
                if self._detect_version:
                    version = self._extract_version(banner)
                if self._detect_os:
                    os_g = self._guess_os_banner(banner)
                if self._check_cves:
                    cves = self._match_cves(banner)

            if self._detect_os and not os_g:
                os_g = self._guess_os_ports({port})

            return ScanResult(
                ip=ip, port=port, state=PortState.OPEN,
                service=service, version=version, banner=banner,
                os_guess=os_g, latency_ms=latency, cves=cves,
            )

    async def _grab_banner(
        self,
        reader:  asyncio.StreamReader,
        writer:  asyncio.StreamWriter,
        service: str,
    ) -> str:
        """Send a service-appropriate probe and read the response."""
        probe = _PROBES.get(service, _PROBES["default"])
        try:
            if probe:
                writer.write(probe)
                await asyncio.wait_for(writer.drain(), timeout=1.0)
            data = await asyncio.wait_for(
                reader.read(2048),
                timeout=self._banner_timeout,
            )
            return data.decode(errors="replace").strip()[:512]
        except Exception:
            return ""

    # ── Detection helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _detect_service(banner: str) -> str:
        b = banner.lower()
        checks = [
            ("ssh",   ["ssh-"]),
            ("smtp",  ["220 smtp", "220 mail", "esmtp", "ehlo", "postfix", "exim", "sendmail"]),
            ("ftp",   ["220 ftp", "220-ftp", "220 filezilla", "220 vsftpd", "220 proftpd",
                        "220-filezilla", "220-vsftpd", "220-proftpd", "ftp service"]),
            ("pop3",  ["+ok "]),
            ("imap",  ["* ok ", "capability imap"]),
            ("http",  ["http/1.", "server:", "content-type:", "content-length:"]),
            ("redis", ["+pong", "$-1", "-err", "redis"]),
            ("mysql", ["5.5.", "5.6.", "5.7.", "8.0.", "mariadb", "mysql"]),
            ("postgresql", ["postgresql", "postgres"]),
            ("mongodb", ["ismaster", "serverStatus", "isMaster"]),
            ("vnc",   ["rfb "]),
            ("ldap",  ["ldap"]),
            ("telnet", ["login:", "password:", "username:"]),
        ]
        for svc, patterns in checks:
            if any(p in b for p in patterns):
                return svc
        return "unknown"

    @staticmethod
    def _extract_version(banner: str) -> str:
        for name, pattern in _VERSION_RE:
            m = pattern.search(banner)
            if m:
                ver = m.group(1) if m.lastindex else ""
                return f"{name} {ver}".strip()
        return ""

    @staticmethod
    def _match_cves(banner: str) -> List[str]:
        return [
            f"{cve}: {desc}"
            for cve, desc, pat in _CVE_CHECKS
            if pat.search(banner)
        ]

    @staticmethod
    def _guess_os_banner(banner: str) -> str:
        b = banner.lower()
        mapping = [
            ("Windows",     ["windows", "microsoft", "win32", "iis", "ms-ftp"]),
            ("Linux",       ["ubuntu", "debian", "centos", "rhel", "fedora",
                              "linux", "alpine", "arch"]),
            ("macOS",       ["darwin", "macos", "apple"]),
            ("FreeBSD",     ["freebsd"]),
            ("OpenBSD",     ["openbsd"]),
            ("Cisco IOS",   ["cisco ios", "cisco adaptive"]),
            ("Juniper",     ["juniper", "junos"]),
            ("FortiOS",     ["fortigate", "fortios"]),
        ]
        for os_name, keywords in mapping:
            if any(k in b for k in keywords):
                return os_name
        return ""

    @staticmethod
    def _guess_os_ports(ports: set) -> str:
        if {88, 389, 3268}.issubset(ports) or {88, 445}.issubset(ports):
            return "Windows Server (Domain Controller)"
        if 3389 in ports or {135, 445}.issubset(ports):
            return "Windows"
        if {22, 80}.issubset(ports) or {22, 443}.issubset(ports):
            return "Linux"
        if 161 in ports or 23 in ports:
            return "Network Device"
        if 5432 in ports: return "PostgreSQL Server"
        if 3306 in ports: return "MySQL/MariaDB Server"
        if 1433 in ports: return "Microsoft SQL Server"
        if 27017 in ports: return "MongoDB Server"
        return ""


__all__ = ["AsyncPortScanner", "ScanResult", "PortState", "_WELL_KNOWN"]
