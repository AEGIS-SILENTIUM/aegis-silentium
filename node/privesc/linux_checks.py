import logging
log = logging.getLogger(__name__)
#!/usr/bin/env python3
"""
AEGIS-Advanced Linux Privilege Escalation Module
==================================================
Comprehensive local enumeration and automated checks:
SUID/GUID, capabilities, sudo misconfigs, writable PATH,
NFS no_root_squash, world-writable cron/scripts, Docker/LXC,
kernel CVE matching, weak service configs, env hijack,
/etc/passwd writability, cron PATH hijack, container escape.
"""
import os
import subprocess
import platform
import stat
import re
import grp
import pwd
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ══════════════════════════════════════════════
# Helper
# ══════════════════════════════════════════════

def _run(cmd: str, timeout: int = 10) -> Tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                            text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 1
    except Exception as e:
        return "", str(e), 1

def _is_root() -> bool:
    return os.geteuid() == 0

def _find_files(paths: List[str], perm: int) -> List[str]:
    """Find files matching permission bits under given paths."""
    results = []
    for base in paths:
        try:
            out, _, rc = _run("find {} -maxdepth 5 -perm -{} -type f 2>/dev/null".format(
                base, oct(perm)[2:]))
            if rc == 0 and out:
                results.extend(out.splitlines())
        except Exception as _exc:
            log.debug("_find_files: %s", _exc)
    return results


# ══════════════════════════════════════════════
# SUID / GUID binaries
# ══════════════════════════════════════════════

GTFOBINS_SUID = {
    "bash", "sh", "dash", "zsh", "fish", "ksh",
    "python", "python2", "python3", "perl", "ruby", "lua",
    "awk", "gawk", "mawk", "nawk",
    "find", "vim", "vi", "nano", "more", "less", "man",
    "tar", "gzip", "gunzip", "zip", "unzip",
    "cp", "mv", "rm", "install", "tee",
    "nmap", "tcpdump", "socat", "nc", "netcat",
    "wget", "curl", "git", "rsync",
    "env", "xargs", "nice", "ionice",
    "strace", "ltrace", "gdb",
    "node", "php",
    "pkexec", "sudoedit", "sudo",
}

def check_suid_binaries() -> List[Dict]:
    """Find world-executable SUID binaries and flag GTFOBins matches."""
    results = []
    try:
        out, _, _ = _run("find / -perm -4000 -type f 2>/dev/null")
        for line in out.splitlines():
            line = line.strip()
            if not line: continue
            name = Path(line).stem.lower()
            base = Path(line).name.lower().split(".")[0]
            is_gtfo = name in GTFOBINS_SUID or base in GTFOBINS_SUID
            results.append({
                "path":      line,
                "gtfobins":  is_gtfo,
                "severity":  "critical" if is_gtfo else "medium",
                "exploit":   "Run: {} -p (for bash)".format(line) if is_gtfo else "Manual review",
            })
    except Exception as e:
        log.debug("check_suid_binaries: %s", e)
    return results


def check_guid_binaries() -> List[Dict]:
    """Find SGID binaries."""
    results = []
    try:
        out, _, _ = _run("find / -perm -2000 -type f 2>/dev/null")
        for line in out.splitlines():
            line = line.strip()
            if line:
                results.append({"path": line, "severity": "medium"})
    except Exception as _exc:
        log.debug("check_guid_binaries: %s", _exc)
    return results


# ══════════════════════════════════════════════
# File capabilities
# ══════════════════════════════════════════════

DANGEROUS_CAPS = {
    "cap_setuid", "cap_setgid", "cap_chown", "cap_dac_override",
    "cap_dac_read_search", "cap_sys_admin", "cap_sys_ptrace",
    "cap_net_admin", "cap_net_raw", "cap_sys_module",
}

def check_capabilities() -> List[Dict]:
    """Find files with dangerous capabilities set."""
    results = []
    out, _, rc = _run("getcap -r / 2>/dev/null")
    if rc == 0:
        for line in out.splitlines():
            if "=" not in line: continue
            path, caps = line.split("=", 1)
            path = path.strip()
            cap_list = [c.strip().lower() for c in re.split(r"[,+]", caps)]
            dangerous = [c for c in cap_list if any(d in c for d in DANGEROUS_CAPS)]
            if dangerous:
                results.append({
                    "path":       path,
                    "caps":       caps.strip(),
                    "dangerous":  dangerous,
                    "severity":   "critical",
                    "exploit":    "Use {} to escalate via {}".format(
                        Path(path).name, ",".join(dangerous)),
                })
    return results


# ══════════════════════════════════════════════
# Sudo misconfigurations
# ══════════════════════════════════════════════

def check_sudo() -> Dict:
    """Check sudo -l for misconfigurations."""
    out, err, rc = _run("sudo -n -l 2>&1")
    result = {"raw": out, "nopasswd": [], "all_commands": False,
              "env_keep": [], "dangerous": []}
    if "NOPASSWD" in out:
        for line in out.splitlines():
            if "NOPASSWD" in line:
                result["nopasswd"].append(line.strip())
                # Check for dangerous commands
                for cmd_name in GTFOBINS_SUID:
                    if cmd_name in line.lower():
                        result["dangerous"].append(line.strip())
    if "(ALL)" in out and "ALL" in out:
        result["all_commands"] = True
    env_keep_match = re.findall(r"env_keep.*?=.*?([A-Z_]+)", out)
    result["env_keep"] = env_keep_match
    return result


# ══════════════════════════════════════════════
# PATH hijacking
# ══════════════════════════════════════════════

def check_writable_path_dirs() -> List[Dict]:
    """Check for world-writable or user-writable dirs in $PATH."""
    results = []
    for d in os.environ.get("PATH", "").split(":"):
        d = d.strip()
        if not d or not os.path.isdir(d): continue
        try:
            st = os.stat(d)
            world_write = bool(st.st_mode & stat.S_IWOTH)
            user_write  = os.access(d, os.W_OK)
            if world_write or user_write:
                results.append({
                    "path":        d,
                    "world_write": world_write,
                    "user_write":  user_write,
                    "severity":    "critical" if world_write else "high",
                    "exploit":     "Place malicious binary in {} to hijack PATH".format(d),
                })
        except Exception as _exc:
            log.debug("check_writable_path_dirs: %s", _exc)
    return results


def check_cron_path_hijack() -> List[Dict]:
    """Check if cron jobs use relative paths or unquoted vars."""
    results = []
    cron_sources = ["/etc/crontab", "/etc/cron.d/"]
    for src in cron_sources:
        files = []
        if os.path.isfile(src):
            files = [src]
        elif os.path.isdir(src):
            files = [str(f) for f in Path(src).glob("*") if f.is_file()]
        for cfile in files:
            try:
                with open(cfile) as f: content = f.read()
                for line in content.splitlines():
                    if line.startswith("#") or not line.strip(): continue
                    # Look for relative command names
                    if re.search(r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+[^/]", line):
                        results.append({
                            "file":     cfile,
                            "line":     line.strip(),
                            "severity": "high",
                            "reason":   "Relative path in cron job",
                        })
            except Exception as _exc:
                log.debug("unknown: %s", _exc)
    return results


# ══════════════════════════════════════════════
# World-writable files / scripts
# ══════════════════════════════════════════════

def check_world_writable() -> List[Dict]:
    """Find world-writable files in common privileged locations."""
    results = []
    check_paths = ["/etc", "/usr/local/bin", "/usr/bin", "/bin",
                   "/sbin", "/usr/sbin", "/opt"]
    for base in check_paths:
        out, _, _ = _run("find {} -maxdepth 2 -perm -0002 -type f 2>/dev/null".format(base))
        for line in out.splitlines():
            line = line.strip()
            if line:
                results.append({
                    "path":    line,
                    "severity":"high",
                    "exploit": "Overwrite {} to execute as owner".format(line),
                })
    return results


# ══════════════════════════════════════════════
# NFS no_root_squash
# ══════════════════════════════════════════════

def check_nfs() -> List[Dict]:
    """Check /etc/exports for no_root_squash."""
    results = []
    if os.path.exists("/etc/exports"):
        try:
            with open("/etc/exports") as f: content = f.read()
            for line in content.splitlines():
                if "no_root_squash" in line.lower():
                    results.append({
                        "export":   line.strip(),
                        "severity": "critical",
                        "exploit":  "Mount NFS share, compile SUID binary as root on attacker machine",
                    })
        except Exception as _exc:
            log.debug("check_nfs: %s", _exc)
    return results


# ══════════════════════════════════════════════
# Kernel version & CVEs
# ══════════════════════════════════════════════

KERNEL_CVES = [
    {"cve": "CVE-2022-0847", "name": "Dirty Pipe",
     "check": lambda maj,min,pat: (5,8,0) <= (maj,min,pat) < (5,16,11),
     "desc":  "Overwrite arbitrary read-only files including SUID binaries"},
    {"cve": "CVE-2021-4034", "name": "PwnKit (pkexec)",
     "check": lambda maj,min,pat: True,  # version-independent, check pkexec
     "desc":  "Local privilege escalation via pkexec (polkit)"},
    {"cve": "CVE-2021-3156", "name": "Baron Samedit (sudo)",
     "check": lambda maj,min,pat: True,
     "desc":  "Heap overflow in sudo sudoedit -s"},
    {"cve": "CVE-2016-5195", "name": "DirtyCow",
     "check": lambda maj,min,pat: (maj,min,pat) < (4,8,3),
     "desc":  "Race condition in copy-on-write — arbitrary write to read-only mappings"},
    {"cve": "CVE-2023-0386",  "name": "OverlayFS",
     "check": lambda maj,min,pat: (5,11,0) <= (maj,min,pat) < (6,2,0),
     "desc":  "FUSE overlayfs allows SUID file copy"},
    {"cve": "CVE-2022-2588",  "name": "Route of Death",
     "check": lambda maj,min,pat: (maj,min,pat) < (5,18,0),
     "desc":  "cls_route UAF allows LPE"},
    {"cve": "CVE-2023-32629", "name": "GameOver(lay)",
     "check": lambda maj,min,pat: (6,2,0) <= (maj,min,pat) < (6,4,0),
     "desc":  "Ubuntu-specific OverlayFS privesc"},
]

def check_kernel() -> Dict:
    release = platform.release()
    uname   = platform.uname()
    try:
        ver_str = release.split("-")[0]
        parts   = [int(x) for x in ver_str.split(".")[:3]]
        while len(parts) < 3: parts.append(0)
        maj, min_, pat = parts
    except Exception:
        maj, min_, pat = 0, 0, 0

    # Check pkexec
    pkexec_vulnerable = False
    pk_out, _, _ = _run("pkexec --version 2>&1")
    if "0.105" in pk_out or "0.106" in pk_out:
        pkexec_vulnerable = True

    # Check sudo version
    sudo_out, _, _ = _run("sudo --version 2>&1 | head -1")
    sudo_match = re.search(r"(\d+\.\d+[.\d]*)", sudo_out)
    sudo_ver   = sudo_match.group(1) if sudo_match else "unknown"

    vuln_list = []
    for cve in KERNEL_CVES:
        try:
            if cve["check"](maj, min_, pat):
                entry = {"cve": cve["cve"], "name": cve["name"],
                          "desc": cve["desc"], "severity": "critical"}
                # Extra conditions
                if "pkexec" in cve["name"] and not pkexec_vulnerable:
                    entry["note"] = "Verify pkexec version manually"
                vuln_list.append(entry)
        except Exception as _exc:
            log.debug("unknown: %s", _exc)

    return {
        "release":       release,
        "version":       (maj, min_, pat),
        "arch":          uname.machine,
        "os":            uname.system,
        "pkexec_ver":    pk_out[:40],
        "sudo_ver":      sudo_ver,
        "possible_cves": vuln_list,
    }


# ══════════════════════════════════════════════
# Container detection & escape vectors
# ══════════════════════════════════════════════

def check_container_context() -> Dict:
    """Detect if running inside container and identify escape vectors."""
    in_docker = os.path.exists("/.dockerenv")
    in_lxc    = os.path.exists("/run/systemd/container") or \
                 os.path.exists("/run/container_type")
    in_k8s    = os.path.exists("/var/run/secrets/kubernetes.io")
    cgroup, _, _ = _run("cat /proc/1/cgroup 2>/dev/null | head -5")
    in_docker     = in_docker or "docker" in cgroup.lower()
    in_lxc        = in_lxc or "lxc" in cgroup.lower()

    escapes = []
    # Docker socket
    if os.access("/var/run/docker.sock", os.R_OK | os.W_OK):
        escapes.append({
            "method":  "docker_socket",
            "severity":"critical",
            "desc":    "Docker socket accessible — spawn privileged container to escape",
        })
    # Privileged container check
    out, _, _ = _run("cat /proc/self/status | grep CapEff")
    if "0000003fffffffff" in out or "ffffffffffffffff" in out:
        escapes.append({
            "method":  "privileged_container",
            "severity":"critical",
            "desc":    "Running as privileged — mount host filesystem via /dev/sda or cgroup escape",
        })
    # K8s service account token
    tok = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    if os.path.exists(tok):
        try:
            with open(tok) as f: token_preview = f.read()[:40]
            escapes.append({
                "method":       "k8s_service_account",
                "severity":     "high",
                "token_prefix": token_preview,
                "desc":         "Kubernetes service account token — enumerate cluster RBAC",
            })
        except Exception as _exc:
            log.debug("unknown: %s", _exc)
    # writable host mount
    out2, _, _ = _run("cat /proc/mounts 2>/dev/null")
    for line in out2.splitlines():
        if "rw" in line and ("/host" in line or "sda" in line or "vda" in line):
            escapes.append({"method": "host_mount", "severity": "critical",
                             "line": line.strip(),
                             "desc": "Host filesystem mounted read-write"})

    return {
        "in_docker": in_docker,
        "in_lxc":    in_lxc,
        "in_k8s":    in_k8s,
        "cgroup":    cgroup[:200],
        "escapes":   escapes,
    }


# ══════════════════════════════════════════════
# Interesting files & credentials
# ══════════════════════════════════════════════

def check_interesting_files() -> List[Dict]:
    """Search for credential files, private keys, config files."""
    patterns = [
        ("/root/.ssh/id_*",           "ssh_private_key",  "critical"),
        ("/home/*/.ssh/id_*",         "ssh_private_key",  "critical"),
        ("/root/.aws/credentials",     "aws_credentials",  "critical"),
        ("/home/*/.aws/credentials",   "aws_credentials",  "critical"),
        ("/etc/shadow",                "shadow_file",      "critical"),
        ("/etc/sudoers",               "sudoers",          "high"),
        ("/etc/sudoers.d/*",           "sudoers_drop",     "high"),
        ("/**/config.php",             "web_config",       "medium"),
        ("/**/.env",                   "env_file",         "medium"),
        ("/**/wp-config.php",          "wordpress_config", "high"),
        ("/**/id_rsa",                 "ssh_private_key",  "critical"),
        ("/**/*.pem",                  "ssl_key",          "high"),
        ("/**/*.key",                  "private_key",      "high"),
        ("/var/www/**/.htpasswd",      "htpasswd",         "high"),
        ("/root/.bash_history",        "root_history",     "high"),
        ("/home/*/.bash_history",      "user_history",     "medium"),
    ]
    results = []
    for pattern, ftype, sev in patterns:
        import glob
        for path in glob.glob(pattern, recursive=True)[:5]:
            if os.path.exists(path) and os.access(path, os.R_OK):
                try:
                    size = os.path.getsize(path)
                    results.append({
                        "path":     path,
                        "type":     ftype,
                        "severity": sev,
                        "size":     size,
                        "readable": True,
                    })
                except Exception as _exc:
                    log.debug("unknown: %s", _exc)
    return results


# ══════════════════════════════════════════════
# Running services & processes
# ══════════════════════════════════════════════

def check_running_services() -> List[Dict]:
    """Find interesting running services and their users."""
    results = []
    out, _, _ = _run("ps aux 2>/dev/null | grep -v grep")
    for line in out.splitlines():
        cols = line.split()
        if len(cols) < 11: continue
        user  = cols[0]
        pid   = cols[1]
        cmd   = " ".join(cols[10:])[:120]
        if user == "root" and any(kw in cmd.lower() for kw in
                ["mysql", "postgres", "redis", "memcached",
                 "mongo", "elastic", "kafka", "zookeeper"]):
            results.append({"user": user, "pid": pid, "cmd": cmd,
                             "severity": "medium",
                             "note": "Privileged service — check for auth bypass"})
    return results


# ══════════════════════════════════════════════
# /etc/passwd writability
# ══════════════════════════════════════════════

def check_passwd_writable() -> Dict:
    writable = os.access("/etc/passwd", os.W_OK)
    shadow_r = os.access("/etc/shadow", os.R_OK)
    return {
        "passwd_writable": writable,
        "shadow_readable": shadow_r,
        "severity":        "critical" if writable or shadow_r else "none",
        "exploit":         ("Write root user to /etc/passwd" if writable else
                             "Crack shadow hashes" if shadow_r else ""),
    }


# ══════════════════════════════════════════════
# Full check
# ══════════════════════════════════════════════

def full_check(verbose: bool = False) -> Dict:
    """
    Run all privilege escalation checks.
    Returns structured dict of findings.
    """
    print("[privesc] Running full Linux privilege escalation check…")

    result = {}
    checks = [
        ("suid",           check_suid_binaries),
        ("guid",           check_guid_binaries),
        ("capabilities",   check_capabilities),
        ("sudo",           check_sudo),
        ("path_hijack",    check_writable_path_dirs),
        ("cron_path",      check_cron_path_hijack),
        ("world_writable", check_world_writable),
        ("nfs",            check_nfs),
        ("kernel",         check_kernel),
        ("containers",     check_container_context),
        ("interesting",    check_interesting_files),
        ("services",       check_running_services),
        ("passwd",         check_passwd_writable),
    ]

    for name, fn in checks:
        try:
            result[name] = fn()
            if verbose:
                count = len(result[name]) if isinstance(result[name], list) else (
                    1 if result[name] else 0)
                print("  [{}] {} findings".format(name, count))
        except Exception as e:
            result[name] = {"error": str(e)}

    # Summary
    critical = sum(
        1 for k, v in result.items()
        if isinstance(v, list) and any(
            (i.get("severity") if isinstance(i, dict) else "") == "critical"
            for i in v
        )
    )
    result["_summary"] = {
        "total_checks": len(checks),
        "critical_findings": critical,
        "is_root": _is_root(),
    }
    return result


if __name__ == "__main__":
    import json
    r = full_check(verbose=True)
    print("\n=== SUMMARY ===")
    print("Critical:", r["_summary"]["critical_findings"])
    if r["kernel"].get("possible_cves"):
        print("Kernel CVEs:", [c["cve"] for c in r["kernel"]["possible_cves"]])


# ════════════════════════════════════════════════════════════════════════════
# Class-based API matching __init__.py exports
# ════════════════════════════════════════════════════════════════════════════

class LinuxPrivescChecker:
    """Comprehensive Linux privilege escalation checker."""
    def check_suid_binaries(self) -> List[Dict]:
        return check_suid_binaries()
    def check_sudo_nopasswd(self) -> List[Dict]:
        s = check_sudo()
        return s.get("nopasswd_commands", [])
    def check_cron_hijack(self) -> List[Dict]:
        return check_cron_path_hijack()
    def check_kernel_cves(self) -> Dict:
        return check_kernel()
    def check_capabilities(self) -> List[Dict]:
        return check_capabilities()
    def check_all(self) -> Dict:
        return full_check()
    def print_report(self, findings: list) -> None:
        for f in findings:
            sev = f.get("severity", "?").upper()
            title = f.get("path", f.get("title", str(f)))
            print(f"  [{sev}] {title}")


class GTFOBinsChecker:
    """SUID/capabilities cross-reference against GTFOBins database."""
    def check(self) -> List[Dict]:
        return [r for r in check_suid_binaries() if r.get("gtfobins")]


class SudoChecker:
    """sudo -l parser and NOPASSWD detector."""
    def check(self) -> Dict:
        return check_sudo()


class KernelExploitMatcher:
    """Kernel version → CVE matcher."""
    def check(self) -> Dict:
        return check_kernel()


class ContainerEscapeChecker:
    """Docker/K8s container escape vector checker."""
    def check(self) -> Dict:
        return check_container_context()


class CredentialHarvester:
    """SSH keys, .env, config file finder."""
    def harvest(self) -> List[Dict]:
        return check_interesting_files()


def run_all_checks() -> Dict:
    """Run all privesc checks and return consolidated results."""
    return full_check(verbose=True)
