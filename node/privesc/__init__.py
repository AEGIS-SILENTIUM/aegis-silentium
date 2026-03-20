"""
AEGIS-Advanced Node Privilege Escalation Package
==================================================
Automated Linux privilege escalation checks: SUID/GUID binaries with
GTFOBins exploitation paths, sudo misconfigurations, cron hijacking,
kernel CVE detection, container escapes, and credential harvesting.

Exports:
    LinuxPrivescChecker     — Main privesc check engine
    GTFOBinsChecker         — SUID/capabilities vs GTFOBins database
    SudoChecker             — sudo -l parser + NOPASSWD detection
    KernelExploitMatcher    — Kernel version → CVE matcher
    ContainerEscapeChecker  — Docker/K8s container escape vectors
    CredentialHarvester     — SSH keys, .env, config file finder
    run_all_checks          — Run everything, return consolidated report

Covered CVEs:
    CVE-2021-4034 (PwnKit/pkexec),   CVE-2021-3493 (Ubuntu OverlayFS),
    CVE-2022-0847 (Dirty Pipe),      CVE-2021-3156 (Baron Samedit/sudo),
    CVE-2021-33909 (Sequoia),        CVE-2021-22555 (netfilter heap),
    CVE-2023-0386  (OverlayFS fuse), CVE-2023-2640  (GameOver(lay)),
    CVE-2016-5195  (DirtyCow),       CVE-2022-2588  (Route of Death)

Usage:
    from node.privesc import run_all_checks

    report = run_all_checks()
    for finding in report["findings"]:
        print(finding["severity"], finding["title"], "→", finding["exploit"])

    # Granular
    from node.privesc import LinuxPrivescChecker
    checker = LinuxPrivescChecker()
    findings = []
    findings += checker.check_suid_binaries()
    findings += checker.check_sudo_nopasswd()
    findings += checker.check_cron_hijack()
    findings += checker.check_kernel_cves()
    checker.print_report(findings)
"""

from .linux_checks import (
    LinuxPrivescChecker,
    GTFOBinsChecker,
    SudoChecker,
    KernelExploitMatcher,
    ContainerEscapeChecker,
    CredentialHarvester,
    run_all_checks,
)

__all__ = [
    "LinuxPrivescChecker",
    "GTFOBinsChecker",
    "SudoChecker",
    "KernelExploitMatcher",
    "ContainerEscapeChecker",
    "CredentialHarvester",
    "run_all_checks",
]

__version__ = "5.0"
