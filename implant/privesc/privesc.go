// Package privesc provides privilege escalation enumeration.
// Checks SUID binaries, sudo rules, writable /etc/passwd, kernel version,
// container escapes, capabilities, and NFS no_root_squash.
package privesc

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Finding represents a potential privilege escalation vector.
type Finding struct {
	Type     string `json:"type"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"` // "high"|"medium"|"low"
	Vector   string `json:"vector"`
}

// Check runs all privilege escalation checks and returns findings.
func Check() ([]Finding, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("privesc: only implemented for linux")
	}
	var findings []Finding
	findings = append(findings, checkSUID()...)
	findings = append(findings, checkSudo()...)
	findings = append(findings, checkWritablePasswd()...)
	findings = append(findings, checkWritableCron()...)
	findings = append(findings, checkCapabilities()...)
	findings = append(findings, checkDocker()...)
	findings = append(findings, checkKernelVersion()...)
	findings = append(findings, checkNFSNoRootSquash()...)
	findings = append(findings, checkWorldWritableServices()...)
	return findings, nil
}

// ── SUID Binaries ─────────────────────────────────────────────────────────────

// Known exploitable SUID binaries (GTFOBins list, non-exhaustive)
var exploitableSUID = map[string]bool{
	"nmap": true, "vim": true, "vi": true, "nano": true, "find": true,
	"less": true, "more": true, "python": true, "python3": true,
	"ruby": true, "perl": true, "lua": true, "awk": true, "gawk": true,
	"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true,
	"csh": true, "tcsh": true, "php": true, "node": true, "nodejs": true,
	"tclsh": true, "expect": true, "socat": true, "netcat": true,
	"nc": true, "ncat": true, "curl": true, "wget": true, "ftp": true,
	"tftp": true, "cp": true, "mv": true, "chmod": true, "chown": true,
	"dd": true, "tee": true, "cat": true, "xxd": true, "tar": true,
	"zip": true, "unzip": true, "7z": true, "git": true, "man": true,
	"env": true, "ld": true, "make": true, "strace": true, "gdb": true,
	"taskset": true, "docker": true, "podman": true, "runc": true,
	"screen": true, "tmux": true, "journalctl": true, "pkexec": true,
}

func checkSUID() []Finding {
	var findings []Finding
	searchDirs := []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin",
		"/usr/local/bin", "/usr/local/sbin", "/opt"}

	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(dir, e.Name())
			info, err := e.Info()
			if err != nil {
				continue
			}
			// Check SUID bit (mode & 04000)
			if info.Mode()&0o4000 != 0 {
				name := e.Name()
				severity := "low"
				if exploitableSUID[name] {
					severity = "high"
				}
				findings = append(findings, Finding{
					Type:     "suid",
					Detail:   path,
					Severity: severity,
					Vector:   fmt.Sprintf("SUID binary: %s — check GTFOBins", path),
				})
			}
		}
	}
	return findings
}

// ── sudo -l ───────────────────────────────────────────────────────────────────

func checkSudo() []Finding {
	out, err := exec.Command("sudo", "-l", "-n").CombinedOutput()
	if err != nil {
		return nil
	}
	text := string(out)
	if !strings.Contains(text, "(") {
		return nil
	}

	var findings []Finding
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "(") {
			continue
		}
		severity := "medium"
		if strings.Contains(line, "NOPASSWD") {
			severity = "high"
		}
		if strings.Contains(line, "ALL") {
			severity = "high"
		}
		findings = append(findings, Finding{
			Type:     "sudo",
			Detail:   line,
			Severity: severity,
			Vector:   "sudo misconfiguration",
		})
	}
	return findings
}

// ── Writable /etc/passwd ──────────────────────────────────────────────────────

func checkWritablePasswd() []Finding {
	f, err := os.OpenFile("/etc/passwd", os.O_WRONLY|os.O_APPEND, 0)
	if err == nil {
		f.Close()
		return []Finding{{
			Type:     "writable_passwd",
			Detail:   "/etc/passwd is world-writable",
			Severity: "high",
			Vector:   "Add root::<uid 0> entry",
		}}
	}
	return nil
}

// ── Writable cron directories ─────────────────────────────────────────────────

func checkWritableCron() []Finding {
	cronDirs := []string{
		"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
		"/etc/cron.weekly", "/etc/cron.monthly",
	}
	var findings []Finding
	for _, dir := range cronDirs {
		info, err := os.Stat(dir)
		if err != nil {
			continue
		}
		if info.Mode()&0o002 != 0 { // world-writable
			findings = append(findings, Finding{
				Type:     "writable_cron",
				Detail:   dir,
				Severity: "high",
				Vector:   "Write malicious cron job to " + dir,
			})
		}
	}
	return findings
}

// ── Linux Capabilities ────────────────────────────────────────────────────────

var dangerousCaps = []string{
	"cap_setuid", "cap_setgid", "cap_sys_admin", "cap_sys_ptrace",
	"cap_net_bind_service", "cap_dac_override", "cap_chown",
	"cap_net_raw", "cap_sys_module",
}

func checkCapabilities() []Finding {
	out, err := exec.Command("getcap", "-r", "/").CombinedOutput()
	if err != nil {
		return nil
	}
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, cap := range dangerousCaps {
			if strings.Contains(strings.ToLower(line), cap) {
				findings = append(findings, Finding{
					Type:     "capability",
					Detail:   line,
					Severity: "high",
					Vector:   "Dangerous capability: " + cap,
				})
				break
			}
		}
	}
	return findings
}

// ── Docker group / socket ─────────────────────────────────────────────────────

func checkDocker() []Finding {
	var findings []Finding

	// Check if docker socket is accessible
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		if f, err := os.Open("/var/run/docker.sock"); err == nil {
			f.Close()
			findings = append(findings, Finding{
				Type:     "docker",
				Detail:   "/var/run/docker.sock accessible",
				Severity: "high",
				Vector:   "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
			})
		}
	}

	// Check if running inside container
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		if strings.Contains(string(b), "docker") || strings.Contains(string(b), "kubepods") {
			findings = append(findings, Finding{
				Type:     "container",
				Detail:   "Running inside container",
				Severity: "medium",
				Vector:   "Check for privileged container, host mounts, cgroup escape",
			})
		}
	}
	return findings
}

// ── Kernel version ────────────────────────────────────────────────────────────

// Known exploitable kernel version ranges (non-exhaustive — for reference)
var vulnerableKernels = []struct {
	Max  string
	CVE  string
	Name string
}{
	{"5.8.0", "CVE-2021-4034", "PwnKit (pkexec)"},
	{"5.9.0", "CVE-2021-3156", "sudo heap overflow"},
	{"4.4.0", "CVE-2016-5195", "Dirty COW"},
	{"5.16.0", "CVE-2022-0847", "Dirty Pipe"},
}

func checkKernelVersion() []Finding {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return nil
	}
	version := strings.TrimSpace(string(out))

	findings := []Finding{{
		Type:     "kernel_version",
		Detail:   version,
		Severity: "info",
		Vector:   "Check manually against kernel exploit databases",
	}}

	// Simple prefix check for very old kernels
	if strings.HasPrefix(version, "2.") || strings.HasPrefix(version, "3.") ||
		strings.HasPrefix(version, "4.") {
		findings = append(findings, Finding{
			Type:     "old_kernel",
			Detail:   version,
			Severity: "high",
			Vector:   "Old kernel — likely vulnerable to multiple CVEs. Search searchsploit.",
		})
	}
	return findings
}

// ── NFS no_root_squash ────────────────────────────────────────────────────────

func checkNFSNoRootSquash() []Finding {
	b, err := os.ReadFile("/etc/exports")
	if err != nil {
		return nil
	}
	var findings []Finding
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "no_root_squash") {
			findings = append(findings, Finding{
				Type:     "nfs_no_root_squash",
				Detail:   strings.TrimSpace(line),
				Severity: "high",
				Vector:   "Mount share as root from attacker machine, set SUID on binary",
			})
		}
	}
	return findings
}

// ── World-writable service files ──────────────────────────────────────────────

func checkWorldWritableServices() []Finding {
	searchDirs := []string{
		"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system",
	}
	var findings []Finding
	for _, dir := range searchDirs {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".service") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			info, err := e.Info()
			if err != nil {
				continue
			}
			if info.Mode()&0o002 != 0 {
				findings = append(findings, Finding{
					Type:     "writable_service",
					Detail:   path,
					Severity: "high",
					Vector:   "Overwrite service file to execute arbitrary command as root",
				})
			}
		}
	}
	return findings
}
