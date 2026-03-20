//go:build linux

package evasion

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// getUptime returns system uptime from /proc/uptime.
func getUptime() time.Duration {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	parts := strings.Fields(string(b))
	if len(parts) == 0 {
		return 0
	}
	secs, _ := strconv.ParseFloat(parts[0], 64)
	return time.Duration(secs * float64(time.Second))
}

// checkDebugger reads TracerPid from /proc/self/status.
func checkDebugger() bool {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pid, _ := strconv.Atoi(parts[1])
				return pid != 0
			}
		}
	}
	return false
}

// setProcName sets the process name via prctl(PR_SET_NAME).
func setProcName(name string) {
	if len(name) > 15 {
		name = name[:15]
	}
	b := make([]byte, 16)
	copy(b, name)
	// PR_SET_NAME = 15
	syscall.Syscall6(syscall.SYS_PRCTL, 15,
		uintptr(unsafe.Pointer(&b[0])), 0, 0, 0, 0)
}
