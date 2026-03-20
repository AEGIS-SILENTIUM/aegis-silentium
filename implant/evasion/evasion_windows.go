//go:build windows

package evasion

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	ntdll                = syscall.NewLazyDLL("ntdll.dll")
	procIsDebuggerPresent = kernel32.NewProc("IsDebuggerPresent")
	procGetTickCount64   = kernel32.NewProc("GetTickCount64")
	procCheckRemoteDebuggerPresent = kernel32.NewProc("CheckRemoteDebuggerPresent")
	procNtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
)

func getUptime() time.Duration {
	r, _, _ := procGetTickCount64.Call()
	return time.Duration(r) * time.Millisecond
}

func checkDebugger() bool {
	// IsDebuggerPresent
	r, _, _ := procIsDebuggerPresent.Call()
	if r != 0 {
		return true
	}
	// CheckRemoteDebuggerPresent
	var present bool
	handle, _ := syscall.GetCurrentProcess()
	procCheckRemoteDebuggerPresent.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&present)),
	)
	return present
}

func setProcName(name string) {
	// Windows doesn't support process name masquerading at the API level easily;
	// PPID spoofing and hollow processes require injection (see inject/).
	_ = name
}
