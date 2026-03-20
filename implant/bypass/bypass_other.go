//go:build !windows

// Package bypass — Linux/macOS stub.
// AMSI and ETW are Windows-only concepts.
// Linux hardening (ptrace-based detection avoidance) is in evasion/.
package bypass

import "fmt"

type HardenResult struct {
	AMSIPatched   bool
	ETWPatched    bool
	NTDLLUnhooked bool
	Raw           int
}

func (r HardenResult) String() string {
	return "bypass: linux/darwin — no AMSI/ETW"
}

func Harden() HardenResult     { return HardenResult{} }
func PatchAMSI() error          { return nil }
func PatchETW() error           { return nil }
func UnhookNTDLL() (int, error) { return 0, nil }
func GetSSN(name string) (uint32, error) {
	return 0, fmt.Errorf("SSN: windows only")
}
