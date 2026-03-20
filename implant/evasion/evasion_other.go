//go:build !linux && !windows

package evasion

import "time"

func getUptime() time.Duration { return 0 }
func checkDebugger() bool      { return false }
func setProcName(name string)  {}
