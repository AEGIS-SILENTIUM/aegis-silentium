//go:build !windows

package persistence

import "fmt"

func registryRunKey(name, value string, hklm bool) error {
	return fmt.Errorf("registry: not on windows")
}

func registryDeleteKey(name string) error { return nil }
