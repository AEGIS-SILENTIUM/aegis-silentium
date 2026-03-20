//go:build windows

package persistence

import (
	"golang.org/x/sys/windows/registry"
)

const runKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

func registryRunKey(name, value string, hklm bool) error {
	root := registry.CURRENT_USER
	if hklm {
		root = registry.LOCAL_MACHINE
	}
	k, _, err := registry.CreateKey(root, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(name, value)
}

func registryDeleteKey(name string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.DeleteValue(name)
}
