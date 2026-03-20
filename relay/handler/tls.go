// Package handler provides reusable TLS, HTTP, and connection utilities
// for the AEGIS-SILENTIUM relay.
//
// Architecture note:
//   handler → stdlib only (crypto/tls, net/http, etc.)
//   main    → handler + yaml.v3
//
// This package deliberately has NO imports from any other relay subpackage
// to prevent import cycles.  All shared types are defined here or in types.go.
//
// AUTHORIZED USE ONLY — professional adversary simulation environments.
package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
// TLS configuration helpers
// ────────────────────────────────────────────────────────────────────────────

// TLSConfig describes how a TLS listener or client should be configured.
type TLSConfig struct {
	// CertFile and KeyFile hold PEM-encoded server certificate and private key.
	// Required for server mode.
	CertFile string
	KeyFile  string

	// CAFile is used for mutual TLS verification (server verifying client certs).
	// Leave empty to skip client-cert validation.
	CAFile string

	// ClientCertFile / ClientKeyFile are used when this side acts as mTLS client.
	ClientCertFile string
	ClientKeyFile  string

	// MinVersion is the minimum TLS version to accept (default: TLS 1.2).
	MinVersion uint16

	// InsecureSkipVerify disables certificate verification (DEV ONLY — never
	// set true in production).
	InsecureSkipVerify bool

	// ServerName is set in client configs for SNI.
	ServerName string
}

// ServerTLSConfig returns a *tls.Config for a TLS server using the provided
// certificate files.  If cfg.CAFile is set, mutual TLS is enabled and the
// server will require + verify client certificates.
func ServerTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, errors.New("handler: CertFile and KeyFile are required for server TLS")
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("handler: load server cert/key: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   orDefault(cfg.MinVersion, tls.VersionTLS12),
		CipherSuites: preferredCipherSuites(),
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}

	if cfg.CAFile != "" {
		pool, err := loadCertPool(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("handler: load CA for mTLS: %w", err)
		}
		tlsCfg.ClientCAs  = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		log.Println("[tls] mutual TLS enabled — client certs required")
	}

	return tlsCfg, nil
}

// ClientTLSConfig returns a *tls.Config for an HTTPS client connecting to a
// server with the given CA.  If mTLS client cert files are provided they are
// loaded and presented to the server.
func ClientTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion:         orDefault(cfg.MinVersion, tls.VersionTLS12),
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec
		ServerName:         cfg.ServerName,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}

	if cfg.CAFile != "" {
		pool, err := loadCertPool(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("handler: load CA: %w", err)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.ClientCertFile != "" && cfg.ClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("handler: load client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Self-signed certificate generation (dev / test use only)
// ────────────────────────────────────────────────────────────────────────────

// SelfSignedCert generates an ephemeral ECDSA P-256 self-signed certificate.
// The returned *tls.Config is suitable for a local dev/test TLS listener.
// DO NOT use in production — use properly signed certs from scripts/gen_certs.sh.
func SelfSignedCert(hosts ...string) (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("handler: generate key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	if len(tmpl.DNSNames) == 0 && len(tmpl.IPAddresses) == 0 {
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("handler: create cert: %w", err)
	}
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("handler: marshal key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM  := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("handler: key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP connection-level utilities
// ────────────────────────────────────────────────────────────────────────────

// ConnTracker tracks active connections and their metadata.
type ConnTracker struct {
	mu    sync.Mutex
	conns map[net.Conn]connMeta
	total atomic.Int64
}

type connMeta struct {
	remoteAddr string
	opened     time.Time
}

// NewConnTracker returns an initialised ConnTracker.
func NewConnTracker() *ConnTracker {
	return &ConnTracker{conns: make(map[net.Conn]connMeta)}
}

// ConnState implements the http.Server.ConnState callback.
func (ct *ConnTracker) ConnState(c net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		ct.mu.Lock()
		ct.conns[c] = connMeta{remoteAddr: c.RemoteAddr().String(), opened: time.Now()}
		ct.mu.Unlock()
		ct.total.Add(1)
	case http.StateClosed, http.StateHijacked:
		ct.mu.Lock()
		delete(ct.conns, c)
		ct.mu.Unlock()
	}
}

// ActiveCount returns the number of currently open connections.
func (ct *ConnTracker) ActiveCount() int {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	return len(ct.conns)
}

// TotalCount returns total accepted connections since the tracker was created.
func (ct *ConnTracker) TotalCount() int64 { return ct.total.Load() }

// CloseAll forcefully closes all tracked connections.
func (ct *ConnTracker) CloseAll() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	for c := range ct.conns {
		c.Close()
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Graceful shutdown helper
// ────────────────────────────────────────────────────────────────────────────

// GracefulShutdown shuts down srv within timeout, then force-closes remaining
// connections via the tracker.
func GracefulShutdown(srv *http.Server, tracker *ConnTracker, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	err := srv.Shutdown(ctx)
	if tracker != nil {
		tracker.CloseAll()
	}
	return err
}

// ────────────────────────────────────────────────────────────────────────────
// Request fingerprinting / entropy detection
// ────────────────────────────────────────────────────────────────────────────

// RequestFingerprint computes a stable SHA-256 fingerprint of an HTTP request
// that can be used for replay detection.  It hashes: method + URI + ordered
// significant headers (excluding Date and dynamic hop-by-hop headers).
func RequestFingerprint(r *http.Request) [32]byte {
	h := sha256.New()
	fmt.Fprintf(h, "%s %s\n", r.Method, r.URL.RequestURI())
	for _, key := range []string{"Content-Type", "User-Agent", "Accept", "X-Request-Id"} {
		if v := r.Header.Get(key); v != "" {
			fmt.Fprintf(h, "%s: %s\n", key, v)
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ────────────────────────────────────────────────────────────────────────────
// Rate-limiting (token bucket, thread-safe)
// ────────────────────────────────────────────────────────────────────────────

// RateLimiter is a simple token-bucket rate limiter keyed by remote IP.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    int           // tokens per second
	burst   int           // maximum burst size
	ttl     time.Duration // bucket idle expiry
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// NewRateLimiter creates a RateLimiter with the given sustained rate (req/s)
// and burst size.  Idle buckets are cleaned up after ttl.
func NewRateLimiter(ratePerSec, burst int, ttl time.Duration) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*bucket),
		rate:    ratePerSec,
		burst:   burst,
		ttl:     ttl,
	}
	go rl.cleanup()
	return rl
}

// Allow returns true if the remote key (usually IP) is within its rate limit.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(rl.burst), lastSeen: now}
		rl.buckets[key] = b
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * float64(rl.rate)
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastSeen = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// cleanup periodically evicts idle buckets.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.ttl / 2)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-rl.ttl)
		for k, b := range rl.buckets {
			if b.lastSeen.Before(cutoff) {
				delete(rl.buckets, k)
			}
		}
		rl.mu.Unlock()
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Replay-nonce cache
// ────────────────────────────────────────────────────────────────────────────

// NonceCache tracks seen nonces to prevent replay attacks.
// Nonces expire after ttl.
type NonceCache struct {
	mu    sync.Mutex
	seen  map[[32]byte]time.Time
	ttl   time.Duration
}

// NewNonceCache creates a NonceCache with the given TTL.
func NewNonceCache(ttl time.Duration) *NonceCache {
	nc := &NonceCache{seen: make(map[[32]byte]time.Time), ttl: ttl}
	go nc.cleanup()
	return nc
}

// Check returns true if the nonce has NOT been seen before (i.e. it is fresh).
// Calling Check also marks the nonce as seen.
func (nc *NonceCache) Check(nonce [32]byte) bool {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	if _, exists := nc.seen[nonce]; exists {
		return false // replay
	}
	nc.seen[nonce] = time.Now()
	return true
}

func (nc *NonceCache) cleanup() {
	ticker := time.NewTicker(nc.ttl / 2)
	defer ticker.Stop()
	for range ticker.C {
		nc.mu.Lock()
		cutoff := time.Now().Add(-nc.ttl)
		for k, t := range nc.seen {
			if t.Before(cutoff) {
				delete(nc.seen, k)
			}
		}
		nc.mu.Unlock()
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Drain + read body safely
// ────────────────────────────────────────────────────────────────────────────

// ReadBody reads up to maxBytes from an HTTP request body.
// Returns an error if maxBytes is exceeded.
func ReadBody(r *http.Request, maxBytes int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	lr := io.LimitReader(r.Body, maxBytes+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("request body exceeds %d bytes", maxBytes)
	}
	return data, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ────────────────────────────────────────────────────────────────────────────

func loadCertPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid certificates found in %s", caFile)
	}
	return pool, nil
}

func orDefault(v, def uint16) uint16 {
	if v == 0 {
		return def
	}
	return v
}

// preferredCipherSuites returns a safe set of TLS 1.2 cipher suites.
// TLS 1.3 cipher suites are chosen automatically by the Go runtime.
func preferredCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
}
