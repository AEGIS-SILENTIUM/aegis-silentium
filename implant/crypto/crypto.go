// Package crypto provides authenticated encryption for all implant traffic.
// Uses AES-256-GCM (primary) with ChaCha20-Poly1305 fallback.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	AESKeyLen   = 32 // AES-256
	NonceLen    = 12 // GCM standard nonce
	TagLen      = 16 // GCM authentication tag
)

// Session holds a derived symmetric key for a single beacon session.
type Session struct {
	key    []byte // 32-byte session key
	seqTx  uint64 // transmit sequence counter (prevents nonce reuse)
	seqRx  uint64 // receive sequence counter
}

// ── ECDH Key Exchange ─────────────────────────────────────────────────────────

// ECDHKeyPair holds an ephemeral P-256 key pair.
type ECDHKeyPair struct {
	priv *ecdh.PrivateKey
	Pub  []byte // uncompressed 65-byte public key
}

// NewECDHKeyPair generates a fresh ephemeral ECDH P-256 key pair.
func NewECDHKeyPair() (*ECDHKeyPair, error) {
	curve := ecdh.P256()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ECDHKeyPair{
		priv: priv,
		Pub:  priv.PublicKey().Bytes(),
	}, nil
}

// DeriveSession performs ECDH with the relay's public key and derives a
// symmetric session key via HKDF-SHA256.
func (kp *ECDHKeyPair) DeriveSession(relayPubBytes []byte, info []byte) (*Session, error) {
	curve := ecdh.P256()
	relayPub, err := curve.NewPublicKey(relayPubBytes)
	if err != nil {
		return nil, err
	}
	shared, err := kp.priv.ECDH(relayPub)
	if err != nil {
		return nil, err
	}
	// HKDF-SHA256: expand shared secret into 32-byte session key
	hk := hkdf.New(sha256.New, shared, nil, info)
	key := make([]byte, AESKeyLen)
	if _, err := io.ReadFull(hk, key); err != nil {
		return nil, err
	}
	return &Session{key: key}, nil
}

// ── AES-256-GCM Encryption ────────────────────────────────────────────────────

// Encrypt encrypts plaintext with AES-256-GCM. The nonce is derived from the
// transmit sequence counter to guarantee uniqueness without storing random nonces.
// Wire format: [8-byte seqno][12-byte nonce][ciphertext+tag]
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Derive nonce from sequence counter (deterministic, collision-free)
	nonce := make([]byte, NonceLen)
	binary.BigEndian.PutUint64(nonce[:8], s.seqTx)
	// pad remaining 4 bytes with zeros (seqTx is unique per message)

	seq := s.seqTx
	s.seqTx++

	out := make([]byte, 8+NonceLen, 8+NonceLen+len(plaintext)+TagLen)
	binary.BigEndian.PutUint64(out[:8], seq)
	copy(out[8:], nonce)
	out = gcm.Seal(out, nonce, plaintext, out[:8]) // AAD = seqno
	return out, nil
}

// Decrypt decrypts a message produced by Encrypt.
func (s *Session) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 8+NonceLen+TagLen {
		return nil, errors.New("crypto: ciphertext too short")
	}

	seq := binary.BigEndian.Uint64(ciphertext[:8])
	// Replay protection: seq must be >= expected rx counter
	if seq < s.seqRx {
		return nil, errors.New("crypto: replay detected")
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := ciphertext[8 : 8+NonceLen]
	data := ciphertext[8+NonceLen:]
	plain, err := gcm.Open(nil, nonce, data, ciphertext[:8])
	if err != nil {
		return nil, err
	}

	if seq >= s.seqRx {
		s.seqRx = seq + 1
	}
	return plain, nil
}

// ── ChaCha20-Poly1305 (fallback / DNS channel) ────────────────────────────────

// EncryptChaCha encrypts with ChaCha20-Poly1305 using a random nonce.
// Useful for DNS channels where GCM block alignment matters less than size.
func EncryptChaCha(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptChaCha decrypts output of EncryptChaCha.
func DecryptChaCha(key, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("crypto: chacha ciphertext too short")
	}
	return aead.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}

// ── Utility ───────────────────────────────────────────────────────────────────

// Wipe zeroes a byte slice. Call on all key material before releasing.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// RandBytes returns n cryptographically random bytes.
func RandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}
