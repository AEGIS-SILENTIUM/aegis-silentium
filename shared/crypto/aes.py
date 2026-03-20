#!/usr/bin/env python3
"""
AEGIS-Advanced Cryptography Suite
===================================
AES-256-GCM, AES-256-CBC, RSA-4096, ECDH, HMAC, PBKDF2,
key management, message sealing, traffic obfuscation.
"""
import os, hmac as _hmac, hashlib, base64, struct, json, time
from typing import Tuple, Optional

import logging as _crypto_log
_crypto_logger = _crypto_log.getLogger("aegis.crypto")

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, serialization, padding as asym_pad
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as rsa_pad
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    import logging as _clog
    _clog.getLogger("aegis.crypto").critical(
        "cryptography library unavailable — using WEAK fallback. Install: pip install cryptography")
    _CRYPTO_STRONG = False
    HAS_CRYPTO = False
    _crypto_logger.warning(
        "SECURITY DEGRADATION: 'cryptography' package not installed. "
        "Falling back to stdlib-only XOR+HMAC construction which provides "
        "confidentiality but NOT authenticated encryption (no AES-GCM). "
        "Install with: pip install cryptography>=41.0.0 "
        "NEVER deploy to production without the cryptography package."
    )

# ══════════════════════════════════════════════
# AES-256-GCM (authenticated, preferred)
# ══════════════════════════════════════════════

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM. Returns nonce(12)+tag(16)+ct."""
    if len(key) != 32:
        key = hashlib.sha256(key).digest()
    if HAS_CRYPTO:
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext, aad or None)
        return nonce + ct
    return _fallback_encrypt(key, plaintext)

def aes_gcm_decrypt(key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    if len(key) != 32:
        key = hashlib.sha256(key).digest()
    if HAS_CRYPTO:
        return AESGCM(key).decrypt(data[:12], data[12:], aad or None)
    return _fallback_decrypt(key, data)

# ══════════════════════════════════════════════
# AES-256-CBC (compatibility)
# ══════════════════════════════════════════════

def aes_cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-CBC. Returns IV(16)+ct."""
    key = _norm_key(key)
    if HAS_CRYPTO:
        iv = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return iv + enc.update(padded) + enc.finalize()
    return _fallback_encrypt(key, plaintext)

def aes_cbc_decrypt(key: bytes, data: bytes) -> bytes:
    key = _norm_key(key)
    if HAS_CRYPTO:
        dec = Cipher(algorithms.AES(key), modes.CBC(data[:16])).decryptor()
        padded = dec.update(data[16:]) + dec.finalize()
        unpad = sym_padding.PKCS7(128).unpadder()
        return unpad.update(padded) + unpad.finalize()
    return _fallback_decrypt(key, data)

def _norm_key(k: bytes) -> bytes:
    if len(k) in (16, 24, 32):
        return k
    return hashlib.sha256(k).digest()

# ── Pure stdlib fallback ──────────────────────
def _fallback_encrypt(key: bytes, pt: bytes) -> bytes:
    _crypto_logger.warning(
        "USING FALLBACK ENCRYPTION (XOR+HMAC-SHA256) — "
        "not AES-GCM. Install 'cryptography' for authenticated encryption."
    )
    enc_k = hashlib.sha256(key + b"enc").digest()[:16]
    mac_k = hashlib.sha256(key + b"mac").digest()
    iv    = os.urandom(16)
    ks    = b"".join(hashlib.sha256(enc_k + iv + i.to_bytes(4,"big")).digest()
                     for i in range((len(pt)//32)+2))
    ct    = bytes(a^b for a,b in zip(pt, ks))
    tag   = _hmac.new(mac_k, iv+ct, hashlib.sha256).digest()
    return iv + tag + ct

def _fallback_decrypt(key: bytes, data: bytes) -> bytes:
    enc_k = hashlib.sha256(key + b"enc").digest()[:16]
    mac_k = hashlib.sha256(key + b"mac").digest()
    iv, tag, ct = data[:16], data[16:48], data[48:]
    if not _hmac.compare_digest(_hmac.new(mac_k,iv+ct,hashlib.sha256).digest(), tag):
        raise ValueError("HMAC mismatch")
    ks = b"".join(hashlib.sha256(enc_k + iv + i.to_bytes(4,"big")).digest()
                  for i in range((len(ct)//32)+2))
    return bytes(a^b for a,b in zip(ct, ks))

# ══════════════════════════════════════════════
# Fernet (C2 protocol layer)
# ══════════════════════════════════════════════

def make_fernet_key(secret: bytes, salt: bytes = b"aegis_fernet_v4",
                    iterations: int = 200000) -> bytes:
    if HAS_CRYPTO:
        raw = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                          salt=salt, iterations=iterations).derive(secret)
    else:
        raw = hashlib.pbkdf2_hmac("sha256", secret, salt, iterations, dklen=32)
    return base64.urlsafe_b64encode(raw)

def fernet_encrypt(key_b64: bytes, data: dict) -> str:
    if HAS_CRYPTO:
        return Fernet(key_b64).encrypt(json.dumps(data).encode()).decode()
    raw = base64.urlsafe_b64decode(key_b64)
    return base64.urlsafe_b64encode(aes_gcm_encrypt(raw, json.dumps(data).encode())).decode()

def fernet_decrypt(key_b64: bytes, token: str) -> dict:
    if HAS_CRYPTO:
        return json.loads(Fernet(key_b64).decrypt(token.encode()).decode())
    raw = base64.urlsafe_b64decode(key_b64)
    ct  = base64.urlsafe_b64decode(token.encode())
    return json.loads(aes_gcm_decrypt(raw, ct).decode())

# ══════════════════════════════════════════════
# RSA-4096
# ══════════════════════════════════════════════

def rsa_generate_keypair(key_size: int = 4096) -> Tuple[bytes, bytes]:
    if not HAS_CRYPTO: raise RuntimeError("cryptography required")
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return (
        priv.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()),
        priv.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
    )

def rsa_encrypt(public_pem: bytes, pt: bytes) -> bytes:
    if not HAS_CRYPTO: raise RuntimeError("cryptography required")
    pub = serialization.load_pem_public_key(public_pem)
    return pub.encrypt(pt, rsa_pad.OAEP(
        mgf=rsa_pad.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def rsa_decrypt(private_pem: bytes, ct: bytes) -> bytes:
    if not HAS_CRYPTO: raise RuntimeError("cryptography required")
    priv = serialization.load_pem_private_key(private_pem, password=None)
    return priv.decrypt(ct, rsa_pad.OAEP(
        mgf=rsa_pad.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def rsa_sign(private_pem: bytes, data: bytes) -> bytes:
    if not HAS_CRYPTO: raise RuntimeError("cryptography required")
    priv = serialization.load_pem_private_key(private_pem, password=None)
    return priv.sign(data, rsa_pad.PSS(
        mgf=rsa_pad.MGF1(hashes.SHA256()), salt_length=rsa_pad.PSS.MAX_LENGTH),
        hashes.SHA256())

def rsa_verify(public_pem: bytes, sig: bytes, data: bytes) -> bool:
    if not HAS_CRYPTO: raise RuntimeError("cryptography required")
    try:
        pub = serialization.load_pem_public_key(public_pem)
        pub.verify(sig, data, rsa_pad.PSS(
            mgf=rsa_pad.MGF1(hashes.SHA256()), salt_length=rsa_pad.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
    except Exception:
        return False

# ══════════════════════════════════════════════
# ECDH P-256 key exchange
# ══════════════════════════════════════════════

def ecdh_generate_keypair() -> Tuple[bytes, bytes]:
    if not HAS_CRYPTO: raise RuntimeError("cryptography required")
    priv = ec.generate_private_key(ec.SECP256R1())
    return (
        priv.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()),
        priv.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
    )

def ecdh_derive_shared(private_pem: bytes, peer_public_pem: bytes) -> bytes:
    if not HAS_CRYPTO: raise RuntimeError("cryptography required")
    priv     = serialization.load_pem_private_key(private_pem, password=None)
    peer_pub = serialization.load_pem_public_key(peer_public_pem)
    shared   = priv.exchange(ec.ECDH(), peer_pub)
    return HKDF(algorithm=hashes.SHA256(), length=32,
                 salt=b"aegis-ecdh-v4", info=b"aegis-session").derive(shared)

# ══════════════════════════════════════════════
# KDF helpers
# ══════════════════════════════════════════════

def pbkdf2(password: bytes, salt: bytes = None,
           iterations: int = 200000, length: int = 32) -> Tuple[bytes, bytes]:
    if salt is None: salt = os.urandom(32)
    if HAS_CRYPTO:
        key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length,
                          salt=salt, iterations=iterations).derive(password)
    else:
        key = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=length)
    return key, salt

def hkdf_expand(km: bytes, length: int = 32, info: bytes = b"aegis",
                salt: bytes = None) -> bytes:
    if HAS_CRYPTO:
        return HKDF(algorithm=hashes.SHA256(), length=length,
                     salt=salt, info=info).derive(km)
    prk = _hmac.new(salt or b"\x00"*32, km, hashlib.sha256).digest()
    t   = b""; okm = b""
    for i in range(1, (length//32)+2):
        t   = _hmac.new(prk, t+info+bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

# ══════════════════════════════════════════════
# HMAC & hash
# ══════════════════════════════════════════════

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()

def hmac_verify(key: bytes, data: bytes, expected: bytes) -> bool:
    return _hmac.compare_digest(hmac_sha256(key, data), expected)

def sha256(data: bytes) -> bytes: return hashlib.sha256(data).digest()
def sha512(data: bytes) -> bytes: return hashlib.sha512(data).digest()
def sha256_hex(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def random_bytes(n: int = 32) -> bytes: return os.urandom(n)
def random_hex(n: int = 16) -> str: return os.urandom(n).hex()

# ══════════════════════════════════════════════
# Sealed message envelope (sign + encrypt)
# ══════════════════════════════════════════════

def seal_message(data: dict, sym_key: bytes,
                 sign_key: Optional[bytes] = None) -> str:
    raw = json.dumps(data).encode()
    ct  = aes_gcm_encrypt(sym_key, raw)
    env = {"v": 4, "ts": int(time.time()), "ct": base64.b64encode(ct).decode()}
    if sign_key:
        env["sig"] = hmac_sha256(sign_key, ct).hex()
    return base64.urlsafe_b64encode(json.dumps(env).encode()).decode()

def open_message(token: str, sym_key: bytes,
                 sign_key: Optional[bytes] = None) -> dict:
    env = json.loads(base64.urlsafe_b64decode(token.encode()).decode())
    ct  = base64.b64decode(env["ct"])
    if abs(time.time() - env.get("ts", 0)) > 300:
        raise ValueError("Timestamp out of range — possible replay attack")
    if sign_key:
        if not _hmac.compare_digest(env.get("sig",""), hmac_sha256(sign_key, ct).hex()):
            raise ValueError("HMAC signature mismatch — tampered message")
    return json.loads(aes_gcm_decrypt(sym_key, ct).decode())

# ══════════════════════════════════════════════
# Traffic obfuscation
# ══════════════════════════════════════════════

def xor_obfuscate(data: bytes, key: bytes) -> bytes:
    kc = (key * ((len(data)//len(key))+2))[:len(data)]
    return bytes(a^b for a,b in zip(data, kc))

def pad_to_size(data: bytes, target: int = 1024) -> bytes:
    """Pad to fixed size to defeat traffic-analysis."""
    if len(data) + 2 > target: target = len(data) + 2 + 16
    return struct.pack(">H", len(data)) + data + os.urandom(target - len(data) - 2)

def unpad_from_size(blob: bytes) -> bytes:
    n = struct.unpack(">H", blob[:2])[0]
    return blob[2:2+n]

# ══════════════════════════════════════════════
# File integrity
# ══════════════════════════════════════════════

def file_hash(path: str, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
    return h.hexdigest()

def verify_file_integrity(path: str, expected: str, algo: str = "sha256") -> bool:
    try: return file_hash(path, algo) == expected
    except Exception: return False

# ══════════════════════════════════════════════
# Key Manager
# ══════════════════════════════════════════════

class KeyManager:
    def __init__(self):
        self._store: dict = {}
        self._active: str = ""

    def generate(self, algo: str = "aes256", ttl: int = 3600) -> str:
        key_id = os.urandom(8).hex()
        key    = os.urandom(32 if algo != "aes128" else 16)
        self._store[key_id] = {"key": key, "exp": time.time()+ttl, "algo": algo}
        self._active = key_id
        return key_id

    def get(self, key_id: str = None) -> Optional[bytes]:
        kid = key_id or self._active
        rec = self._store.get(kid)
        if not rec or time.time() > rec["exp"]:
            if rec: del self._store[kid]
            return None
        return rec["key"]

    def rotate(self, algo: str = "aes256", ttl: int = 3600) -> str:
        old = list(self._store.keys())
        new_id = self.generate(algo, ttl)
        for oid in old:
            if oid in self._store: self._store[oid]["exp"] = time.time() + 10
        return new_id

    def import_key(self, key: bytes, algo: str = "aes256", ttl: int = 3600) -> str:
        kid = os.urandom(8).hex()
        self._store[kid] = {"key": key, "exp": time.time()+ttl, "algo": algo}
        self._active = kid
        return kid

    def purge_expired(self) -> int:
        now  = time.time()
        dead = [k for k,v in self._store.items() if v["exp"] < now]
        for k in dead: del self._store[k]
        return len(dead)

    def list_keys(self) -> list:
        now = time.time()
        return [{"id":k,"algo":v["algo"],"ttl":int(v["exp"]-now),"active":k==self._active}
                for k,v in self._store.items() if v["exp"]>now]

KEY_MANAGER = KeyManager()

if __name__ == "__main__":
    k = os.urandom(32)
    assert aes_gcm_decrypt(k, aes_gcm_encrypt(k, b"test")) == b"test", "GCM fail"
    s = seal_message({"x":1}, k, k)
    assert open_message(s, k, k)["x"] == 1, "seal fail"
    print("All crypto tests passed.")


# ════════════════════════════════════════════════════════════════════════════
# Compatibility API — class-based wrappers matching __init__.py exports
# ════════════════════════════════════════════════════════════════════════════

SESSION_KEY_SIZE = 32
NONCE_SIZE = 12

class AESCipher:
    """AES-256-GCM cipher wrapper."""
    def __init__(self, key: bytes):
        self.key = key if len(key) == 32 else hashlib.sha256(key).digest()
    def encrypt(self, pt: bytes, aad: bytes = b"") -> bytes:
        return aes_gcm_encrypt(self.key, pt, aad)
    def decrypt(self, ct: bytes, aad: bytes = b"") -> bytes:
        return aes_gcm_decrypt(self.key, ct, aad)

class FernetCipher:
    """Fernet-based symmetric cipher."""
    def __init__(self, secret: bytes):
        self._key = make_fernet_key(secret)
    def encrypt(self, data: dict) -> str:
        return fernet_encrypt(self._key, data)
    def decrypt(self, token: str) -> dict:
        return fernet_decrypt(self._key, token)

class RSACipher:
    """RSA-4096 asymmetric cipher."""
    def __init__(self, public_pem: bytes = None, private_pem: bytes = None):
        self.public_pem = public_pem
        self.private_pem = private_pem
    def encrypt(self, pt: bytes) -> bytes:
        return rsa_encrypt(self.public_pem, pt)
    def decrypt(self, ct: bytes) -> bytes:
        return rsa_decrypt(self.private_pem, ct)
    def sign(self, data: bytes) -> bytes:
        return rsa_sign(self.private_pem, data)
    def verify(self, sig: bytes, data: bytes) -> bool:
        return rsa_verify(self.public_pem, sig, data)
    @staticmethod
    def generate(key_size: int = 4096):
        priv_pem, pub_pem = rsa_generate_keypair(key_size)
        return RSACipher(public_pem=pub_pem, private_pem=priv_pem)

class ECDHKeyExchange:
    """ECDH P-256 key exchange wrapper."""
    def __init__(self):
        self._priv_pem, self.public_pem = ecdh_generate_keypair()
    def derive(self, peer_public_pem: bytes) -> bytes:
        return ecdh_derive_shared(self._priv_pem, peer_public_pem)

class PBKDF2Key:
    """PBKDF2-SHA256 key derivation."""
    def __init__(self, password: bytes, iterations: int = 200000):
        self._password = password
        self._iterations = iterations
    def derive(self, salt: bytes = None, length: int = 32):
        return pbkdf2(self._password, salt, self._iterations, length)

# Convenience functions
def encrypt_message(data: dict, key: bytes, sign_key: bytes = None) -> str:
    return seal_message(data, key, sign_key)

def decrypt_message(token: str, key: bytes, sign_key: bytes = None) -> dict:
    return open_message(token, key, sign_key)

def generate_key(length: int = 32) -> bytes:
    return random_bytes(length)

def hmac_sign(key: bytes, data: bytes) -> bytes:
    return hmac_sha256(key, data)

def secure_zero(buf: bytearray) -> None:
    """Best-effort in-place zeroing of a bytearray."""
    for i in range(len(buf)):
        buf[i] = 0
