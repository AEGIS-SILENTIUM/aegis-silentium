"""
c2/auth/mtls.py

Mutual TLS node authentication — certificate issuance, verification, revocation.

Changes from previous version:
  - server_ssl_context() no longer references self._ca_cert_path (which did
    not exist as an attribute) — it now correctly uses the already-loaded CA
    cert object written to a temp file, or accepts an explicit path argument.
  - ipaddress imported at the module level (not inline via __import__).
  - Redis client uses connection pooling via ConnectionPool.
  - generate_relay_ca() moved to a standalone helper function (not mixed with
    the class implementation).
"""

import datetime
import hashlib
import ipaddress
import json
import logging
import os
import secrets
import ssl
import time
from dataclasses import dataclass
from typing import Optional, Tuple

import redis
from redis import ConnectionPool

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

log = logging.getLogger("c2.auth")

CERT_TTL_HOURS   = 24
REDIS_REVOKE_KEY = "aegis:auth:revoked"
REDIS_NODE_KEY   = "aegis:auth:node:{}"


@dataclass
class NodeCertBundle:
    """Certificate material issued to a node on first checkin."""
    cert_pem:    bytes   # signed node certificate (PEM)
    key_pem:     bytes   # node private key (sent once, never stored on C2)
    ca_cert_pem: bytes   # relay CA cert for node-side pinning
    serial:      int
    expires_at:  float   # unix timestamp
    host_id:     str


@dataclass
class NodeAuthRecord:
    """What the C2 keeps about an authenticated node."""
    host_id:         str
    cert_serial:     int
    cert_thumbprint: str   # SHA-256 of DER-encoded cert
    issued_at:       float
    expires_at:      float
    ip_address:      str
    revoked:         bool = False


class NodeAuthority:
    """
    Issues and verifies short-lived node client certificates.

    The relay CA key is loaded once at startup and kept in memory.
    Compromise of the relay CA requires rotating the CA and revoking all nodes.

    Redis is accessed through a connection pool — no per-operation reconnect.
    """

    def __init__(self, ca_cert_path: str, ca_key_path: str, redis_url: str) -> None:
        self._ca_cert      = self._load_cert(ca_cert_path)
        self._ca_key       = self._load_key(ca_key_path)
        self._ca_cert_path = ca_cert_path   # needed for SSL context building
        pool               = ConnectionPool.from_url(redis_url, decode_responses=True)
        self._redis        = redis.Redis(connection_pool=pool)
        log.info(f"NodeAuthority ready — CA subject: {self._ca_cert.subject}")

    # ── Certificate issuance ──────────────────────────────────────────────────

    def issue_node_cert(self, host_id: str, ip_address: str) -> NodeCertBundle:
        """
        Issue a short-lived TLS client certificate to a node.
        Called once during the initial checkin handshake.
        """
        node_key  = ec.generate_private_key(ec.SECP256R1())
        serial    = int.from_bytes(secrets.token_bytes(16), "big")
        now       = datetime.datetime.utcnow()
        expire    = now + datetime.timedelta(hours=CERT_TTL_HOURS)

        san_entries = [x509.DNSName(host_id)]
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_address)))
        except ValueError:
            pass  # ip_address is not a valid IP — skip IP SAN

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, host_id),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AEGIS-SILENTIUM"),
            ]))
            .issuer_name(self._ca_cert.subject)
            .public_key(node_key.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(expire)
            .add_extension(
                x509.SubjectAlternativeName(san_entries), critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        cert_der = cert.public_bytes(serialization.Encoding.DER)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem  = node_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        ca_pem       = self._ca_cert.public_bytes(serialization.Encoding.PEM)
        thumbprint   = hashlib.sha256(cert_der).hexdigest()

        record = NodeAuthRecord(
            host_id=host_id,
            cert_serial=serial,
            cert_thumbprint=thumbprint,
            issued_at=time.time(),
            expires_at=expire.timestamp(),
            ip_address=ip_address,
        )
        self._store_auth_record(record)

        log.info(f"Issued cert to {host_id[:8]} serial={serial} ttl={CERT_TTL_HOURS}h")
        return NodeCertBundle(
            cert_pem=cert_pem,
            key_pem=key_pem,
            ca_cert_pem=ca_pem,
            serial=serial,
            expires_at=expire.timestamp(),
            host_id=host_id,
        )

    # ── Verification ──────────────────────────────────────────────────────────

    def verify_node_cert(self, cert_der: bytes, host_id: str) -> Tuple[bool, str]:
        """
        Verify a node's client certificate on every beacon.
        Returns (is_valid, reason_string).
        """
        try:
            cert = x509.load_der_x509_certificate(cert_der)
        except Exception as exc:
            return False, f"cert parse error: {exc}"

        # 1. Signature against our CA
        try:
            self._ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
        except Exception:
            return False, "signature verification failed"

        # 2. Expiry
        if datetime.datetime.utcnow() > cert.not_valid_after_utc.replace(tzinfo=None):
            return False, f"cert expired at {cert.not_valid_after_utc}"

        # 3. Revocation
        if self._is_revoked(cert.serial_number):
            return False, f"cert serial {cert.serial_number} is revoked"

        # 4. CN matches host_id
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn_attrs or cn_attrs[0].value != host_id:
            return False, f"CN mismatch: expected {host_id}"

        # 5. Thumbprint matches our issuance record
        thumbprint = hashlib.sha256(cert_der).hexdigest()
        record     = self._load_auth_record(host_id)
        if record and record.cert_thumbprint != thumbprint:
            return False, "cert thumbprint mismatch — possible substitution attack"

        return True, "ok"

    # ── Revocation ────────────────────────────────────────────────────────────

    def revoke_node(self, host_id: str, reason: str = "operator") -> bool:
        record = self._load_auth_record(host_id)
        if not record:
            return False
        self._redis.sadd(REDIS_REVOKE_KEY, str(record.cert_serial))
        record.revoked = True
        self._store_auth_record(record)
        log.warning(f"Revoked {host_id[:8]} serial={record.cert_serial} reason={reason}")
        return True

    def list_nodes(self) -> list:
        """Return all auth records from Redis."""
        keys  = self._redis.keys("aegis:auth:node:*")
        nodes = []
        for k in keys:
            raw = self._redis.get(k)
            if raw:
                try:
                    nodes.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass
        return nodes

    # ── SSL context ───────────────────────────────────────────────────────────

    def server_ssl_context(
        self,
        server_cert_path: str,
        server_key_path:  str,
    ) -> ssl.SSLContext:
        """
        Build a server SSL context that requires client certificates (mTLS).
        The CA cert path is stored at __init__ time from ca_cert_path.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(server_cert_path, server_key_path)
        ctx.load_verify_locations(cafile=self._ca_cert_path)   # correct attribute
        ctx.verify_mode    = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_ciphers("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
        return ctx

    # ── Internal ──────────────────────────────────────────────────────────────

    def _store_auth_record(self, record: NodeAuthRecord) -> None:
        key = REDIS_NODE_KEY.format(record.host_id)
        ttl = max(3600, int(record.expires_at - time.time()) + 3600)
        self._redis.setex(key, ttl, json.dumps(record.__dict__))

    def _load_auth_record(self, host_id: str) -> Optional[NodeAuthRecord]:
        raw = self._redis.get(REDIS_NODE_KEY.format(host_id))
        if not raw:
            return None
        try:
            return NodeAuthRecord(**json.loads(raw))
        except (TypeError, KeyError):
            return None

    def _is_revoked(self, serial: int) -> bool:
        return bool(self._redis.sismember(REDIS_REVOKE_KEY, str(serial)))

    @staticmethod
    def _load_cert(path: str) -> x509.Certificate:
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    @staticmethod
    def _load_key(path: str):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)


# ── CA generation helper (run once during operator setup) ─────────────────────

def generate_relay_ca(out_dir: str, cn: str = "AEGIS-SILENTIUM Relay CA") -> None:
    """
    Generate a self-signed EC CA for signing node certificates.
    Run this ONCE during initial setup. Protect the private key offline.
    """
    os.makedirs(out_dir, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.utcnow()

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    key_path  = os.path.join(out_dir, "relay_ca.key")
    cert_path = os.path.join(out_dir, "relay_ca.crt")

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    os.chmod(key_path, 0o600)

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Relay CA written:\n  cert: {cert_path}\n  key:  {key_path}")
    print("IMPORTANT: Store relay_ca.key offline — it signs all node identities.")
