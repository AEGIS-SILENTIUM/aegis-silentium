"""
AEGIS-SILENTIUM Shared Profiles Package
=====================================
Malleable C2 profile engine — Python implementation mirroring the Go relay.

Exports:
    MalleableProfile  — loaded from YAML or dict
    ProfileEngine     — encode/decode helper
    TransformBlock    — forward/reverse transform chain
    Transform         — single transform operation

Usage:
    from shared.profiles import ProfileEngine

    engine = ProfileEngine()
    engine.load("/path/to/google-analytics.yaml")

    # Encode beacon payload for wire transmission
    wire = engine.encode_client(json_bytes)

    # Decode server response
    plaintext = engine.decode_server(response_bytes)
"""

from .malleable import MalleableProfile, ProfileEngine, Transform, TransformBlock

__all__ = ["MalleableProfile", "ProfileEngine", "Transform", "TransformBlock"]
__version__ = "5.0"
