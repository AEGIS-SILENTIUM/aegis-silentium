# shared/crypto/__init__.py - Crypto module with strength enforcement
"""
AEGIS-SILENTIUM v12 Crypto Module

Provides AES-256-GCM and ECDHE-P256 using the `cryptography` library.
If that library is unavailable, a WEAK fallback is used and a CRITICAL
warning is emitted. NEVER deploy without the `cryptography` library installed.

  pip install cryptography>=43
"""
import os

def require_strong_crypto() -> None:
    """Raise RuntimeError if the strong crypto library is not available."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:
        raise RuntimeError(
            "Strong crypto unavailable: pip install cryptography>=43\n"
            f"Original error: {e}"
        )

def is_strong_crypto_available() -> bool:
    """Return True if the strong crypto library is available."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return True
    except ImportError:
        return False

CRYPTO_STRONG = is_strong_crypto_available()
