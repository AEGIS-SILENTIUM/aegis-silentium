"""
AEGIS-SILENTIUM — Security Headers Middleware
==============================================
Applies a comprehensive set of security headers to every response:

  Content-Security-Policy   — restricts script/style/frame origins
  Strict-Transport-Security — force HTTPS (HSTS)
  X-Content-Type-Options    — prevent MIME sniffing
  X-Frame-Options           — clickjacking protection
  Referrer-Policy           — no-referrer for privacy
  Permissions-Policy        — disable unused browser APIs
  X-Correlation-ID          — echo back the request correlation ID

Also adds a request correlation ID to every incoming request
(stored in a contextvar for structured logging).
"""
from __future__ import annotations

import secrets
import time

from flask import Flask, g, request


_CSP = (
    "default-src 'none'; "
    "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com "
    "  https://cdnjs.cloudflare.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none';"
)

_HSTS          = "max-age=31536000; includeSubDomains"
_REFERRER      = "no-referrer"
_X_CONTENT_OPT = "nosniff"
_PERMISSIONS   = "camera=(), microphone=(), geolocation=(), payment=()"


def init_security_headers(app: Flask) -> None:
    """Register before/after request hooks on the Flask app."""

    @app.before_request
    def _tag_request():
        g.corr_id   = request.headers.get("X-Correlation-ID") or secrets.token_hex(8)
        g.req_start = time.monotonic()

        # Propagate into logging context
        from c2.observability.logging import correlation_id, current_operator
        correlation_id.set(g.corr_id)

    @app.after_request
    def _add_headers(response):
        response.headers["X-Correlation-ID"]          = getattr(g, "corr_id", "")
        response.headers["Content-Security-Policy"]   = _CSP
        response.headers["X-Content-Type-Options"]    = _X_CONTENT_OPT
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["Referrer-Policy"]           = _REFERRER
        response.headers["Permissions-Policy"]        = _PERMISSIONS
        response.headers["X-Powered-By"]              = "AEGIS"  # overwrite Flask default

        # HSTS — only for production (HTTPS)
        if not app.debug:
            response.headers["Strict-Transport-Security"] = _HSTS

        # Instrument latency
        if hasattr(g, "req_start"):
            elapsed_ms = (time.monotonic() - g.req_start) * 1000
            from c2.observability.metrics import (
                http_requests_total, http_request_duration_ms
            )
            path   = _bucket_path(request.path)
            method = request.method
            status = str(response.status_code)
            http_requests_total.inc({"method": method, "path": path, "status": status})
            http_request_duration_ms.observe(elapsed_ms, {"method": method, "path": path})

        return response


def _bucket_path(path: str) -> str:
    """Collapse dynamic segments to prevent high-cardinality labels."""
    parts = path.split("/")
    result = []
    for p in parts:
        if p.isdigit():
            result.append("{id}")
        elif len(p) > 20 and not p.startswith("api"):
            result.append("{token}")
        else:
            result.append(p)
    return "/".join(result)


__all__ = ["init_security_headers"]
