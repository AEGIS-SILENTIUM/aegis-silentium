#!/usr/bin/env python3
"""
scripts/check_config.py
AEGIS-SILENTIUM v12 — Pre-deployment configuration checker

Run before starting in production:
  python3 scripts/check_config.py

Exits 0 if all checks pass, 1 if any critical issues are found.
"""
import os, sys, re
from pathlib import Path

RED   = "\033[91m"
YLW   = "\033[93m"
GRN   = "\033[92m"
RST   = "\033[0m"

errors   = []
warnings = []

def error(msg):   errors.append(msg);   print(f"{RED}✗ CRITICAL: {msg}{RST}")
def warn(msg):    warnings.append(msg); print(f"{YLW}⚠ WARNING:  {msg}{RST}")
def ok(msg):      print(f"{GRN}✓ {msg}{RST}")

print("\nAEGIS-SILENTIUM v12 — Configuration Health Check\n")

# ── Operator key ────────────────────────────────────────────────────────────
op_key = os.environ.get("OPERATOR_KEY", "")
if not op_key:
    error("OPERATOR_KEY not set")
elif len(op_key) < 48:
    error(f"OPERATOR_KEY too short: {len(op_key)} chars (min 48)")
elif op_key.lower() in ("changeme","default","test","demo","secret","aegis"):
    error("OPERATOR_KEY is a placeholder value")
else:
    ok(f"OPERATOR_KEY: {len(op_key)} chars")

# ── Database ─────────────────────────────────────────────────────────────────
pg_pass = os.environ.get("POSTGRES_PASSWORD","")
if not pg_pass:
    warn("POSTGRES_PASSWORD not set")
else:
    ok(f"POSTGRES_PASSWORD: set ({len(pg_pass)} chars)")

pg_host = os.environ.get("POSTGRES_HOST","")
if not pg_host:
    warn("POSTGRES_HOST not set, defaulting to localhost")
else:
    ok(f"POSTGRES_HOST: {pg_host}")

# ── TLS ──────────────────────────────────────────────────────────────────────
tls = os.environ.get("REQUIRE_TLS","0")
if tls not in ("1","true","yes"):
    warn("REQUIRE_TLS not enabled — set REQUIRE_TLS=1 for production")
else:
    ok("TLS enforcement: enabled")
    cert = os.environ.get("TLS_CERT_FILE","")
    key  = os.environ.get("TLS_KEY_FILE","")
    if not cert or not Path(cert).exists():
        error(f"TLS_CERT_FILE not found: {cert!r}")
    else:
        ok(f"TLS_CERT_FILE: {cert}")
    if not key or not Path(key).exists():
        error(f"TLS_KEY_FILE not found: {key!r}")
    else:
        ok(f"TLS_KEY_FILE: {key}")

# ── JWT secret ───────────────────────────────────────────────────────────────
jwt = os.environ.get("C2_JWT_SECRET","")
if not jwt:
    warn("C2_JWT_SECRET not set — sessions will not survive restarts")
elif jwt.lower() in ("changeme","secret","default","test"):
    error("C2_JWT_SECRET is a placeholder value")
else:
    ok(f"C2_JWT_SECRET: set ({len(jwt)} chars)")

# ── CORS ─────────────────────────────────────────────────────────────────────
cors = os.environ.get("CORS_ALLOWED_ORIGINS","")
if not cors:
    warn("CORS_ALLOWED_ORIGINS not set — API restricted to same-origin only")
else:
    ok(f"CORS_ALLOWED_ORIGINS: {cors[:60]}")

# ── IP allowlist ─────────────────────────────────────────────────────────────
allowlist = os.environ.get("AEGIS_IP_ALLOWLIST","")
if not allowlist:
    warn("AEGIS_IP_ALLOWLIST not set — any IP can attempt authentication")
else:
    ok(f"AEGIS_IP_ALLOWLIST: {allowlist[:60]}")

# ── Summary ──────────────────────────────────────────────────────────────────
print(f"\n{'='*55}")
print(f"  Errors:   {len(errors)}")
print(f"  Warnings: {len(warnings)}")
if errors:
    print(f"\n{RED}DEPLOYMENT BLOCKED: {len(errors)} critical error(s).{RST}")
    sys.exit(1)
elif warnings:
    print(f"\n{YLW}Warnings found. Review before production deployment.{RST}")
    sys.exit(0)
else:
    print(f"\n{GRN}All checks passed. Ready for deployment.{RST}")
    sys.exit(0)
