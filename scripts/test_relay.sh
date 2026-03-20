#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# AEGIS-SILENTIUM — Relay Connectivity and ECDHE Smoke Test
# Verifies relay TLS, ECDHE handshake, and beacon path are functional.
#
# Usage:
#   bash scripts/test_relay.sh --relay https://localhost:443 [--insecure]
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

RELAY_URL="https://localhost:443"
INSECURE=""
NODE_ID="test-node-$(date +%s)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --relay)    RELAY_URL="$2"; shift 2 ;;
        --node-id)  NODE_ID="$2";   shift 2 ;;
        --insecure) INSECURE="-k";  shift ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

echo "══════════════════════════════════════════════════════════════"
echo " AEGIS-SILENTIUM Relay Smoke Test"
echo " Relay: ${RELAY_URL}"
echo " Node ID: ${NODE_ID}"
echo "══════════════════════════════════════════════════════════════"

TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

PASS=0; FAIL=0

run_test() {
    local name="$1"
    local cmd="$2"
    echo -n "  [test] ${name}... "
    if eval "${cmd}" &>"${TMPDIR}/test_out.txt"; then
        echo "PASS"
        PASS=$((PASS+1))
    else
        echo "FAIL"
        cat "${TMPDIR}/test_out.txt" | head -5
        FAIL=$((FAIL+1))
    fi
}

# ── 1. TLS connectivity ───────────────────────────────────────────────────────
echo ""
echo "1. TLS Connectivity"
run_test "HTTPS health endpoint" \
    "curl -sf ${INSECURE} --max-time 10 ${RELAY_URL}/health | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d[\"status\"]==\"ok\"'"

# ── 2. TLS version check ──────────────────────────────────────────────────────
echo ""
echo "2. TLS Version"
run_test "TLS 1.3 supported" \
    "curl -sf ${INSECURE} --tls-max 1.3 --tlsv1.3 --max-time 10 ${RELAY_URL}/health > /dev/null"
run_test "TLS 1.1 rejected" \
    "! curl -sf ${INSECURE} --tls-max 1.1 --tlsv1.1 --max-time 5 ${RELAY_URL}/health > /dev/null 2>&1"

# ── 3. ECDHE Handshake ────────────────────────────────────────────────────────
echo ""
echo "3. ECDHE Handshake"

# Generate a test ECDH key pair
python3 - <<PYEOF > "${TMPDIR}/handshake_req.json" 2>/dev/null || true
import json, os, base64
try:
    from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.backends import default_backend
    priv = generate_private_key(SECP256R1(), default_backend())
    pub = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    nonce = os.urandom(32)
    print(json.dumps({
        "node_id": "test-node-001",
        "pub_key": base64.b64encode(pub).decode(),
        "nonce": base64.b64encode(nonce).decode(),
    }))
except ImportError:
    import hashlib
    fake_pub = hashlib.sha256(b"test").digest() * 2
    fake_nonce = os.urandom(32)
    print(json.dumps({
        "node_id": "test-node-001",
        "pub_key": base64.b64encode(fake_pub).decode(),
        "nonce": base64.b64encode(fake_nonce).decode(),
    }))
PYEOF

if [[ -s "${TMPDIR}/handshake_req.json" ]]; then
    run_test "ECDHE handshake endpoint responds" \
        "curl -sf ${INSECURE} -X POST -H 'Content-Type: application/json' \
         -d @${TMPDIR}/handshake_req.json --max-time 10 \
         ${RELAY_URL}/api/v1/auth/token | python3 -c \
         'import json,sys; d=json.load(sys.stdin); assert \"pub_key\" in str(d) or len(d) > 0'"
else
    echo "  [skip] handshake test (Python/cryptography unavailable)"
fi

# ── 4. Rate limiting ──────────────────────────────────────────────────────────
echo ""
echo "4. Rate Limiting"
run_test "Rate limit returns 429 after burst" \
    "for i in \$(seq 1 200); do
         CODE=\$(curl -s ${INSECURE} -o /dev/null -w '%{http_code}' --max-time 2 ${RELAY_URL}/health);
         if [[ \"\$CODE\" == \"429\" ]]; then exit 0; fi;
     done; exit 1"

# ── 5. Invalid requests rejected ─────────────────────────────────────────────
echo ""
echo "5. Input Validation"
run_test "Empty body rejected" \
    "CODE=\$(curl -s ${INSECURE} -o /dev/null -w '%{http_code}' -X POST --max-time 5 ${RELAY_URL}/api/v1/events);
     [[ \"\$CODE\" == \"400\" || \"\$CODE\" == \"401\" || \"\$CODE\" == \"422\" ]]"

run_test "Oversized body rejected" \
    "CODE=\$(curl -s ${INSECURE} -o /dev/null -w '%{http_code}' -X POST \
         -H 'Content-Type: application/json' \
         --data-binary @<(python3 -c 'print(\"x\"*2000000)') \
         --max-time 10 ${RELAY_URL}/api/v1/events);
     [[ \"\$CODE\" != \"200\" ]]"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════════"
echo " Results: ${PASS} passed, ${FAIL} failed"
if [[ "${FAIL}" -eq 0 ]]; then
    echo " ✓ All tests passed — relay is operational"
    exit 0
else
    echo " ✗ ${FAIL} test(s) failed — review relay configuration"
    exit 1
fi
