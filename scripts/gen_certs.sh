#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# AEGIS-SILENTIUM — TLS Certificate and Key Generation Script
# Generates all certificates required for the framework:
#   - Root CA
#   - Intelligence Core server cert
#   - Relay server certs (one per relay)
#   - Client certs for relay→core mTLS
#   - Dashboard client cert
#   - Relay ECDSA signing key (for ECDHE signature verification)
#   - Operator ECDSA key pair (for signed objectives / kill switch)
#
# Usage:
#   bash scripts/gen_certs.sh [--out /path/to/certs] [--relays 3] [--days 90]
#
# AUTHORIZED USE ONLY
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
OUT_DIR="./certs"
RELAY_COUNT=3
CERT_DAYS=90
COUNTRY="US"
ORG="AEGIS-SILENTIUM"
CORE_CN="core.internal"
RELAY_CN_PREFIX="relay"
DASHBOARD_CN="dashboard.internal"

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)     OUT_DIR="$2";     shift 2 ;;
        --relays)  RELAY_COUNT="$2"; shift 2 ;;
        --days)    CERT_DAYS="$2";   shift 2 ;;
        --help)
            echo "Usage: $0 [--out DIR] [--relays N] [--days N]"
            exit 0
            ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

mkdir -p "${OUT_DIR}"/{ca,core,relays,clients,operator,wireguard}
chmod 700 "${OUT_DIR}"

echo "══════════════════════════════════════════════════════════════"
echo " AEGIS-SILENTIUM Certificate Generation"
echo " Output: ${OUT_DIR}  |  Validity: ${CERT_DAYS} days"
echo " Relays: ${RELAY_COUNT}"
echo "══════════════════════════════════════════════════════════════"

# ── Helper function ───────────────────────────────────────────────────────────
gen_cert() {
    local name="$1"
    local cn="$2"
    local dir="$3"
    local ca_cert="$4"
    local ca_key="$5"
    local ext="${6:-}"

    # Generate private key (ECDSA P-256)
    openssl ecparam -name prime256v1 -genkey -noout -out "${dir}/${name}_key.pem"
    chmod 600 "${dir}/${name}_key.pem"

    # Generate CSR
    openssl req -new \
        -key "${dir}/${name}_key.pem" \
        -subj "/C=${COUNTRY}/O=${ORG}/CN=${cn}" \
        -out "${dir}/${name}.csr"

    # Sign with CA
    if [[ -n "${ext}" ]]; then
        openssl x509 -req -days "${CERT_DAYS}" \
            -in "${dir}/${name}.csr" \
            -CA "${ca_cert}" -CAkey "${ca_key}" -CAcreateserial \
            -extfile <(echo "${ext}") \
            -out "${dir}/${name}_cert.pem"
    else
        openssl x509 -req -days "${CERT_DAYS}" \
            -in "${dir}/${name}.csr" \
            -CA "${ca_cert}" -CAkey "${ca_key}" -CAcreateserial \
            -out "${dir}/${name}_cert.pem"
    fi
    rm -f "${dir}/${name}.csr"
    echo "  ✓ ${cn} (${name})"
}

# ── 1. Root CA ────────────────────────────────────────────────────────────────
echo ""
echo "1. Generating Root CA..."
CA_KEY="${OUT_DIR}/ca/ca_key.pem"
CA_CERT="${OUT_DIR}/ca/ca_cert.pem"

openssl ecparam -name prime256v1 -genkey -noout -out "${CA_KEY}"
chmod 600 "${CA_KEY}"
openssl req -new -x509 -days $(( CERT_DAYS * 2 )) \
    -key "${CA_KEY}" \
    -subj "/C=${COUNTRY}/O=${ORG}/CN=AEGIS-SILENTIUM Root CA" \
    -extensions v3_ca \
    -out "${CA_CERT}"
echo "  ✓ Root CA: ${CA_CERT}"

# ── 2. Intelligence Core server cert ─────────────────────────────────────────
echo ""
echo "2. Generating Core server certificate..."
gen_cert "core" "${CORE_CN}" "${OUT_DIR}/core" "${CA_CERT}" "${CA_KEY}" \
    "subjectAltName=DNS:${CORE_CN},DNS:localhost,IP:127.0.0.1,IP:10.99.0.1
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth"

# ── 3. Relay server certs ─────────────────────────────────────────────────────
echo ""
echo "3. Generating ${RELAY_COUNT} relay server certificates..."
mkdir -p "${OUT_DIR}/relays"
for i in $(seq 1 "${RELAY_COUNT}"); do
    gen_cert "relay${i}" "${RELAY_CN_PREFIX}${i}.internal" \
        "${OUT_DIR}/relays" "${CA_CERT}" "${CA_KEY}" \
        "subjectAltName=DNS:${RELAY_CN_PREFIX}${i}.internal,DNS:aegis-relay${i}
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth"
done

# ── 4. mTLS client certs (relay → core authentication) ────────────────────────
echo ""
echo "4. Generating mTLS client certificates for relays..."
mkdir -p "${OUT_DIR}/clients"
for i in $(seq 1 "${RELAY_COUNT}"); do
    gen_cert "relay${i}_client" "relay${i}-client" \
        "${OUT_DIR}/clients" "${CA_CERT}" "${CA_KEY}" \
        "keyUsage=digitalSignature
extendedKeyUsage=clientAuth"
done

# ── 5. Dashboard client cert ──────────────────────────────────────────────────
echo ""
echo "5. Generating Dashboard server + client certificates..."
gen_cert "dashboard" "${DASHBOARD_CN}" "${OUT_DIR}/core" "${CA_CERT}" "${CA_KEY}" \
    "subjectAltName=DNS:${DASHBOARD_CN},DNS:localhost,IP:127.0.0.1
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth"

gen_cert "dashboard_client" "operator-dashboard" \
    "${OUT_DIR}/clients" "${CA_CERT}" "${CA_KEY}" \
    "keyUsage=digitalSignature
extendedKeyUsage=clientAuth"

# ── 6. Relay ECDSA signing key (for ECDHE handshake signatures) ───────────────
echo ""
echo "6. Generating relay ECDSA signing key..."
openssl ecparam -name prime256v1 -genkey -noout \
    -out "${OUT_DIR}/relays/relay_signing_key.pem"
chmod 600 "${OUT_DIR}/relays/relay_signing_key.pem"
openssl ec -in "${OUT_DIR}/relays/relay_signing_key.pem" \
    -pubout -out "${OUT_DIR}/relays/relay_signing_pub.pem"
# Also export DER for Python (cryptography.hazmat.primitives.serialization.load_der_public_key)
openssl ec -in "${OUT_DIR}/relays/relay_signing_key.pem" \
    -pubout -outform DER -out "${OUT_DIR}/relays/relay_signing_pub.der"
echo "  ✓ relay_signing_key.pem + relay_signing_pub.pem + relay_signing_pub.der"

# ── 7. Operator ECDSA key pair (for signed objectives / kill switch) ──────────
echo ""
echo "7. Generating operator ECDSA key pair (for signed commands)..."
openssl ecparam -name prime256v1 -genkey -noout \
    -out "${OUT_DIR}/operator/operator_key.pem"
chmod 600 "${OUT_DIR}/operator/operator_key.pem"
openssl ec -in "${OUT_DIR}/operator/operator_key.pem" \
    -pubout -out "${OUT_DIR}/operator/operator_pub.pem"
openssl ec -in "${OUT_DIR}/operator/operator_key.pem" \
    -pubout -outform DER -out "${OUT_DIR}/operator/operator_pub.der"
# Base64-encode DER for config file embedding
OPERATOR_PUBKEY_B64=$(base64 -w 0 "${OUT_DIR}/operator/operator_pub.der")
echo "  ✓ operator_key.pem (KEEP SECRET!) + operator_pub.pem"
echo ""
echo "  >> Add to silentium.conf [emergency] operator_pubkey = ${OPERATOR_PUBKEY_B64}"

# ── 8. WireGuard key pairs ────────────────────────────────────────────────────
echo ""
echo "8. Generating WireGuard key pairs..."
if command -v wg &>/dev/null; then
    # Core
    wg genkey | tee "${OUT_DIR}/wireguard/core_wg_private.key" \
        | wg pubkey > "${OUT_DIR}/wireguard/core_wg_public.key"
    chmod 600 "${OUT_DIR}/wireguard/core_wg_private.key"
    # Relays
    for i in $(seq 1 "${RELAY_COUNT}"); do
        wg genkey | tee "${OUT_DIR}/wireguard/relay${i}_wg_private.key" \
            | wg pubkey > "${OUT_DIR}/wireguard/relay${i}_wg_public.key"
        chmod 600 "${OUT_DIR}/wireguard/relay${i}_wg_private.key"
    done
    echo "  ✓ WireGuard key pairs generated"
    echo "  Core public key: $(cat ${OUT_DIR}/wireguard/core_wg_public.key)"
else
    echo "  ⚠ wireguard-tools not found — skipping WireGuard key generation"
    echo "    Install with: apt install wireguard-tools"
    echo "    Then run: wg genkey | tee private.key | wg pubkey > public.key"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════════"
echo " Certificate generation complete!"
echo ""
echo " Files written to: ${OUT_DIR}/"
echo "   ca/           — Root CA (trust anchor)"
echo "   core/         — Core server cert + dashboard cert"
echo "   relays/       — Relay server certs + ECDSA signing key"
echo "   clients/      — mTLS client certs for relay→core auth"
echo "   operator/     — Operator signing key (KEEP SECRET!)"
echo "   wireguard/    — WireGuard key pairs"
echo ""
echo " Next steps:"
echo "   1. Copy certs/ to /etc/aegis/ on each host"
echo "   2. Update silentium.conf with cert paths"
echo "   3. Embed relay_signing_pub.der in implant config"
echo "   4. Run scripts/setup_wireguard.sh to configure WireGuard"
echo "══════════════════════════════════════════════════════════════"
