#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# AEGIS-SILENTIUM — WireGuard Setup Script
# Configures the encrypted relay→core communication channel.
# Run on each relay and on the intelligence core.
#
# Usage:
#   # On Core:
#   bash scripts/setup_wireguard.sh --role core --private-key PRIV --peer-pubkey RELAY1_PUB
#
#   # On Relay:
#   bash scripts/setup_wireguard.sh --role relay --id 1 --private-key PRIV \
#       --core-endpoint CORE_IP:51820 --core-pubkey CORE_PUB
#
# AUTHORIZED USE ONLY
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

ROLE=""
RELAY_ID=1
WG_IFACE="wg0"
PRIVATE_KEY=""
PEER_PUBKEY=""
CORE_ENDPOINT=""
CORE_PUBKEY=""
CORE_WG_IP="10.99.0.1"
WG_PORT=51820

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)           ROLE="$2";           shift 2 ;;
        --id)             RELAY_ID="$2";        shift 2 ;;
        --private-key)    PRIVATE_KEY="$2";     shift 2 ;;
        --peer-pubkey)    PEER_PUBKEY="$2";     shift 2 ;;
        --core-endpoint)  CORE_ENDPOINT="$2";   shift 2 ;;
        --core-pubkey)    CORE_PUBKEY="$2";     shift 2 ;;
        --iface)          WG_IFACE="$2";        shift 2 ;;
        *)                echo "Unknown: $1";   exit 1 ;;
    esac
done

[[ -z "${ROLE}" ]] && { echo "Error: --role required (core or relay)"; exit 1; }

# Require root
[[ "$(id -u)" -ne 0 ]] && { echo "Error: must run as root"; exit 1; }

# Check wg-quick available
command -v wg-quick &>/dev/null || { echo "Error: wireguard-tools not installed"; exit 1; }

WG_CONF="/etc/wireguard/${WG_IFACE}.conf"
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

echo "Setting up WireGuard interface ${WG_IFACE} as ${ROLE}..."

if [[ "${ROLE}" == "core" ]]; then
    cat > "${WG_CONF}" <<EOF
[Interface]
Address    = ${CORE_WG_IP}/24
ListenPort = ${WG_PORT}
PrivateKey = ${PRIVATE_KEY}

# Block direct internet access to Core API (only via wg0)
PostUp   = iptables -A INPUT -p tcp --dport 5000 ! -i ${WG_IFACE} -j DROP
PostUp   = iptables -A INPUT -p tcp --dport 5432 ! -i lo -j DROP
PostDown = iptables -D INPUT -p tcp --dport 5000 ! -i ${WG_IFACE} -j DROP
PostDown = iptables -D INPUT -p tcp --dport 5432 ! -i lo -j DROP

[Peer]
# Relay peer (add more [Peer] blocks for additional relays)
PublicKey  = ${PEER_PUBKEY}
AllowedIPs = 10.99.0.$((RELAY_ID + 1))/32
EOF
    echo "  Core WireGuard config written to ${WG_CONF}"

elif [[ "${ROLE}" == "relay" ]]; then
    RELAY_WG_IP="10.99.0.$((RELAY_ID + 1))"
    cat > "${WG_CONF}" <<EOF
[Interface]
Address    = ${RELAY_WG_IP}/24
PrivateKey = ${PRIVATE_KEY}

[Peer]
# Intelligence Core
PublicKey           = ${CORE_PUBKEY}
Endpoint            = ${CORE_ENDPOINT}
AllowedIPs          = ${CORE_WG_IP}/32
PersistentKeepalive = 25
EOF
    echo "  Relay ${RELAY_ID} WireGuard config written to ${WG_CONF}"
fi

chmod 600 "${WG_CONF}"

# Enable and start
systemctl enable "wg-quick@${WG_IFACE}"
wg-quick up "${WG_IFACE}" 2>/dev/null || wg-quick down "${WG_IFACE}" && wg-quick up "${WG_IFACE}"

echo "  WireGuard ${WG_IFACE} is up"
echo "  $(wg show ${WG_IFACE} | head -3)"

if [[ "${ROLE}" == "relay" ]]; then
    echo ""
    echo "  Testing connectivity to Core (${CORE_WG_IP})..."
    if ping -c 2 -W 3 "${CORE_WG_IP}" &>/dev/null; then
        echo "  ✓ Core reachable via WireGuard"
    else
        echo "  ✗ Core NOT reachable — check Core WireGuard config and firewall"
    fi
fi

echo "WireGuard setup complete."
