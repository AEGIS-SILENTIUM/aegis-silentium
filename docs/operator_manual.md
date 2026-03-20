# AEGIS-SILENTIUM — Operator Manual

> **AUTHORIZED USE ONLY.** Read the [Ethics & Legal section of the README](README.md#ethics--legal) before proceeding.

---

## Table of Contents

1. [Pre-Engagement Checklist](#pre-engagement-checklist)
2. [Infrastructure Setup](#infrastructure-setup)
3. [Dashboard Overview](#dashboard-overview)
4. [Setting Objectives / Injecting Tasks](#setting-objectives--injecting-tasks)
5. [Monitoring Operations](#monitoring-operations)
6. [Understanding Scan Results](#understanding-scan-results)
7. [Dormant Mode & Trust Scoring](#dormant-mode--trust-scoring)
8. [Emergency Procedures](#emergency-procedures)
9. [Engagement Closure](#engagement-closure)
10. [Troubleshooting](#troubleshooting)

---

## Pre-Engagement Checklist

Before any operation begins, confirm every item below:

- [ ] Written authorization from system owner (scope, duration, rules of engagement)
- [ ] Engagement scope documented (IP ranges, domains, excluded systems)
- [ ] Rules of engagement reviewed (prohibited actions, escalation path)
- [ ] Legal counsel sign-off (if required by your organization)
- [ ] Operator ECDSA key pair generated and secured (`certs/operator/operator_key.pem`)
- [ ] Intelligence Core deployed on operator-controlled infrastructure
- [ ] Relays provisioned with short-lived credentials (Terraform)
- [ ] WireGuard tunnel active and tested
- [ ] All certificates generated and distributed
- [ ] Dashboard accessible at `https://localhost:7331`
- [ ] Emergency stop procedure documented and accessible offline
- [ ] Data handling plan: where results are stored, who has access, destruction timeline

---

## Infrastructure Setup

### Step 1: Generate Certificates

```bash
bash scripts/gen_certs.sh --out ./certs --relays 3 --days 90
```

Securely store `certs/operator/operator_key.pem` — this is the key used to
sign all operator commands including the kill switch. If lost, you cannot
send authenticated commands.

### Step 2: Deploy Intelligence Core

```bash
# Edit configuration
cp configs/silentium.conf configs/silentium.local.conf
# Set: operator_key, database passwords, column_enc_key

# Deploy
docker compose -f deployment/docker-compose.silentium.yml up -d core postgres scheduler
```

### Step 3: Provision Relays

```bash
cd deployment/terraform
terraform init && terraform apply
# Note relay IPs from output
terraform output relay_https_urls
```

Update `configs/silentium.local.conf`:
```ini
[c2]
relay_urls = https://RELAY1_IP:443,https://RELAY2_IP:8443
```

### Step 4: Verify Relay Connectivity

```bash
bash scripts/test_relay.sh --relay https://RELAY1_IP:443
bash scripts/test_relay.sh --relay https://RELAY2_IP:8443
```

All tests should pass before deploying any implants.

---

## Dashboard Overview

Access the dashboard at `https://localhost:7331` with your client certificate
and operator key.

### Navigation

| Section | Description |
|---|---|
| **Overview** | Live stats: active nodes, open tasks, critical vulns, campaigns |
| **Nodes** | Fleet table: status, last-seen, platform, scan count, commands |
| **Vulnerabilities** | Filtered by severity; CSV export; click for full details |
| **Tasks** | Task queue with status filter (pending/running/done/failed) |
| **Campaigns** | Campaign management: create, view, close |
| **Event Feed** | Live SSE event stream from all nodes |

### Dashboard Indicators

| Color | Meaning |
|---|---|
| 🟢 Green | Node active, healthy |
| 🟡 Yellow | Node dormant (trust score below threshold) |
| 🟠 Orange | Node last-seen >5 min ago |
| 🔴 Red | Node dead (>10 min) or critical vulnerability found |

---

## Setting Objectives / Injecting Tasks

### Via Dashboard

The dashboard can queue tasks for active nodes. Click a node row → **Issue Command**:

- `scan <url>` — Run full 11-phase scan
- `persist` — Attempt persistence (requires `persistence.enabled=true` in implant config)
- `privesc` — Run privilege escalation checks
- `exfil <path>` — Exfiltrate a file
- `sleep <secs>` — Put node to sleep
- `info` — Collect system information
- `die` — Kill the implant (unsigned, immediate)

### Via Signed Objective (Command Node)

For high-security operations where the Command Node is offline most of the time:

```bash
# Queue a scan
bash scripts/inject_objective.sh \
  --key certs/operator/operator_key.pem \
  --relay https://RELAY1_IP:443 \
  --cmd scan \
  --target https://scope.example.com

# Put specific node to sleep
bash scripts/inject_objective.sh \
  --key certs/operator/operator_key.pem \
  --relay https://RELAY1_IP:443 \
  --cmd sleep \
  --node node-001 \
  --sleep-secs 3600

# Kill a specific node
bash scripts/inject_objective.sh \
  --key certs/operator/operator_key.pem \
  --relay https://RELAY1_IP:443 \
  --cmd kill \
  --node node-001
```

After injecting, disconnect the Command Node from the relay network immediately.
The objective propagates through the relay mesh to the core, then to the node
on its next beacon.

---

## Monitoring Operations

### Live Event Feed

The dashboard event feed shows real-time events from all nodes. Key event types:

| Event | Meaning |
|---|---|
| `node.registered` | New implant checked in |
| `scan.started` | Scan phase begun |
| `scan.completed` | Scan phase finished |
| `vuln.found` | Vulnerability discovered (check severity) |
| `node.dormant` | Node entered dormant mode (low trust score) |
| `node.trusted` | Node exited dormant mode |
| `node.dead` | No beacon for >10 min |
| `persist.success` | Persistence established (if enabled) |
| `exfil.sent` | Data exfiltrated |

### Vulnerability Severity Levels

| Severity | CVSS Range | Recommended Action |
|---|---|---|
| CRITICAL | 9.0–10.0 | Immediate escalation to system owner |
| HIGH | 7.0–8.9 | Report within 24 hours |
| MEDIUM | 4.0–6.9 | Include in daily report |
| LOW | 0.1–3.9 | Include in final report |
| INFO | N/A | Informational, include in appendix |

### Core API

Direct API access (from within WireGuard network only):

```bash
# Node status
curl -s -H "X-Aegis-Key: $OPERATOR_KEY" http://10.99.0.1:5000/api/nodes | jq

# Recent vulnerabilities
curl -s -H "X-Aegis-Key: $OPERATOR_KEY" \
  "http://10.99.0.1:5000/api/vulnerabilities?severity=CRITICAL" | jq

# Task queue
curl -s -H "X-Aegis-Key: $OPERATOR_KEY" http://10.99.0.1:5000/api/tasks | jq
```

---

## Dormant Mode & Trust Scoring

When a node enters dormant mode, it does **not** stop beaconing (that would
alert defenders to a lost beacon). Instead it sends minimal benign telemetry.

To see a node's current trust score via the API:

```bash
curl -s -H "X-Aegis-Key: $OPERATOR_KEY" \
  "http://10.99.0.1:5000/api/nodes/NODE_ID/trust" | jq
```

### Adjusting the Threshold

If nodes are stuck dormant in your lab environment (e.g., VM-based testing),
lower the trust threshold in `silentium.conf`:

```ini
[evasion]
trust_threshold = 10    # Very permissive for lab/VM environments
```

For production engagements, keep the default (40) or higher.

---

## Emergency Procedures

### Procedure 1: Kill a Single Node

```bash
bash scripts/inject_objective.sh \
  --key certs/operator/operator_key.pem \
  --relay https://RELAY1_IP:443 \
  --cmd kill --node NODE_ID
```

The node receives the kill command on its next beacon, executes `self_destruct()`
(wipes traces, removes persistence, deletes itself), and exits.

### Procedure 2: Kill All Nodes (Emergency Stop)

```bash
bash scripts/inject_objective.sh \
  --key certs/operator/operator_key.pem \
  --relay https://RELAY1_IP:443 \
  --cmd kill_all
```

The kill_all command propagates through the relay mesh to all registered nodes.
Each node self-destructs on its next beacon (within one `beacon.interval`).

### Procedure 3: Stop All Relays

```bash
# Touch kill switch on relay host
ssh relay1 "touch /tmp/aegis_kill"

# OR via signed objective
bash scripts/inject_objective.sh \
  --key certs/operator/operator_key.pem \
  --relay https://RELAY1_IP:443 \
  --cmd stop
```

Relays poll the kill-switch file every 5 seconds and shut down cleanly
(graceful HTTP server shutdown, all session keys zeroed).

### Procedure 4: Infrastructure Takedown (End of Engagement)

```bash
# Step 1: Kill all nodes
bash scripts/inject_objective.sh --key certs/operator/operator_key.pem \
  --relay https://RELAY1_IP:443 --cmd kill_all

# Step 2: Wait one full beacon interval for nodes to self-destruct
sleep 120

# Step 3: Destroy relay infrastructure
cd deployment/terraform && terraform destroy -auto-approve

# Step 4: Stop core and DB
docker compose -f deployment/docker-compose.silentium.yml down -v

# Step 5: Securely wipe all local data
# (operator keys, certs, result exports)
find ./certs -type f -exec shred -u {} \;
```

### Procedure 5: Relay Compromise

If a relay host is suspected compromised:

1. Immediately destroy the relay: `terraform taint aws_instance.relay[N] && terraform apply`
2. Rotate that relay's WireGuard key on the core
3. Generate new TLS cert for replacement relay
4. Update implant config with new relay URL
5. Review relay logs for any anomalous traffic before compromise

**What an attacker gains from a relay:** Nothing useful.
- Past traffic: undecipherable (PFS — no session keys stored)
- Core location: the WireGuard tunnel's remote endpoint — rotate immediately
- Current in-memory ECDHE sessions: ephemeral, expire within seconds/minutes

---

## Engagement Closure

Complete these steps at the end of every engagement:

1. **Kill all nodes**: `inject_objective.sh --cmd kill_all`
2. **Verify nodes are gone**: check dashboard for dead nodes, wait 1 full interval
3. **Verify persistence removed**: manually confirm on target systems per scope
4. **Export findings**: dashboard CSV export or API call
5. **Destroy relay infrastructure**: `terraform destroy`
6. **Stop core**: `docker compose down -v`
7. **Archive or destroy results**: per engagement data handling plan
8. **Shred operator keys**: `shred -u certs/operator/operator_key.pem`
9. **Write debrief report**: findings, TTPs simulated, recommendations

---

## Troubleshooting

### Node not appearing in dashboard

1. Check relay logs: `docker logs aegis-relay1 | tail -50`
2. Verify implant config: correct relay URL, operator key
3. Check trust score — node may be in dormant mode
4. Verify TLS cert is trusted (add `-k` to disable verify in dev)

### "rehandshake" response from relay

The ECDHE session expired (default TTL: 300s). The implant will automatically
re-handshake on the next beacon. If this happens frequently, increase
`ecdhe_session_ttl` in relay config.

### DoH exfil not working

1. Check `doh_domain` in `silentium.conf` — must be an operator-controlled domain
2. Verify authoritative DNS is configured to log subdomain queries
3. Try `--provider google` if Cloudflare is blocked in target environment
4. Reduce `doh_rate_limit` if DNS queries are being dropped

### Relay rate limit too aggressive

Edit relay config `relay1.yaml`:
```yaml
security:
  rate_limit: 500   # requests/sec per IP (increase for bulk testing)
```

### WireGuard tunnel down

```bash
# On relay
wg show wg0
wg-quick down wg0 && wg-quick up wg0

# Verify core reachable
ping 10.99.0.1
```

### PostgreSQL connection error

```bash
docker exec -it aegis-postgres pg_isready -U aegis
docker logs aegis-postgres | tail -20
```

---

*AEGIS-SILENTIUM Operator Manual v1.0 — For authorized security professionals only.*
