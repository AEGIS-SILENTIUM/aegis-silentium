# AEGIS-SILENTIUM — Developer Guide

> For authorized security researchers and engineers extending the framework.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Development Environment](#development-environment)
3. [Adding a New Exfiltration Channel](#adding-a-new-exfiltration-channel)
4. [Adding a New Malleable C2 Profile](#adding-a-new-malleable-c2-profile)
5. [Adding a Scan Plugin](#adding-a-scan-plugin)
6. [Adding a New Attack Module](#adding-a-new-attack-module)
7. [Extending the Relay (Go)](#extending-the-relay-go)
8. [Database Schema](#database-schema)
9. [Testing](#testing)
10. [Security Coding Standards](#security-coding-standards)
11. [Release Checklist](#release-checklist)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PACKAGE DEPENDENCY GRAPH                                                    │
│                                                                             │
│  node/app.py                                                                │
│    ├── node/aegis_core.py         (scan engine — do not modify)             │
│    ├── node/c2_client/beacon.py   (ECDHE beacon)                            │
│    ├── node/evasion/honeypot.py   (trust scoring)                           │
│    ├── node/exfil/channels.py     (exfil channels)                          │
│    ├── node/exfil/doh.py          (DoH/A-record exfil)                      │
│    ├── node/lateral/ssh_mover.py                                            │
│    ├── node/opsec/clear_logs.py                                             │
│    ├── node/persistence/{linux,windows}.py                                  │
│    ├── node/privesc/linux_checks.py                                         │
│    ├── shared/crypto/aes.py                                                 │
│    ├── shared/crypto/ecdhe.py                                               │
│    └── shared/profiles/malleable.py                                         │
│                                                                             │
│  relay/main.go                                                              │
│    └── profiles/ (same YAML files as shared/profiles/)                     │
│                                                                             │
│  c2/app.py                                                                  │
│    ├── c2/campaign/__init__.py                                               │
│    ├── c2/listeners/__init__.py                                              │
│    └── c2/mesh/__init__.py                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Design Principles

1. **Implant uses stdlib-first**: All implant code works with stdlib only;
   `cryptography` and `paramiko` are optional enhancements. Never add hard
   dependencies to the implant.

2. **Profile parity**: The Python `shared/profiles/malleable.py` and Go
   `relay/main.go` profile engines must produce identical results for the
   same YAML profile. Add tests when modifying either.

3. **Relay is stateless**: The relay must never write anything to disk.
   All session data is in-memory and expires automatically.

4. **Feature flags, not code removal**: New dangerous features go behind
   a `enabled = false` config flag. Never enable by default.

---

## Development Environment

### Python (implant + core)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt   # pytest, black, mypy, ruff
```

### Go (relay)

```bash
cd relay
go mod download
go build -o relay_dev ./main.go
```

### Local test stack

```bash
# Generate dev certs (short expiry for testing)
bash scripts/gen_certs.sh --out ./certs --relays 2 --days 7

# Start everything
docker compose -f deployment/docker-compose.silentium.yml up --build

# Run relay smoke tests
bash scripts/test_relay.sh --relay https://localhost:443 --insecure
```

---

## Adding a New Exfiltration Channel

### Step 1: Create the channel module

Create `node/exfil/my_channel.py`:

```python
"""
AEGIS-SILENTIUM — node/exfil/my_channel.py
Description of your channel.
"""

import logging
log = logging.getLogger("aegis.exfil.my_channel")

class MyChannel:
    def __init__(self, config: dict):
        self.endpoint = config.get("my_endpoint", "")

    def send(self, data: bytes, label: str = "data") -> bool:
        """
        Send data via your channel.
        Returns True on success, False on failure.
        All exceptions must be caught internally.
        """
        try:
            # Your implementation
            log.info("MyChannel: sent %d bytes (label=%s)", len(data), label)
            return True
        except Exception as e:
            log.error("MyChannel send failed: %s", e)
            return False


def exfil_via_my_channel(data: bytes, label: str, **kwargs) -> bool:
    """Convenience function matching channels.py interface."""
    ch = MyChannel(kwargs)
    return ch.send(data, label)
```

### Step 2: Add to `channels.py` fallback chain

In `node/exfil/channels.py`, find `exfil_to_c2()` and add your channel:

```python
from .my_channel import exfil_via_my_channel

def exfil_to_c2(data, label, c2_url, node_id, config=None):
    config = config or {}
    channels = config.get("channel_priority",
        "doh,https,dns,icmp,smtp,my_channel,deadrop").split(",")

    for ch in channels:
        if ch == "my_channel":
            if exfil_via_my_channel(data, label, **config.get("my_channel", {})):
                return True
        # ... other channels ...
    return False
```

### Step 3: Export from package

Add to `node/exfil/__init__.py`:

```python
from .my_channel import MyChannel, exfil_via_my_channel
__all__ += ["MyChannel", "exfil_via_my_channel"]
```

### Step 4: Add config section

In `configs/silentium.conf`:
```ini
[exfil_my_channel]
my_endpoint = https://example.com/ingest
```

### Step 5: Write tests

```python
# tests/test_exfil_my_channel.py
from node.exfil.my_channel import MyChannel

def test_send_success(mock_endpoint):
    ch = MyChannel({"my_endpoint": mock_endpoint.url})
    assert ch.send(b"test data", "test") is True

def test_send_failure_no_endpoint():
    ch = MyChannel({})
    assert ch.send(b"test data", "test") is False
```

---

## Adding a New Malleable C2 Profile

Profiles are pure YAML — no code changes needed.

### Step 1: Create the YAML file

```yaml
# relay/profiles/my-profile.yaml
name: my-profile
version: "1.0"

default_headers:
  User-Agent: "MyApp/1.0"
  Content-Type: "application/json"
  X-Correlation-Id: "auto"   # "auto" → random UUID per request

uris:
  - /api/ingest              # beacon URI (first entry)
  - /api/auth                # handshake URI (second entry)

client:
  container: json
  key: "payload"
  transforms:
    - op: gzip
    - op: base64

server:
  container: json
  key: "result"
  transforms:
    - op: gzip
    - op: base64
```

### Step 2: Deploy to both relay and implant

```bash
# Copy to relay profiles directory
cp relay/profiles/my-profile.yaml configs/profiles/my-profile.yaml

# Set in relay config (relay1.yaml, relay2.yaml, etc.)
# profile:
#   file: /profiles/my-profile.yaml
```

### Step 3: Verify parity (critical)

Run the profile parity test to ensure Go and Python implementations agree:

```bash
# Python
python3 -c "
from shared.profiles import ProfileEngine
e = ProfileEngine()
e.load('relay/profiles/my-profile.yaml')
data = b'hello world'
encoded = e.encode_client(data)
decoded = e.decode_client(encoded)
assert decoded == data, f'Python decode failed: {decoded!r}'
print('Python: OK')
"

# Go
cd relay && go test -run TestProfileParity ./...
```

---

## Adding a Scan Plugin

Plugins extend the scan engine with custom checks. Create a plugin file
and drop it in `node/plugins/`:

```python
# node/plugins/my_plugin.py
"""
AEGIS scan plugin: My Custom Check
"""

class MyPlugin:
    name = "my_plugin"
    description = "Checks for XYZ"

    async def run(self, target: str, session, findings: list) -> list:
        """
        Run your check against `target`.
        `session`: aiohttp ClientSession for making requests.
        `findings`: list of existing findings (read-only).
        Returns list of new Finding dicts.
        """
        results = []
        try:
            async with session.get(f"{target}/xyz") as resp:
                if resp.status == 200:
                    body = await resp.text()
                    if "vulnerable_pattern" in body:
                        results.append({
                            "type": "MY_CHECK",
                            "severity": "HIGH",
                            "title": "XYZ vulnerability found",
                            "description": f"Pattern detected at {target}/xyz",
                            "url": f"{target}/xyz",
                            "evidence": body[:200],
                        })
        except Exception as e:
            pass
        return results
```

Register it in `configs/silentium.conf`:
```ini
[scan]
plugin_dir = node/plugins
```

---

## Adding a New Attack Module

Attack modules live in `node/aegis_core.py` in the `AdvancedAttackModule` class.

```python
async def _check_my_attack(self, url: str, session) -> list:
    """
    Check for My Attack.
    All attack modules must:
    - Be async
    - Return a list of vulnerability dicts
    - Catch all exceptions internally
    - Never cause service disruption
    """
    results = []
    try:
        payload = "MY_ATTACK_PAYLOAD"
        async with session.get(url, params={"q": payload}, timeout=10) as resp:
            body = await resp.text()
            if "vulnerable_indicator" in body:
                results.append(self._make_finding(
                    vuln_type="MY_ATTACK",
                    severity="HIGH",
                    url=url,
                    evidence=body[:500],
                    description="My attack description",
                    remediation="Remediation advice",
                ))
    except Exception:
        pass
    return results
```

Then register it in `AdvancedAttackModule.run_all()`:
```python
checks = [
    # ... existing checks ...
    self._check_my_attack,
]
```

---

## Extending the Relay (Go)

### Adding a new handler

```go
// In relay/main.go, add to the mux:
mux.HandleFunc("/my/endpoint", relay.handleMyEndpoint)

// Implement the handler:
func (r *Relay) handleMyEndpoint(w http.ResponseWriter, req *http.Request) {
    // Always check rate limit first
    ip, _, _ := net.SplitHostPort(req.RemoteAddr)
    if !r.checkRate(ip) {
        http.Error(w, "rate limit", http.StatusTooManyRequests)
        return
    }

    // Your logic here

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
```

### Adding a new profile container

In `relay/main.go`, extend `wrapInContainer()` and `unwrapContainer()`:

```go
case "my_container":
    // Wrap data in your container format
    return []byte(fmt.Sprintf(`{"my_key": "%s"}`, string(data))), nil
```

Mirror the logic in Python `shared/profiles/malleable.py`'s
`_wrap_container()` and `_unwrap_container()`.

### Building the relay

```bash
cd relay

# Development build
go build -o relay_dev ./main.go

# Production (hardened, stripped)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w -extldflags=-static" -trimpath \
  -o relay_linux_amd64 ./main.go

# macOS
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -trimpath \
  -o relay_darwin_arm64 ./main.go
```

---

## Database Schema

```sql
-- nodes: registered implants
CREATE TABLE nodes (
    id          TEXT PRIMARY KEY,
    hostname    TEXT,
    platform    TEXT,
    ip_address  TEXT,
    status      TEXT DEFAULT 'active',   -- active | dormant | dead
    trust_score INTEGER,
    registered_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen   TIMESTAMPTZ,
    metadata    JSONB
);

-- campaigns: engagement campaigns
CREATE TABLE campaigns (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    status      TEXT DEFAULT 'active',   -- active | paused | closed
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    closed_at   TIMESTAMPTZ,
    config      JSONB
);

-- tasks: work queued for nodes
CREATE TABLE tasks (
    id          SERIAL PRIMARY KEY,
    campaign_id INTEGER REFERENCES campaigns(id),
    node_id     TEXT,
    task_type   TEXT,
    target      TEXT,
    status      TEXT DEFAULT 'pending',  -- pending | running | done | failed
    priority    INTEGER DEFAULT 5,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    started_at  TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    result      JSONB
);

-- vulnerabilities: findings from scans
-- NOTE: 'details' column is AES-256-GCM encrypted at rest
CREATE TABLE vulnerabilities (
    id          SERIAL PRIMARY KEY,
    task_id     INTEGER REFERENCES tasks(id),
    node_id     TEXT,
    target      TEXT,
    vuln_type   TEXT,
    severity    TEXT,
    title       TEXT,
    details     BYTEA,    -- encrypted
    url         TEXT,
    cvss_score  NUMERIC(4,1),
    found_at    TIMESTAMPTZ DEFAULT NOW()
);

-- events: audit log
CREATE TABLE events (
    id          BIGSERIAL PRIMARY KEY,
    node_id     TEXT,
    event_type  TEXT,
    payload     JSONB,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- node_commands: pending commands for nodes
CREATE TABLE node_commands (
    id          SERIAL PRIMARY KEY,
    node_id     TEXT,
    command     TEXT,
    args        JSONB,
    status      TEXT DEFAULT 'pending',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    executed_at TIMESTAMPTZ
);
```

---

## Testing

### Unit tests

```bash
# Python
pytest tests/ -v --tb=short

# Go (relay)
cd relay && go test ./... -v
```

### Integration tests

```bash
# Full stack test (requires Docker)
bash scripts/test_relay.sh --relay https://localhost:443 --insecure

# Profile parity test
python3 tests/test_profile_parity.py
```

### Crypto tests

```bash
# ECDHE round-trip
python3 -c "
from shared.crypto.ecdhe import ECDHEClient
# Requires relay running at localhost:9443
# See tests/test_ecdhe_integration.py for full test
print('Run: pytest tests/test_ecdhe_integration.py')
"
```

### Coverage target

- Core crypto modules (`shared/crypto/`): ≥90% coverage
- Exfil channels: ≥80% coverage
- Relay Go code: ≥70% coverage

---

## Security Coding Standards

1. **No hardcoded secrets**: Use environment variables or config files.
   Never commit keys, passwords, or API tokens.

2. **Zero session keys after use**: Use `bytearray` for key material in Python.
   Call `secure_zero()` when done. In Go, zero byte slices with a loop.

3. **All crypto via audited libraries**: `cryptography` (Python), stdlib
   `crypto/` (Go). Never implement your own crypto primitives.

4. **Catch and log, never crash**: All implant code must catch exceptions.
   A crash creates a more visible artifact than a silent failure.

5. **Rate-limit all network operations**: Avoid triggering SIEM alerts.
   Use jitter on all timed operations.

6. **Feature flags for dangerous ops**: New dangerous capabilities go behind
   `enabled = false` in config. Document explicitly in the config file.

7. **No `eval()` on untrusted input**: C2 commands are dispatched through
   an explicit dispatch table — never via `eval()` or `exec()` on raw input.

8. **Input validation on relay**: Relay validates body size, HMAC, session
   existence, and revocation before any processing. Never trust implant input.

---

## Release Checklist

- [ ] All unit tests passing
- [ ] Integration tests passing
- [ ] Profile parity test passing (Go ↔ Python)
- [ ] No hardcoded secrets in codebase (`git grep -r "password\|secret\|key" --include="*.py" --include="*.go"`)
- [ ] `requirements.txt` updated
- [ ] `go.mod` updated
- [ ] CHANGELOG.md updated
- [ ] README.md version number updated
- [ ] Docker images rebuilt and tested
- [ ] Terraform plan reviewed (no unintended changes)
- [ ] Security review completed for any new dangerous features

---

*AEGIS-SILENTIUM Developer Guide v1.0*
