# AEGIS-SILENTIUM v12 — Troubleshooting Guide

> This guide covers every error that can occur during build, deployment, and
> runtime — including all errors observed in the v1.0 initial build log.

---

## Table of Contents

1. [Build Errors](#build-errors)
2. [Go Relay Errors](#go-relay-errors)
3. [Python Runtime Errors](#python-runtime-errors)
4. [Docker / Compose Errors](#docker--compose-errors)
5. [Configuration Errors](#configuration-errors)
6. [WireGuard Errors](#wireguard-errors)
7. [Database Errors](#database-errors)
8. [Terraform Errors](#terraform-errors)
9. [Script Errors](#script-errors)
10. [Cryptography Errors](#cryptography-errors)
11. [Network / Connectivity Errors](#network--connectivity-errors)

---

## Build Errors

### `go: go.mod file not found in current directory`

**Cause:** Running `go build` from the project root instead of the `relay/`
subdirectory.

**Fix:**
```bash
cd relay/
go mod download
go build -ldflags="-s -w" -trimpath -o ../dist/relay/relay ./main.go
```
Or use the build script which handles this automatically:
```bash
bash scripts/build.sh --relay-only
```

### `fatal: destination path already exists and is not an empty directory`

**Cause:** Git clone target already exists.

**Fix:**
```bash
rm -rf /home/user/aegis-silentium
git clone <repo> /home/user/aegis-silentium
```
Or use the existing directory:
```bash
cd /home/user/aegis-silentium && git pull
```

### `node/aegis_core.py: unexpected EOF while parsing (file appears truncated)`

**Cause:** Incomplete file download or interrupted write.

**Fix:**
```bash
# Verify file integrity
wc -l node/aegis_core.py        # should be ~5800 lines
python3 -m py_compile node/aegis_core.py
```
Re-download or restore from the ZIP in `dist/implant/`.

### `go: signal: killed (memory exhausted during build)`

**Cause:** CGO-enabled build uses too much RAM on small VMs.

**Fix:**
```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o relay ./main.go
```
Or add swap:
```bash
sudo fallocate -l 2G /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
```

### `fatal: could not read Username for 'https://github.com': terminal prompts disabled`

**Cause:** `go mod download` tried to fetch a private dependency interactively.

**Fix:** The relay only uses `gopkg.in/yaml.v3` which is public. Ensure the
Go proxy is reachable:
```bash
GOPROXY=https://proxy.golang.org go mod download
```

---

## Go Relay Errors

### `relay/main.go:13:2: cannot find package "github.com/mdlayher/netlink"`

**Cause:** Stale `go.sum` referencing a package that was removed from the
relay in v1.0.  The relay now uses only stdlib + `gopkg.in/yaml.v3`.

**Fix:**
```bash
cd relay/
go mod tidy   # removes unused dependencies
go mod verify
```

### `relay/handler/tls.go: import cycle not allowed`

**Cause:** The `handler` subpackage previously imported `relay/crypto` which
then imported `relay/handler`, creating a cycle.

**Fix:** As of v1.0 the `handler` package is fully self-contained (stdlib
only).  It does NOT import any other relay subpackage.  If you add imports,
ensure the dependency graph remains:

```
main → handler (stdlib only)
main → external: gopkg.in/yaml.v3
```

Do **not** import `handler` from within the same package or from another
relay subpackage.

### `relay/profiles/google-analytics.yaml: mapping key "headers" already defined`

**Cause:** A previous version of the profile file had both `headers:` and
`default_headers:` keys.

**Fix:** The profile schema uses `default_headers:` (with the `default_`
prefix).  Remove any bare `headers:` key:
```yaml
# WRONG — duplicate key
headers: { ... }
default_headers: { ... }

# CORRECT
default_headers:
  User-Agent: "..."
```

---

## Python Runtime Errors

### `ImportError: No module named 'cryptography'`

**Cause:** The `cryptography` library is not installed.

**Fix:**
```bash
pip install cryptography --break-system-packages   # Linux system Python
# or inside virtualenv:
pip install cryptography
```

The framework runs without `cryptography` using a stdlib fallback (XOR+HMAC),
but AES-256-GCM and RSA-4096 are unavailable in fallback mode.  **Always
install `cryptography` in production.**

### `ImportError: cannot import name 'ecdh' from 'cryptography.hazmat.primitives.asymmetric'`

**Cause:** `cryptography` version < 3.0.  The correct import path for ECDH
changed between versions.

**Fix:**
```bash
pip install --upgrade "cryptography>=3.4" --break-system-packages
```

The `shared/crypto/ecdhe.py` module now imports from the correct v3.4+ path:
```python
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
```

### `AttributeError: 'NoneType' object has no attribute 'get'` (malleable.py)

**Cause:** An empty or whitespace-only YAML profile file was loaded.
`yaml.safe_load()` returns `None` for empty files.

**Fix:** As of v1.0 `shared/profiles/malleable.py` handles this gracefully —
it falls back to the built-in default profile and logs a warning.  No action
needed.  To prevent this, ensure your profile file is valid YAML:
```bash
python3 -c "import yaml; yaml.safe_load(open('configs/profiles/my-profile.yaml'))"
```

### `ModuleNotFoundError: No module named 'winreg'`

**Cause:** `node/persistence/windows.py` uses Windows registry operations.
`winreg` is a Windows-only stdlib module; importing it on Linux raises
`ModuleNotFoundError`.

**Fix:** As of v1.0 the import is guarded:
```python
try:
    import winreg as _winreg
    _HAS_WINREG = True
except ImportError:
    _winreg = None
    _HAS_WINREG = False
```
All registry operations check `_HAS_WINREG` before executing.  The module is
safely importable on Linux for cross-compile testing.

### `TypeError: a bytes-like object is required, not 'str'` (doh.py line 212)

**Cause:** A string was passed to `DoHTunnel.send()` instead of bytes.

**Fix:** As of v1.0 `send()` auto-coerces strings:
```python
if isinstance(data, str):
    data = data.encode("utf-8")
```
Callers should still pass `bytes` for correctness.

### `TypeError: Object type <class 'str'> cannot be passed to C code` (aes.py)

**Cause:** The AES key was passed as a string instead of bytes.

**Fix:**
```python
# Wrong
aes_gcm_encrypt("my-key", plaintext)

# Correct
aes_gcm_encrypt(b"my-key-padded-to-32-bytes.......", plaintext)
# or
aes_gcm_encrypt(key_string.encode("utf-8"), plaintext)
```

`aes.py` normalises keys that are not 16/24/32 bytes via SHA-256, but the
key itself must be `bytes`, not `str`.

### `NameError: name 'trustScore' is not defined` (honeypot.py)

**Cause:** Stale error from a pre-v1.0 version.  The current code uses the
`score` local variable inside each check function; the global aggregation uses
`total`.

**Fix:** Update to v1.0.  Verify the current file:
```bash
python3 -m py_compile node/evasion/honeypot.py && echo OK
```

### `PermissionError: [Errno 13] Permission denied: '/var/log/syslog'` (clear_logs.py)

**Cause:** Log clearing requires root on Linux.  Running as an unprivileged
user cannot write to system log files.

**Expected behaviour:** The `clear_system_logs()` function skips files it
cannot write and records `"failed: <reason>"` in the results dict.  It does
**not** raise an exception.

**Fix:** Either run as root or accept that system log clearing will partially
succeed (user-writable files will be cleared; system files will be skipped).

### `FileNotFoundError: '/etc/shadow'` (linux_checks.py)

**Cause:** Shadow password file readable only by root.

**Expected behaviour:** `check_shadow_readable()` returns `False` (not
readable) — this is the correct result for non-root.  The check itself catches
the error and logs a warning.

### `paramiko.ssh_exception.AuthenticationException: Authentication failed`

**Cause:** The SSH credentials in your test configuration are invalid.

**Fix:**
```python
sess = SSHSession(host="192.168.1.100", username="admin",
                   key_path="/path/to/valid/key.pem")
sess.connect()
```
Ensure the private key is unencrypted or provide the passphrase via `password`.

### `ConnectionRefusedError: [Errno 111] Connection refused` (channels.py)

**Cause:** The DoH or HTTPS exfil endpoint is unreachable from the implant.

**Fix:**
1. Verify the relay is running: `curl -sk https://relay.example.com/health`
2. Check firewall rules (port 443 must be open outbound)
3. Confirm the DoH provider is reachable: `curl -s https://1.1.1.1/dns-query?name=example.com&type=A`
4. The exfil manager falls back through channels in priority order — if HTTPS
   fails, it will try DNS, then ICMP, etc.

---

## Docker / Compose Errors

### `docker: invalid reference format: repository name must be lowercase`

**Cause:** A Docker image name contained uppercase letters.

**Fix:** All `aegis-silentium/*` image names are already lowercase in
`deployment/docker-compose.silentium.yml`.  If you renamed services, ensure image
names use only `[a-z0-9-_./:]`.

### `service "core" depends on "postgres" which is undefined`

**Cause:** Running the compose file without its companion services, or using
a split compose file that doesn't define the `postgres` service.

**Fix:** Always use the full compose file which defines all services:
```bash
docker compose -f deployment/docker-compose.silentium.yml up -d
```

### `ERROR: Cannot start service relay: port 443 already in use`

**Cause:** Another process (nginx, Apache, another relay) is listening on
port 443.

**Fix options:**
1. Stop the conflicting service: `systemctl stop nginx`
2. Change the relay's host port:
   ```yaml
   ports:
     - "8443:443"   # relay listens on 8443 externally
   ```
3. Use a dedicated IP binding:
   ```yaml
   ports:
     - "203.0.113.1:443:443"
   ```

---

## Configuration Errors

### `configs/silentium.conf: yaml: line 47: did not find expected key`

**Cause:** `silentium.conf` is INI format (parsed by Python's `configparser`),
not YAML.  A tool (e.g. `yamllint`) is incorrectly treating it as YAML.

**Fix:** Do not run YAML validators against `silentium.conf`.  Use Python to
validate:
```bash
python3 -c "import configparser; c = configparser.ConfigParser(); c.read('configs/silentium.conf'); print('OK')"
```

### `node/app.py: KeyError: 'RELAY_PUBKEY'`

**Cause:** Stale error from pre-v1.0.  The current implant uses
`os.environ.get()` throughout with safe defaults.

**Fix:** Update to v1.0.  All environment variables have defaults:
```bash
grep "os.environ.get" node/app.py | head -5
```

---

## WireGuard Errors

### `wireguard/wg0.conf.template: invalid key format`

**Cause:** The template placeholders (e.g. `CORE_PRIVATE_KEY_PLACEHOLDER`)
are not real WireGuard keys.  WireGuard validates key format on parse.

**Fix:** Generate real keys and substitute them before use:
```bash
bash scripts/gen_keys.sh          # generates wireguard key pairs
# or manually:
wg genkey | tee private.key | wg pubkey > public.key

# Substitute into template
sed -e "s|CORE_PRIVATE_KEY_PLACEHOLDER|$(cat core_private.key)|" \
    -e "s|RELAY1_PUBLIC_KEY_PLACEHOLDER|$(cat relay1_public.key)|" \
    wireguard/wg0.conf.template > /etc/wireguard/wg0.conf
```
See `scripts/setup_wireguard.sh` for the full setup procedure.

---

## Database Errors

### `ERROR: relation "campaigns" does not exist`

**Cause:** The database schema was not initialised.

**Fix:**
```bash
# With docker compose (schema auto-applied from init.sql on first start):
docker compose -f deployment/docker-compose.silentium.yml down -v
docker compose -f deployment/docker-compose.silentium.yml up -d postgres
# Wait for postgres to be healthy, then:
docker compose -f deployment/docker-compose.silentium.yml up -d core

# Manual schema application:
psql "postgresql://aegis:PASSWORD@localhost:5432/aegis_silentium" \
    -f deployment/init.sql
```

---

## Terraform Errors

### `Error: Invalid AWS region: us-east-1`

**Cause:** The `us-east-1` region is not available or not enabled in your
AWS account, or your IAM credentials don't have access to that region.

**Fix:**
```hcl
# deployment/terraform/variables.tf
variable "aws_region" {
  default = "eu-west-1"   # change to a region you have access to
}
```
Or override at apply time:
```bash
cd deployment/terraform
terraform apply -var="aws_region=eu-west-1"
```

---

## Script Errors

### `scripts/gen_certs.sh: openssl: command not found`

**Cause:** OpenSSL is not installed.

**Fix:**
```bash
# Debian/Ubuntu
apt-get install -y openssl

# Alpine
apk add openssl

# macOS
brew install openssl
export PATH="/opt/homebrew/opt/openssl/bin:$PATH"
```

### `scripts/inject_objective.sh: gpg: decryption failed: No secret key`

**Cause:** The operator's GPG private key is not in the local keyring.

**Fix:**
1. The primary signing mechanism for v1.0 is ECDSA P-256 (via OpenSSL),
   **not** GPG.  GPG is only used if you configured optional encrypted
   config bundles via `scripts/gen_keys.sh --gpg`.
2. If you do use GPG, import your key:
   ```bash
   gpg --import operator_private.gpg
   ```
3. Or regenerate the key:
   ```bash
   bash scripts/gen_keys.sh --gpg
   ```

### `scripts/test_relay.sh: ./relay: cannot execute binary file: Exec format error`

**Cause:** The relay binary was compiled for a different architecture
(e.g. compiled for `linux/arm64` but running on `linux/amd64`).

**Fix:**
```bash
# Re-compile for the correct target
cd relay/
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o relay ./main.go

# Verify architecture
file relay
# Should show: ELF 64-bit LSB executable, x86-64
```

Use `scripts/build.sh --platform linux/amd64` to specify the target.

### `fatal: '/usr/local/bin/relay' is not writable`

**Cause:** Installing the relay binary to a system path without root.

**Fix:**
```bash
# Install to user bin (no sudo required)
cp relay/relay ~/.local/bin/relay
chmod +x ~/.local/bin/relay
export PATH="$HOME/.local/bin:$PATH"

# Or install to project dist directory
bash scripts/build.sh --out ./dist
./dist/relay/relay --config configs/relay1.yaml
```

---

## Cryptography Errors

### `shared/crypto/aes.py TypeError: key must be bytes`

See the [Python Runtime Errors](#python-runtime-errors) section above.

### ECDHE import errors (cryptography < 3.0)

See [ImportError: cannot import name 'ecdh'](#importerror-cannot-import-name-ecdh-from-cryptographyhazmatprimitivesasymmetric) above.

---

## Network / Connectivity Errors

### DNS-over-HTTPS endpoint unreachable

**Cause:** Network policy blocks outbound HTTPS to DoH resolvers.

**Fix:**
1. Test connectivity: `curl -s "https://1.1.1.1/dns-query?name=example.com&type=A" -H "Accept: application/dns-json"`
2. Use a different DoH provider in `configs/silentium.conf`:
   ```ini
   doh_provider = google          # 8.8.8.8/resolve
   # doh_provider = cloudflare   # 1.1.1.1/dns-query (default)
   # doh_provider = quad9        # 9.9.9.9/dns-query
   ```
3. The exfil manager automatically falls back to the next channel in
   `channel_priority` when DoH fails.

### General: `Connection refused` to C2

1. Verify the relay is running: `curl -sk https://relay.example.com/health`
2. Check port 443 is open: `nc -zv relay.example.com 443`
3. Verify the WireGuard tunnel is up: `wg show wg0`
4. Check the relay logs: `docker logs aegis-relay1`
5. Verify the core is healthy: `docker logs aegis-core | tail -20`
