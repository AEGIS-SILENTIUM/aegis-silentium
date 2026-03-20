# AEGIS-SILENTIUM v12 — Termux Standalone Installation Guide

Complete step-by-step guide to running AEGIS-SILENTIUM standalone on an
Android device using Termux. No root required. No Docker. Tested on
Android 10–14, arm64.

---

## Prerequisites

| Requirement | Minimum |
|---|---|
| Android version | 10.0+ |
| RAM | 3 GB (4 GB+ recommended) |
| Storage | 4 GB free |
| Architecture | arm64 (most modern phones) |
| Network | WiFi or mobile data |

---

## Part 1 — Install Termux

**Do NOT use Termux from the Google Play Store** — it is outdated and
broken. Use the F-Droid version.

1. Open your browser and go to: **https://f-droid.org/packages/com.termux/**
2. Download and install the APK.
3. Open Termux.

---

## Part 2 — Bootstrap the Environment

Run every command exactly as shown. Do not skip steps.

### 2.1 Update Termux packages

```bash
pkg update -y && pkg upgrade -y
```

### 2.2 Install system dependencies

```bash
pkg install -y \
  python \
  python-pip \
  postgresql \
  redis \
  golang \
  git \
  openssl \
  libffi \
  build-essential \
  wget \
  curl \
  nano
```

> **Note:** This will download ~400 MB. Use WiFi.

### 2.3 Verify versions

```bash
python --version        # must be 3.11+
python3 --version       # same
pg_config --version     # PostgreSQL 15+
redis-server --version  # Redis 7+
go version              # Go 1.21+
```

---

## Part 3 — Set Up PostgreSQL

### 3.1 Initialize the database cluster

```bash
mkdir -p $PREFIX/var/lib/postgresql
initdb $PREFIX/var/lib/postgresql
```

### 3.2 Start PostgreSQL

```bash
pg_ctl -D $PREFIX/var/lib/postgresql -l $PREFIX/var/log/postgresql.log start
```

### 3.3 Create the AEGIS database and user

```bash
createdb aegis
psql -d aegis -c "CREATE USER aegis WITH PASSWORD 'CHANGE_THIS_NOW';"
psql -d aegis -c "GRANT ALL PRIVILEGES ON DATABASE aegis TO aegis;"
psql -d aegis -c "ALTER USER aegis CREATEDB;"
```

> **Security:** Replace `CHANGE_THIS_NOW` with a strong random password.
> Generate one:
> ```bash
> cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 40
> ```

### 3.4 Apply the schema

Navigate to the AEGIS directory first (see Part 4), then:

```bash
psql -U aegis -d aegis -f deployment/init.sql
psql -U aegis -d aegis -f deployment/migrations/v9_schema.sql
psql -U aegis -d aegis -f deployment/migrations/v10_distributed.sql
psql -U aegis -d aegis -f deployment/migrations/v11_full.sql
```

---

## Part 4 — Get AEGIS-SILENTIUM

### 4.1 Extract the project

Copy `AEGIS-SILENTIUM-v12.zip` to your device (via USB, download link, etc.)
then in Termux:

```bash
# If file is in Downloads:
cp /sdcard/Download/AEGIS-SILENTIUM-v12.zip ~/
cd ~
unzip AEGIS-SILENTIUM-v12.zip
cd AEGIS-SILENTIUM-v12
```

---

## Part 5 — Set Up the Python Environment

### 5.1 Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate
```

Your prompt will now show `(venv)`.

### 5.2 Install Python dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

If any package fails to compile, install its system header first:

```bash
# For psycopg2:
pkg install -y libpq
pip install psycopg2-binary

# For cryptography:
pkg install -y libcrypt
pip install cryptography

# For Pillow (screenshots):
pkg install -y libjpeg-turbo libpng
pip install Pillow
```

---

## Part 6 — Set Up Redis

### 6.1 Start Redis

```bash
redis-server --daemonize yes \
  --logfile $PREFIX/var/log/redis.log \
  --bind 127.0.0.1 \
  --requirepass "CHANGE_REDIS_PASSWORD"
```

> Generate a password:
> ```bash
> cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 32
> ```

---

## Part 7 — Generate Credentials and Certificates

### 7.1 Generate the operator key

```bash
# Generate a cryptographically secure 48-character key
OPERATOR_KEY=$(cat /dev/urandom | tr -dc 'A-Za-z0-9!@#$%^&*' | head -c 48)
echo "OPERATOR_KEY=$OPERATOR_KEY"
# Save it — you will need it to log in
```

### 7.2 Generate TLS certificates (self-signed for local use)

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -days 365 -nodes \
  -subj "/CN=aegis-local/O=AEGIS/C=US"
echo "✅ TLS certs generated"
```

### 7.3 Get the certificate fingerprint (for cert pinning)

```bash
openssl x509 -in certs/cert.pem -fingerprint -sha256 -noout \
  | sed 's/SHA256 Fingerprint=//' \
  | tr -d ':'
```

Save this fingerprint — use it as `AEGIS_RELAY_CERT_HASH`.

### 7.4 Generate the relay signing key

```bash
openssl ecparam -genkey -name prime256v1 | openssl ec -out certs/relay_key.pem
openssl ec -in certs/relay_key.pem -pubout -out certs/relay_pub.pem
echo "✅ ECDSA relay keys generated"
```

---

## Part 8 — Configure Environment Variables

### 8.1 Create the `.env` file

```bash
cat > .env << EOF
# ── REQUIRED — do not start without these ──
OPERATOR_KEY=${OPERATOR_KEY}
POSTGRES_PASSWORD=CHANGE_THIS_NOW
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_DB=aegis
POSTGRES_USER=aegis
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=CHANGE_REDIS_PASSWORD

# ── TLS / Security ──
AEGIS_RELAY_CERT_HASH=PASTE_FINGERPRINT_HERE
AEGIS_ALLOW_KEY_AUTH=0

# ── Optional tuning ──
C2_PORT=8080
C2_DEBUG=false
LOG_LEVEL=info
EOF
```

### 8.2 Export the variables

```bash
set -a
source .env
set +a
```

> Add `source ~/AEGIS-SILENTIUM-v12/.env` to `~/.bashrc` so variables
> persist across sessions:
> ```bash
> echo "set -a; source ~/AEGIS-SILENTIUM-v12/.env; set +a" >> ~/.bashrc
> ```

---

## Part 9 — Start the C2 Server

### 9.1 Run in the foreground (testing)

```bash
source venv/bin/activate
python c2/app.py
```

You should see:

```
[AEGIS] v12.0 online — operator key OK — postgres OK — redis OK
 * Running on http://0.0.0.0:8080
```

If you see `OPERATOR_KEY environment variable is not set` — re-run Part 8.

### 9.2 Run in the background (persistent)

```bash
nohup python c2/app.py > logs/c2.log 2>&1 &
echo "C2 PID: $!"
```

### 9.3 Keep it running when Termux is closed

Install Termux:Boot from F-Droid, then:

```bash
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/start-aegis.sh << 'BOOTEOF'
#!/data/data/com.termux/files/usr/bin/bash
cd ~/AEGIS-SILENTIUM-v12
pg_ctl -D $PREFIX/var/lib/postgresql start
sleep 2
redis-server --daemonize yes --bind 127.0.0.1 \
  --requirepass "$REDIS_PASSWORD" \
  --logfile $PREFIX/var/log/redis.log
sleep 1
set -a; source .env; set +a
source venv/bin/activate
nohup python c2/app.py > logs/c2.log 2>&1 &
BOOTEOF
chmod +x ~/.termux/boot/start-aegis.sh
echo "✅ Boot script installed"
```

---

## Part 10 — Start the Scheduler

Open a second Termux session (swipe right → New Session):

```bash
cd ~/AEGIS-SILENTIUM-v12
set -a; source .env; set +a
source venv/bin/activate
python scheduler/app.py
```

---

## Part 11 — Access the Dashboard

### 11.1 Find your device IP

```bash
ip addr show wlan0 | grep "inet " | awk '{print $2}' | cut -d/ -f1
```

### 11.2 Open the dashboard

Open Chrome or Firefox on the same device or another device on the same
network:

```
http://YOUR_DEVICE_IP:8080
```

Log in with:
- **Handle:** `r00t_handler` (or whatever you configured)
- **Key:** the `OPERATOR_KEY` you generated in Part 7

---

## Part 12 — Start the Relay (optional, for remote implants)

```bash
cd relay
# Install Go deps (first time only)
go mod download
# Build relay
go build -o relay-bin .
# Run
./relay-bin \
  --c2 http://127.0.0.1:8080 \
  --listen 0.0.0.0:4443 \
  --cert ../certs/cert.pem \
  --key ../certs/key.pem
```

---

## Part 13 — Verify Everything Works

```bash
# Health check
curl -s http://127.0.0.1:8080/api/health | python -m json.tool

# Login and get a token
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"handle\":\"r00t_handler\",\"operator_key\":\"$OPERATOR_KEY\"}" \
  | python -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "Token: ${TOKEN:0:20}..."

# Check system status
curl -s http://127.0.0.1:8080/api/v11/system \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool

# List nodes (should be empty initially)
curl -s http://127.0.0.1:8080/api/nodes \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool
```

---

## Troubleshooting

### PostgreSQL won't start

```bash
# Check the log
tail -50 $PREFIX/var/log/postgresql.log

# If "directory already exists but is not empty":
rm -rf $PREFIX/var/lib/postgresql
initdb $PREFIX/var/lib/postgresql
pg_ctl -D $PREFIX/var/lib/postgresql start
```

### Redis AUTH error

```bash
# Connect to redis and check
redis-cli -a "$REDIS_PASSWORD" ping
# Should print PONG
```

### `OPERATOR_KEY not set` error

```bash
source .env
echo $OPERATOR_KEY  # must be non-empty and 32+ chars
```

### `psycopg2` install fails

```bash
pkg install -y libpq-dev
LDFLAGS="-L$PREFIX/lib" CPPFLAGS="-I$PREFIX/include" pip install psycopg2
```

### `cryptography` install fails

```bash
pkg install -y rust
pip install cryptography --no-binary cryptography
```

### Out of memory during install

```bash
# Reduce pip parallelism
pip install --no-cache-dir -r requirements.txt
```

### Port 8080 already in use

```bash
# Find and kill the process
lsof -i :8080 | awk 'NR>1{print $2}' | xargs kill -9
```

### Dashboard loads but login fails

1. Confirm `OPERATOR_KEY` is exactly the same value in `.env` and what you type.
2. Check that the bootstrap operator was created:
   ```bash
   psql -U aegis -d aegis -c "SELECT handle, role FROM operators;"
   ```
3. If the table is empty, re-apply migrations:
   ```bash
   psql -U aegis -d aegis -f deployment/migrations/v9_schema.sql
   ```

---

## Uninstalling

```bash
# Stop services
pg_ctl -D $PREFIX/var/lib/postgresql stop
redis-cli -a "$REDIS_PASSWORD" shutdown

# Remove everything
rm -rf ~/AEGIS-SILENTIUM-v12
dropdb aegis
```

---

## Security Reminders for Termux Deployments

1. **Never expose port 8080 to the open internet without a VPN.**
   Use WireGuard (`pkg install wireguard-tools`) to create a private tunnel.

2. **Rotate the `OPERATOR_KEY` after every engagement.**

3. **The self-signed TLS cert is for local/lab use only.**
   For production, use Let's Encrypt via certbot or a commercially-signed cert.

4. **Enable screen lock** on the Android device. Termux sessions persist
   behind the lock screen.

5. **Wipe after engagement:**
   ```bash
   psql -U aegis -d aegis -c "TRUNCATE nodes, tasks, events, vulnerabilities, exfil_receipts CASCADE;"
   ```

---

*AEGIS-SILENTIUM v12 — Termux Quickstart · Last updated: 2026-03*
