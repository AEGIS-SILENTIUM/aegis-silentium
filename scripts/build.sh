#!/usr/bin/env bash
# =============================================================================
# AEGIS-SILENTIUM v1.0 — Master Build Script
# Builds: Go/C implant, Go relay, Python C2/Dashboard (containerized)
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${REPO_ROOT}/dist"
mkdir -p "$OUT_DIR"

echo "======================================================"
echo " AEGIS-SILENTIUM v1.0 Master Build"
echo " Repo: $REPO_ROOT"
echo " Output: $OUT_DIR"
echo "======================================================"
echo ""

# ── 1. Implant (Go + C/CGO) ───────────────────────────────────────────────────
echo "[1/3] Building implant (Go/C hybrid)..."
mkdir -p "$OUT_DIR/implant"
C2_ADDRESS="${C2_ADDRESS:-https://127.0.0.1:8443}" \
C2_PUBKEY="${C2_PUBKEY:-}" \
PROFILE="${PROFILE:-default}" \
  bash "$REPO_ROOT/implant/build.sh" "$OUT_DIR/implant"

# ── 2. Relay (Go) ────────────────────────────────────────────────────────────
echo ""
echo "[2/3] Building relay (Go)..."
cd "$REPO_ROOT/relay"
if ! command -v go &>/dev/null; then
  echo "[-] go not found — skipping relay build"
else
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w" -o "$OUT_DIR/relay-linux-amd64" .
  echo "[+] → $OUT_DIR/relay-linux-amd64"
fi

# ── 3. C2/Dashboard (Python — syntax check only; runs in Docker) ──────────────
echo ""
echo "[3/3] Python syntax check (C2/Dashboard/Scheduler)..."
python3 -m py_compile "$REPO_ROOT/c2/app.py" && echo "[+] c2/app.py OK"
python3 -m py_compile "$REPO_ROOT/dashboard/app.py" && echo "[+] dashboard/app.py OK"
python3 -m py_compile "$REPO_ROOT/scheduler/app.py" && echo "[+] scheduler/app.py OK"

echo ""
echo "======================================================"
echo " Build complete. Artifacts in $OUT_DIR/"
echo " Next: scripts/gen_keys.sh → configure .env → docker compose up"
echo "======================================================"
