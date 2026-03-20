#!/usr/bin/env bash
# AEGIS-Advanced — Standalone Scan (No Docker Required)
# Usage: bash scripts/standalone.sh <target> [aegis flags...]
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
log()  { echo -e "${GREEN}[✓]${RESET} $*"; }
info() { echo -e "${CYAN}[→]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
die()  { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

echo -e "${CYAN}"
cat << 'BANNER'
 ╔═══════════════════════════════════════════╗
 ║  AEGIS-Advanced v4.0-APEX  STANDALONE     ║
 ║  No Docker · Direct Scan · Auto-Report    ║
 ╚═══════════════════════════════════════════╝
BANNER
echo -e "${RESET}"

TARGET=""
SERVE_PORT=7331
OUTPUT_DIR=""
EXTRA_ARGS=()
OPEN_BROWSER=true
INSTALL_DEPS=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    http*|https*)   TARGET="$1" ;;
    --no-browser)   OPEN_BROWSER=false ;;
    --install-deps) INSTALL_DEPS=true ;;
    --output|-o)    OUTPUT_DIR="$2"; shift ;;
    --serve-port)   SERVE_PORT="$2"; shift ;;
    --help|-h)
      echo "Usage: $0 <target> [--full] [--ml] [--stealth] [--threads N] [--depth N]"
      echo "       [--serve-port N] [--output DIR] [--no-browser] [--install-deps]"
      exit 0 ;;
    *)  EXTRA_ARGS+=("$1") ;;
  esac
  shift
done

[[ -z "$TARGET" ]] && die "No target. Usage: $0 https://target.com"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

PYTHON=$(command -v python3 2>/dev/null || die "Python 3 not found")
PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
log "Python $PY_VER"

if [[ "$INSTALL_DEPS" == "true" ]]; then
  info "Installing dependencies..."
  "$PYTHON" -m pip install -q --user flask flask-cors aiohttp requests \
    beautifulsoup4 lxml cryptography scikit-learn numpy dnspython 2>/dev/null || true
  log "Dependencies installed"
fi

HAVE_FLASK=$("$PYTHON" -c "import flask; print('true')" 2>/dev/null || echo "false")
HAVE_ML=$("$PYTHON" -c "import sklearn; print('true')" 2>/dev/null || echo "false")

if [[ -z "$OUTPUT_DIR" ]]; then
  SAFE=$(echo "$TARGET" | sed 's|https\?://||;s|[^a-zA-Z0-9_.-]|_|g' | cut -c1-40)
  OUTPUT_DIR="$PROJECT_DIR/reports/standalone_${SAFE}_$(date +%Y%m%d_%H%M%S)"
fi
mkdir -p "$OUTPUT_DIR"
log "Output: $OUTPUT_DIR"

HAS_SERVE=false
for arg in "${EXTRA_ARGS[@]:-}"; do [[ "$arg" == "--serve" ]] && HAS_SERVE=true; done
[[ "$HAVE_FLASK" == "true" ]] && EXTRA_ARGS+=("--serve" "--serve-port" "$SERVE_PORT")
EXTRA_ARGS+=("--output" "$OUTPUT_DIR")
[[ "$HAVE_ML" == "true" ]] && EXTRA_ARGS+=("--ml")

AEGIS="$PROJECT_DIR/node/aegis_core.py"
[[ -f "$AEGIS" ]] || die "aegis_core.py not found at $AEGIS"

export PYTHONPATH="$PROJECT_DIR/node:$PROJECT_DIR:${PYTHONPATH:-}"

echo ""
info "Scanning: $TARGET"
echo -e "${YELLOW}  Report: http://127.0.0.1:${SERVE_PORT}/report.html${RESET}"
echo ""

"$PYTHON" "$AEGIS" --target "$TARGET" "${EXTRA_ARGS[@]}" &
AEGIS_PID=$!

if [[ "$HAVE_FLASK" == "true" ]]; then
  sleep 5
  REPORT_URL="http://127.0.0.1:${SERVE_PORT}/report.html"
  if [[ "$OPEN_BROWSER" == "true" ]]; then
    for b in xdg-open open start; do
      command -v "$b" >/dev/null 2>&1 && { "$b" "$REPORT_URL" 2>/dev/null & break; }
    done
  fi
  echo ""
  log "Report server: $REPORT_URL"
  echo -e "  PID: $AEGIS_PID  |  Stop: kill $AEGIS_PID"
  echo ""
fi

wait "$AEGIS_PID" 2>/dev/null || true
log "Scan complete — output in $OUTPUT_DIR"
