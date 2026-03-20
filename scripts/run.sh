#!/usr/bin/env bash
# AEGIS-Advanced — Docker Quick Start
# Usage: bash scripts/run.sh [--clean] [--scale N] [--profile admin]
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
log()  { echo -e "${GREEN}[✓]${RESET} $*"; }
info() { echo -e "${CYAN}[→]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
die()  { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

echo -e "${CYAN}"
cat << 'BANNER'
    ___    ________  ___________
   /   |  / ____/ / / / ___/
  / /| | / __/ / /_/ /\__ \
 / ___ |/ /___/ __  /___/ /
/_/  |_/_____/_/ /_//____/
       ADVANCED v4.0-APEX
BANNER
echo -e "${RESET}"

CLEAN=false; SCALE=3; PROFILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean)   CLEAN=true ;;
    --scale)   SCALE="${2:-3}"; shift ;;
    --profile) PROFILE="${2:-}"; shift ;;
    --help|-h) echo "Usage: $0 [--clean] [--scale N] [--profile admin|extra]"; exit 0 ;;
  esac
  shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_DIR/.env"
cd "$PROJECT_DIR"

command -v docker >/dev/null 2>&1 || die "Docker not installed"
docker info >/dev/null 2>&1     || die "Docker daemon not running"
log "Docker: $(docker --version | cut -d' ' -f3)"

# Generate secrets
if [[ ! -f "$ENV_FILE" ]]; then
  info "Generating secrets -> $ENV_FILE"
  cat > "$ENV_FILE" << ENVEOF
C2_SECRET=$(openssl rand -hex 32 2>/dev/null || python3 -c "import os,binascii;print(binascii.hexlify(os.urandom(32)).decode())")
OPERATOR_KEY=$(openssl rand -hex 16 2>/dev/null || python3 -c "import os,binascii;print(binascii.hexlify(os.urandom(16)).decode())")
POSTGRES_PASSWORD=$(openssl rand -hex 16 2>/dev/null || python3 -c "import os,binascii;print(binascii.hexlify(os.urandom(16)).decode())")
REDIS_PASSWORD=
HOSTNAME=$(hostname)
ENVEOF
  log "Secrets written"
fi
set -a; source "$ENV_FILE"; set +a

[[ "$CLEAN" == "true" ]] && {
  warn "Clean wipe — all data will be lost"
  read -rp "Type 'yes' to confirm: " C
  [[ "$C" == "yes" ]] && docker compose down -v --remove-orphans 2>/dev/null || true
}

CARGS=("-f" "docker-compose.yml" "--env-file" "$ENV_FILE")
[[ -n "$PROFILE" ]] && CARGS+=("--profile" "$PROFILE")

info "Building images..."
docker compose "${CARGS[@]}" build --parallel 2>&1 | grep -E "(Successfully|ERROR)" || true
log "Images ready"

info "Starting postgres + redis..."
docker compose "${CARGS[@]}" up -d postgres redis

info "Waiting for postgres..."
for i in $(seq 1 30); do
  docker compose "${CARGS[@]}" exec -T postgres pg_isready -U aegis -q 2>/dev/null && break
  sleep 2
done
log "PostgreSQL ready"

info "Starting C2..."
docker compose "${CARGS[@]}" up -d c2
sleep 10

info "Starting dashboard, scheduler, nodes..."
docker compose "${CARGS[@]}" up -d dashboard scheduler node-1 node-2 node-3
[[ "$SCALE" -gt 3 ]] && docker compose "${CARGS[@]}" --profile extra up -d

echo ""
echo -e "${CYAN}════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  AEGIS-Advanced Running${RESET}"
echo -e "${CYAN}════════════════════════════════════════════════${RESET}"
docker compose "${CARGS[@]}" ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null | head -15
echo ""
echo -e "  ${GREEN}Dashboard:   ${BOLD}http://localhost:7331${RESET}"
echo -e "  ${GREEN}C2 API:      ${BOLD}http://localhost:5000${RESET}"
echo -e "  ${GREEN}Operator Key:${BOLD} ${OPERATOR_KEY}${RESET}"
echo ""
echo -e "  Add target:  ${CYAN}bash scripts/add_target.sh https://target.com${RESET}"
echo -e "  View logs:   ${CYAN}docker compose logs -f${RESET}"
echo -e "  Stop:        ${CYAN}docker compose down${RESET}"
echo ""
