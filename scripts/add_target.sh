#!/usr/bin/env bash
# AEGIS-Advanced — CLI Target Submission
# Usage: bash scripts/add_target.sh <target|--file FILE> [options]
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
log()  { echo -e "${GREEN}[✓]${RESET} $*"; }
info() { echo -e "${CYAN}[→]${RESET} $*"; }
err()  { echo -e "${RED}[✗]${RESET} $*" >&2; }
die()  { err "$*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$(dirname "$SCRIPT_DIR")/.env"
[[ -f "$ENV_FILE" ]] && { set -a; source "$ENV_FILE"; set +a; }

C2_URL="${C2_URL:-http://localhost:5000}"
OPERATOR_KEY="${OPERATOR_KEY:-aegis-operator-key-2026}"
TARGET=""; CAMPAIGN="default"; PRIORITY=5; FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --campaign|-c) CAMPAIGN="$2"; shift ;;
    --priority|-p) PRIORITY="$2"; shift ;;
    --c2)          C2_URL="$2"; shift ;;
    --key|-k)      OPERATOR_KEY="$2"; shift ;;
    --file|-f)     FILE="$2"; shift ;;
    --help|-h)
      echo "Usage: $0 <target> [--campaign NAME] [--priority 0-9] [--file FILE]"
      echo "  target: URL, IP, or CIDR (e.g. https://example.com or 10.0.0.0/24)"
      exit 0 ;;
    *) TARGET="$1" ;;
  esac
  shift
done

# Check C2
STATS=$(curl -sf --connect-timeout 5 -H "X-Aegis-Key: $OPERATOR_KEY" "$C2_URL/api/stats" 2>/dev/null || echo "{}")
[[ "$STATS" == "{}" ]] && die "Cannot reach C2 at $C2_URL — is AEGIS running?"
NODES=$(echo "$STATS" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('active_nodes',0))" 2>/dev/null || echo "?")
log "C2 connected — $NODES active node(s)"

# Build target list
TARGETS=()
if [[ -n "$FILE" ]]; then
  [[ -f "$FILE" ]] || die "File not found: $FILE"
  while IFS= read -r line; do
    line="${line%%#*}"; line="${line//[[:space:]]/}"
    [[ -n "$line" ]] && TARGETS+=("$line")
  done < "$FILE"
elif [[ -n "$TARGET" ]]; then
  # Expand CIDR if needed
  if [[ "$TARGET" =~ ^[0-9.]+/[0-9]+$ ]]; then
    info "Expanding CIDR: $TARGET"
    while IFS= read -r ip; do TARGETS+=("$ip"); done < <(
      python3 -c "
import sys, ipaddress
net=ipaddress.ip_network('$TARGET', strict=False)
hosts=list(net.hosts())
if len(hosts)>512: print('$TARGET')
else:
  for h in hosts: print(str(h))
" 2>/dev/null || echo "$TARGET")
  else
    TARGETS+=("$TARGET")
  fi
else
  die "No target. Use: $0 https://example.com"
fi

[[ ${#TARGETS[@]} -eq 0 ]] && die "No valid targets"
info "${#TARGETS[@]} target(s) to submit"

# Get/create campaign
CAMP_RESP=$(curl -sf -X POST "$C2_URL/api/campaigns" \
  -H "X-Aegis-Key: $OPERATOR_KEY" -H "Content-Type: application/json" \
  -d "{\"name\":\"$CAMPAIGN\"}" 2>/dev/null || echo "{}")
CAMP_ID=$(echo "$CAMP_RESP" | python3 -c \
  "import sys,json;d=json.load(sys.stdin);print(d.get('campaign_id',1))" 2>/dev/null || echo "1")
[[ -z "$CAMP_ID" || "$CAMP_ID" == "null" ]] && CAMP_ID=1

# Submit in batches
BATCH_SIZE=50; SUBMITTED=0
for (( i=0; i<${#TARGETS[@]}; i+=BATCH_SIZE )); do
  CHUNK=("${TARGETS[@]:$i:$BATCH_SIZE}")
  JSON=$(python3 -c "import json,sys; print(json.dumps(sys.argv[1:]))" "${CHUNK[@]}")
  RESP=$(curl -sf -X POST "$C2_URL/api/campaigns/$CAMP_ID/targets" \
    -H "X-Aegis-Key: $OPERATOR_KEY" -H "Content-Type: application/json" \
    -d "{\"targets\":$JSON,\"priority\":$PRIORITY}" 2>/dev/null || echo "{}")
  ADDED=$(echo "$RESP" | python3 -c \
    "import sys,json;d=json.load(sys.stdin);print(d.get('added',0))" 2>/dev/null || echo "0")
  SUBMITTED=$((SUBMITTED+ADDED))
  printf "\r  Queued: %d/%d" "$SUBMITTED" "${#TARGETS[@]}"
done
echo ""

echo ""
log "$SUBMITTED target(s) queued in campaign '$CAMPAIGN' (priority=$PRIORITY)"
echo -e "  Dashboard: ${CYAN}http://localhost:7331${RESET}"
echo -e "  Campaign:  ${CYAN}$C2_URL/api/campaigns/$CAMP_ID${RESET}"
echo ""
