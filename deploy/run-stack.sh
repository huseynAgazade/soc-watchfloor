#!/usr/bin/env bash
# SOC Watchfloor — run the whole stack locally (no Docker needed).
# Core is served on :8000. Idempotent: stops any previous instances first.
#
#   ./deploy/run-stack.sh          # start (detached)
#   ./deploy/run-stack.sh stop     # stop everything
#
# Secrets are read from the git-ignored files already on this box:
#   services/mcp-detection/secrets.env   (Splunk SIEM + Falcon)
#   services/core/.env                   (ANTHROPIC_API_KEY)
#   $ROOT/secrets/soar.env  (SOAR REST token)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$ROOT/.testvenv/bin"
CHATVENV="$ROOT/services/mcp-soar-chat/.venv/bin"
LOGS="$ROOT/deploy/logs"; mkdir -p "$LOGS"
PY="$VENV/python"

stop() {
  pkill -f 'uvicorn app.main:app --host 0.0.0.0 --port 8000' 2>/dev/null
  pkill -f 'uvicorn http_api:app --host 127.0.0.1 --port 900' 2>/dev/null
  pkill -f 'uvicorn facade:app --host 0.0.0.0 --port 9011' 2>/dev/null
  pkill -f 'splunk-soar-mcp --transport' 2>/dev/null
  echo "stopped."
}

launch() { # name  workdir  "env assignments"  "command..."
  local name="$1" wd="$2" env="$3"; shift 3
  ( cd "$wd" && env $env setsid nohup "$@" >"$LOGS/$name.log" 2>&1 & )
}

start() {
  stop; sleep 1

  # SOAR REST token for the roster + chat MCP server
  local SOAR_URL SOAR_API
  SOAR_URL="$(grep -E '^SPLUNK_SOAR_URL=' $ROOT/secrets/soar.env | cut -d= -f2-)"
  SOAR_API="$(grep -E '^SPLUNK_SOAR_API=' $ROOT/secrets/soar.env | cut -d= -f2-)"
  # Splunk SLA token (Acme) from the detection secrets
  local SLA_TOKEN
  SLA_TOKEN="$(grep -E '^Splunk_TOKEN_ACME=' "$ROOT/services/mcp-detection/secrets.env" | cut -d= -f2-)"

  # 1. SLA/L1 connector (token against the SIEM head)
  launch mcp-soar "$ROOT/services/mcp-soar" \
    "SPLUNK_BASE_URL=https://10.0.0.11:8089 SPLUNK_TOKEN=$SLA_TOKEN SPLUNK_VERIFY_SSL=false" \
    "$VENV/uvicorn" http_api:app --host 127.0.0.1 --port 9000 --log-level warning

  # 2. roster connector (SOAR list 43)
  launch mcp-roster "$ROOT/services/mcp-roster" \
    "SPLUNK_SOAR_URL=$SOAR_URL SPLUNK_SOAR_API=$SOAR_API SOAR_VERIFY_SSL=false ROSTER_LIST_ID=43" \
    "$VENV/uvicorn" http_api:app --host 127.0.0.1 --port 9001 --log-level warning

  # 3. detection connector (serves the export coverage)
  launch mcp-detection "$ROOT/services/mcp-detection" \
    "DETECTION_COMBINED_JSON=$ROOT/services/mcp-detection/pipeline/rules/_all_rules_combined.json" \
    "$VENV/uvicorn" http_api:app --host 127.0.0.1 --port 9002 --log-level warning

  # 4. the SOAR MCP server for the assistant (readonly, private)
  launch soar-mcp "$ROOT/services/mcp-soar-chat" \
    "SPLUNK_SOAR_URL=$SOAR_URL SPLUNK_SOAR_API=$SOAR_API SOAR_MCP_MODE=readonly SOAR_MCP_VERIFY_SSL=false" \
    "$CHATVENV/splunk-soar-mcp" --transport streamable-http --host 127.0.0.1 --port 9010

  # 5. the exec bridge in front of it
  launch soar-bridge "$ROOT/services/mcp-soar-chat" \
    "SOAR_MCP_HTTP_URL=http://127.0.0.1:9010/mcp" \
    "$CHATVENV/uvicorn" facade:app --host 0.0.0.0 --port 9011 --log-level warning

  sleep 3
  # 6. the core (auth, API, serves the web app on :8000; reads services/core/.env)
  launch core "$ROOT/services/core" \
    "DATABASE_URL=sqlite+aiosqlite:///./app.db WEB_DIR=$ROOT/prototype \
     MCP_SOAR_URL=http://127.0.0.1:9000 MCP_ROSTER_URL=http://127.0.0.1:9001 \
     MCP_DETECTION_URL=http://127.0.0.1:9002 SOAR_CHAT_BRIDGE_URL=http://127.0.0.1:9011 \
     SEED_ADMIN_USERNAME=admin SEED_ADMIN_PASSWORD=changeme-admin COOKIE_SECURE=false" \
    "$VENV/uvicorn" app.main:app --host 0.0.0.0 --port 8000 --log-level warning

  sleep 6
  echo "started. health:"
  for p in 8000 9000 9001 9002 9011; do
    printf '  :%s -> %s\n' "$p" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:$p/health 2>/dev/null || echo down)"
  done
  echo "open http://$(hostname -I | awk '{print $1}'):8000/  (admin / changeme-admin)"
}

case "${1:-start}" in
  stop) stop ;;
  *) start ;;
esac
