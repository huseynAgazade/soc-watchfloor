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
#   "$ROOT/secrets/soar.env"  (SOAR URL + automation token)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$ROOT/.testvenv/bin"
CHATVENV="$ROOT/services/mcp-soar-chat/.venv/bin"
LOGS="$ROOT/deploy/logs"; mkdir -p "$LOGS"
PY="$VENV/python"

stop() {
  pkill -f 'uvicorn app.main:app --host 0.0.0.0 --port 8' 2>/dev/null
  pkill -f 'uvicorn app.redirect:app --host 0.0.0.0 --port 8000' 2>/dev/null
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

  # SOAR (soar.example) for the roster + the assistant's MCP server: URL and
  # automation token from the SOAR secrets file.
  local SOAR_SECRETS="$ROOT/secrets/soar.env" SOAR_URL SOAR_API
  SOAR_URL="$(grep -E '^SPLUNK_SOAR_NEW_URL=' "$SOAR_SECRETS" | cut -d= -f2-)"
  SOAR_API="$(grep -E '^SPLUNK_SOAR_NEW_API=' "$SOAR_SECRETS" | cut -d= -f2-)"
  if [ -z "$SOAR_URL" ] || [ -z "$SOAR_API" ]; then
    echo "ERROR: SPLUNK_SOAR_NEW_URL / SPLUNK_SOAR_NEW_API missing in $SOAR_SECRETS"; exit 1
  fi
  # Splunk SLA token (Acme) from the detection secrets
  local SLA_TOKEN
  SLA_TOKEN="$(grep -E '^Splunk_TOKEN_ACME=' "$ROOT/services/mcp-detection/secrets.env" | cut -d= -f2-)"

  # 1. SLA/L1 connector (token against the SIEM head)
  launch mcp-soar "$ROOT/services/mcp-soar" \
    "SPLUNK_BASE_URL=https://10.0.0.11:8089 SPLUNK_TOKEN=$SLA_TOKEN SPLUNK_VERIFY_SSL=false" \
    "$VENV/uvicorn" http_api:app --host 127.0.0.1 --port 9000 --log-level warning

  # 2. roster connector (SOAR custom list monthly_shift_roster, found by name)
  launch mcp-roster "$ROOT/services/mcp-roster" \
    "SPLUNK_SOAR_URL=$SOAR_URL SPLUNK_SOAR_API=$SOAR_API SOAR_VERIFY_SSL=false" \
    "$VENV/uvicorn" http_api:app --host 127.0.0.1 --port 9001 --log-level warning

  # 3. detection connector (serves the export coverage; re-exports daily at 06:00
  #    Dubai, at start-up when the rules are over a day old, and on demand)
  launch mcp-detection "$ROOT/services/mcp-detection" \
    "DETECTION_COMBINED_JSON=$ROOT/services/mcp-detection/pipeline/rules/_all_rules_combined.json \
     DETECTION_SECRETS_FILE=$ROOT/services/mcp-detection/secrets.env DETECTION_REFRESH_AT=06:00 ORG_TIMEZONE=Asia/Dubai" \
    "$VENV/uvicorn" http_api:app --host 127.0.0.1 --port 9002 --log-level warning

  # 4. the SOAR MCP server for the assistant (readonly, private)
  launch soar-mcp "$ROOT/services/mcp-soar-chat" \
    "SPLUNK_SOAR_URL=$SOAR_URL SPLUNK_SOAR_API=$SOAR_API SOAR_MCP_MODE=readonly SOAR_MCP_VERIFY_SSL=false" \
    "$CHATVENV/splunk-soar-mcp" --transport streamable-http --host 127.0.0.1 --port 9010

  # 5. the exec bridge in front of it
  launch soar-bridge "$ROOT/services/mcp-soar-chat" \
    "SOAR_MCP_HTTP_URL=http://127.0.0.1:9010/mcp" \
    "$CHATVENV/uvicorn" facade:app --host 0.0.0.0 --port 9011 --log-level warning

  # 6. TLS certificate for the core. Self-signed for this host on first run —
  #    replace deploy/certs/watchfloor.{crt,key}.pem with one from your internal CA
  #    and browsers stop warning (then set HSTS_ENABLED=true).
  local CERTS="$ROOT/deploy/certs"
  mkdir -p "$CERTS"
  if [ ! -s "$CERTS/watchfloor.crt.pem" ] || [ ! -s "$CERTS/watchfloor.key.pem" ]; then
    local SAN="DNS:localhost,DNS:$(hostname),IP:127.0.0.1" ip
    for ip in $(hostname -I); do SAN="$SAN,IP:$ip"; done
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=SOC Watchfloor" \
      -addext "subjectAltName=$SAN" -keyout "$CERTS/watchfloor.key.pem" -out "$CERTS/watchfloor.crt.pem" 2>/dev/null
    chmod 600 "$CERTS/watchfloor.key.pem"
  fi

  sleep 3
  # 7. the core over HTTPS on :8443 (auth, API, the web app; reads services/core/.env)
  launch core "$ROOT/services/core" \
    "DATABASE_URL=sqlite+aiosqlite:///./app.db WEB_DIR=$ROOT/prototype \
     MCP_SOAR_URL=http://127.0.0.1:9000 MCP_ROSTER_URL=http://127.0.0.1:9001 \
     MCP_DETECTION_URL=http://127.0.0.1:9002 SOAR_CHAT_BRIDGE_URL=http://127.0.0.1:9011 \
     SEED_ADMIN_USERNAME=admin COOKIE_SECURE=true FORCE_HTTPS=true HTTPS_PORT=8443" \
    "$VENV/uvicorn" app.main:app --host 0.0.0.0 --port 8443 --log-level warning \
    --ssl-keyfile "$CERTS/watchfloor.key.pem" --ssl-certfile "$CERTS/watchfloor.crt.pem"

  # 8. plain HTTP on :8000 only redirects to HTTPS
  launch http-redirect "$ROOT/services/core" "HTTPS_PORT=8443" \
    "$VENV/uvicorn" app.redirect:app --host 0.0.0.0 --port 8000 --log-level warning

  sleep 6
  echo "started. health:"
  printf '  :8443 (https) -> %s\n' "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 https://127.0.0.1:8443/health 2>/dev/null || echo down)"
  for p in 8000 9000 9001 9002 9011; do
    printf '  :%s -> %s\n' "$p" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:$p/health 2>/dev/null || echo down)"
  done
  echo "open https://$(hostname -I | awk '{print $1}'):8443/   (http://…:8000 redirects there)"
  echo "(on an empty database the generated admin password is printed in $LOGS/core.log)"
}

case "${1:-start}" in
  stop) stop ;;
  *) start ;;
esac
