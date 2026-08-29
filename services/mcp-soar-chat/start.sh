#!/bin/sh
# Run the upstream splunk-soar-mcp server (private, readonly) + the exec bridge.
set -e
splunk-soar-mcp --transport streamable-http --host 127.0.0.1 --port 9010 &
export SOAR_MCP_HTTP_URL=http://127.0.0.1:9010/mcp
exec uvicorn facade:app --host 0.0.0.0 --port 9011
