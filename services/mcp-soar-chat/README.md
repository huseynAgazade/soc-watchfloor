# mcp-soar-chat

The **assistant's** tool provider: [YOUR_ORG/splunk-soar-mcp](https://github.com/YOUR_ORG/splunk-soar-mcp)
run as a private, **read-only** MCP server, plus a thin `facade.py` bridge the core
calls to execute an already-authorized tool.

- The MCP server has **no auth of its own** — so it is bound to localhost and the
  **core's authorization proxy** (`services/core/app/assistant/`) is the boundary:
  it authenticates the portal user, filters tools by role, enforces tenant
  (customer-label) scope, and sanitizes arguments before any call runs here.
- `readonly` mode registers only query tools (51). Credential redaction is always on.

## Run
```bash
cp .env.example .env      # SOAR base url + automation-user token
./start.sh                # splunk-soar-mcp (9010, private) + facade (9011)
```
