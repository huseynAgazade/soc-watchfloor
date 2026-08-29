"""mcp-splunk — MCP server.

Source: Splunk SIEM (editable SPL from the admin query catalog)
Curated SIEM metrics — case volume, EPS by feed, notable trend, noisy rules — via tokenized read-only SPL.

Read-only. Every tool receives a tenant scope from the core client and must
constrain its query to it; a tool must never widen scope from its own arguments.
Tools return at most ~20 labelled values, not raw payloads — that keeps a locally
hosted model honest and cheap. This is a scaffold: tool handlers are stubs.
"""
import os

SERVER_NAME = "mcp-splunk"
SOURCE = "Splunk SIEM (editable SPL from the admin query catalog)"

# The read-only tools this server exposes to the core agent + dashboards.
TOOLS = [
    "list_dashboards",
    "query_metric",
    "get_soc_metric_pack",
    "compare_periods",]


def main() -> None:
    # TODO: register TOOLS with the MCP runtime and serve over stdio/socket.
    # Each handler: validate tenant scope, run the read-only query, return
    # <=20 labelled values. See docs/ARCHITECTURE.md §7.
    print(f"{SERVER_NAME} scaffold — source={SOURCE} — {len(TOOLS)} tools")


if __name__ == "__main__":
    main()
