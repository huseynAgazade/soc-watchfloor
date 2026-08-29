"""mcp-detection — MCP server.

Source: detection-attck-mapper pipeline (Splunk + Falcon EDR export)
ATT&CK coverage (top-level), rule inventory, phantom cells, unmapped/operational/test rules.

Read-only. Every tool receives a tenant scope from the core client and must
constrain its query to it; a tool must never widen scope from its own arguments.
Tools return at most ~20 labelled values, not raw payloads — that keeps a locally
hosted model honest and cheap. This is a scaffold: tool handlers are stubs.
"""
import os

SERVER_NAME = "mcp-detection"
SOURCE = "detection-attck-mapper pipeline (Splunk + Falcon EDR export)"

# The read-only tools this server exposes to the core agent + dashboards.
TOOLS = [
    "get_mitre_coverage",
    "list_coverage_gaps",
    "list_rules",
    "get_rule_detail",
    "list_unmapped_rules",
    "list_disabled_rules",
    "get_phantom_cells",
    "compare_tenant_coverage",]


def main() -> None:
    # TODO: register TOOLS with the MCP runtime and serve over stdio/socket.
    # Each handler: validate tenant scope, run the read-only query, return
    # <=20 labelled values. See docs/ARCHITECTURE.md §7.
    print(f"{SERVER_NAME} scaffold — source={SOURCE} — {len(TOOLS)} tools")


if __name__ == "__main__":
    main()
