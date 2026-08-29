"""mcp-roster — MCP server.

Source: portal database + SOAR list (monthly_shift_roster) + on-call rotation
Who is on shift, who was, distribution, horizon, coverage, absences, on-call.

Read-only. Every tool receives a tenant scope from the core client and must
constrain its query to it; a tool must never widen scope from its own arguments.
Tools return at most ~20 labelled values, not raw payloads — that keeps a locally
hosted model honest and cheap. This is a scaffold: tool handlers are stubs.
"""
import os

SERVER_NAME = "mcp-roster"
SOURCE = "portal database + SOAR list (monthly_shift_roster) + on-call rotation"

# The read-only tools this server exposes to the core agent + dashboards.
TOOLS = [
    "who_is_on_shift",
    "who_was_on_shift",
    "get_shift_distribution",
    "get_roster_horizon",
    "get_shift_coverage",
    "list_unassigned_shifts",
    "get_absences",
    "get_oncall",
    "get_person_schedule",]


def main() -> None:
    # TODO: register TOOLS with the MCP runtime and serve over stdio/socket.
    # Each handler: validate tenant scope, run the read-only query, return
    # <=20 labelled values. See docs/ARCHITECTURE.md §7.
    print(f"{SERVER_NAME} scaffold — source={SOURCE} — {len(TOOLS)} tools")


if __name__ == "__main__":
    main()
