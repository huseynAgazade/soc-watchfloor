"""Live test: authenticate to Splunk and run every SOAR/SLA tool, then confirm
the MCP server registers them. Reads the Splunk password from SPLUNK_PASSWORD
(set it in the environment, never commit it)."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import tools  # noqa: E402
from splunk_client import SplunkClient  # noqa: E402


def show(title, rows, n=3):
    print(f"\n=== {title} — {len(rows)} rows ===")
    for r in rows[:n]:
        print("  ", r)


def main():
    if not os.environ.get("SPLUNK_PASSWORD") and not os.environ.get("SPLUNK_TOKEN"):
        print("SET SPLUNK_PASSWORD (or SPLUNK_TOKEN) first"); return
    c = SplunkClient()
    c.login()
    print("Splunk auth: OK")

    show("get_sla_by_customer(7d, all)", tools.get_sla_by_customer(c, "7d", "all"), 6)
    show("get_sla_by_customer(7d, initech)", tools.get_sla_by_customer(c, "7d", "initech"))
    show("get_analyst_performance(30d)", tools.get_analyst_performance(c, "30d"), 6)
    show("get_status_mix(7d)", tools.get_status_mix(c, "7d"), 8)
    show("get_case_volume(7d, all)", tools.get_case_volume(c, "7d", "all"), 6)
    c.close()

    # confirm the MCP server exposes these as tools
    import server
    reg = asyncio.get_event_loop().run_until_complete(server.mcp.list_tools())
    print("\n=== MCP tools registered ===")
    for t in reg:
        print("  -", t.name)


if __name__ == "__main__":
    main()
