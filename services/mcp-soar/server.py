"""mcp-soar — MCP server exposing read-only SOAR/SLA tools.

Source: Splunk (running restsoar against Splunk SOAR), the same path the
SOC Incident Overview dashboard uses. Every tool is read-only and returns a
small, labelled result set. Tenant scope is a parameter here; in production the
core injects it from the session and never trusts a model-supplied value.

Run as a normal MCP stdio server:  python server.py
The core connects to it as a tool provider; the assistant then calls these tools.
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

import queries
import tools
from splunk_client import SplunkClient

mcp = FastMCP("mcp-soar")

# One authenticated Splunk client, reused across tool calls.
_client: SplunkClient | None = None


def client() -> SplunkClient:
    global _client
    if _client is None:
        _client = SplunkClient()
        _client.login()
    return _client


@mcp.tool()
def get_sla_by_customer(window: str = "7d", tenant: str = "all") -> list[dict]:
    """Per-customer SLA means and compliance.

    Returns one row per customer with MTTA, MTTT, MTTR, MTTTres and MTTCR (mean
    seconds) plus compliance % for each stage, computed exactly like the SOC
    Incident Overview dashboard. window: 24h|7d|30d|60d|90d. tenant: a customer
    id or "all".
    """
    return tools.get_sla_by_customer(client(), *queries.bounds_for_window(window), tenant)


@mcp.tool()
def get_analyst_performance(window: str = "30d") -> list[dict]:
    """Per-analyst performance: cases owned, triage p50, MTTA, MTTR, MTTTres
    (mean seconds) and triage-SLA compliance %. Automation service accounts are
    excluded. window: 7d|30d|60d|90d.
    """
    return tools.get_analyst_performance(client(), *queries.bounds_for_window(window))


@mcp.tool()
def get_status_mix(window: str = "7d", tenant: str = "all") -> list[dict]:
    """Case counts by customer and SOAR status for resolved, assigned cases in
    the window. window: 24h|7d|30d|60d|90d."""
    return tools.get_status_mix(client(), *queries.bounds_for_window(window), tenant)


@mcp.tool()
def get_case_volume(window: str = "7d", tenant: str = "all") -> list[dict]:
    """Case counts broken down by customer and severity. window: 24h|7d|30d|60d|90d.
    tenant: a customer id or "all"."""
    return tools.get_case_volume(client(), *queries.bounds_for_window(window), tenant)


if __name__ == "__main__":
    mcp.run()
