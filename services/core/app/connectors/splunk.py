"""Client for the Splunk search endpoint of the mcp-soar facade.

The core renders catalog SPL (tokens filled, scope applied) and sends it here;
the facade runs it on the Splunk search head with the job bounded to the window.
"""
from __future__ import annotations

import os
from datetime import datetime

import httpx

BASE = os.environ.get("MCP_SOAR_URL", "http://mcp-soar:9000").rstrip("/")
# long SOAR windows are fetched in slices, so a 90-day query can take a minute
_TIMEOUT = float(os.environ.get("MCP_SOAR_TIMEOUT", "180"))


class ConnectorError(RuntimeError):
    pass


async def search(spl: str, start: datetime, end: datetime, max_rows: int) -> tuple[list[dict], bool]:
    """Rows and whether the result was cut at max_rows."""
    body = {"spl": spl, "earliest": start.timestamp(), "latest": end.timestamp(), "max_rows": max_rows}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.post(f"{BASE}/search", json=body)
    except httpx.HTTPError as e:
        raise ConnectorError(f"splunk connector unreachable: {e}") from e
    if r.status_code != 200:
        detail = r.text[:300]
        try:
            detail = r.json().get("detail", detail)
        except ValueError:
            pass
        raise ConnectorError(f"splunk search failed (HTTP {r.status_code}): {detail}")
    d = r.json()
    return d.get("rows", []), bool(d.get("truncated"))
