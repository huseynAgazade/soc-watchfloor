"""Client for the mcp-soar HTTP facade.

The core calls the SAME connector the assistant uses (one tool layer). Tenant
scope is applied here from the caller's session, never trusted from the browser.
If the connector is unreachable, callers get a clear error and the UI keeps its
last snapshot rather than blanking.
"""
from __future__ import annotations

import os

import httpx

BASE = os.environ.get("MCP_SOAR_URL", "http://mcp-soar:9000").rstrip("/")
_TIMEOUT = float(os.environ.get("MCP_SOAR_TIMEOUT", "60"))


class ConnectorError(RuntimeError):
    pass


async def _get(path: str, params: dict) -> list[dict]:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{BASE}{path}", params=params)
    except httpx.HTTPError as e:
        raise ConnectorError(f"mcp-soar unreachable: {e}") from e
    if r.status_code != 200:
        raise ConnectorError(f"mcp-soar {path} -> HTTP {r.status_code}: {r.text[:160]}")
    return r.json().get("rows", [])


async def sla_by_customer(window: str, tenant: str) -> list[dict]:
    return await _get("/sla", {"window": window, "tenant": tenant})


async def analyst_performance(window: str) -> list[dict]:
    return await _get("/analysts", {"window": window})


async def status_mix(window: str) -> list[dict]:
    return await _get("/status_mix", {"window": window})


async def case_volume(window: str, tenant: str) -> list[dict]:
    return await _get("/case_volume", {"window": window, "tenant": tenant})
