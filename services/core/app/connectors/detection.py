"""Client for the mcp-detection HTTP facade (ATT&CK coverage + rule inventory)."""
from __future__ import annotations

import os

import httpx

BASE = os.environ.get("MCP_DETECTION_URL", "http://mcp-detection:9000").rstrip("/")
_TIMEOUT = float(os.environ.get("MCP_DETECTION_TIMEOUT", "30"))


class DetectionError(RuntimeError):
    pass


async def detection(tenants: list[str] | None = None) -> dict:
    """tenants=None → every tenant; a list (possibly empty) → only those tenants.
    The connector computes coverage over that subset, so nothing outside it is
    ever returned."""
    params = None if tenants is None else {"tenants": ",".join(tenants)}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{BASE}/detection", params=params)
    except httpx.HTTPError as e:
        raise DetectionError(f"mcp-detection unreachable: {e}") from e
    if r.status_code != 200:
        raise DetectionError(f"mcp-detection -> HTTP {r.status_code}: {r.text[:160]}")
    return r.json()


async def status() -> dict:
    """Last sync, last attempt and outcome, next scheduled run."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{BASE}/status")
    except httpx.HTTPError as e:
        raise DetectionError(f"mcp-detection unreachable: {e}") from e
    if r.status_code != 200:
        raise DetectionError(f"mcp-detection -> HTTP {r.status_code}: {r.text[:160]}")
    return r.json()


async def refresh(trigger: str) -> dict:
    """Start a re-export in the background; returns the status with "status": started | already-running."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.post(f"{BASE}/refresh", json={"trigger": trigger[:96]})
    except httpx.HTTPError as e:
        raise DetectionError(f"mcp-detection unreachable: {e}") from e
    if r.status_code != 200:
        raise DetectionError(f"mcp-detection -> HTTP {r.status_code}: {r.text[:160]}")
    return r.json()
