"""Client for the mcp-detection HTTP facade (ATT&CK coverage + rule inventory)."""
from __future__ import annotations

import os

import httpx

BASE = os.environ.get("MCP_DETECTION_URL", "http://mcp-detection:9000").rstrip("/")
_TIMEOUT = float(os.environ.get("MCP_DETECTION_TIMEOUT", "30"))


class DetectionError(RuntimeError):
    pass


async def detection() -> dict:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{BASE}/detection")
    except httpx.HTTPError as e:
        raise DetectionError(f"mcp-detection unreachable: {e}") from e
    if r.status_code != 200:
        raise DetectionError(f"mcp-detection -> HTTP {r.status_code}: {r.text[:160]}")
    return r.json()


async def refresh() -> dict:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.post(f"{BASE}/refresh")
        return r.json()
    except httpx.HTTPError as e:
        raise DetectionError(f"mcp-detection unreachable: {e}") from e
