"""Client for the mcp-roster HTTP facade (live analyst roster from SOAR)."""
from __future__ import annotations

import os

import httpx

BASE = os.environ.get("MCP_ROSTER_URL", "http://mcp-roster:9000").rstrip("/")
_TIMEOUT = float(os.environ.get("MCP_ROSTER_TIMEOUT", "30"))


class RosterError(RuntimeError):
    pass


async def _get(path: str, params: dict | None = None) -> dict:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{BASE}{path}", params=params or {})
    except httpx.HTTPError as e:
        raise RosterError(f"mcp-roster unreachable: {e}") from e
    if r.status_code != 200:
        raise RosterError(f"mcp-roster {path} -> HTTP {r.status_code}: {r.text[:160]}")
    return r.json()


async def roster() -> dict:
    return await _get("/roster")


async def on_shift(at: str | None = None) -> dict:
    return await _get("/on-shift", {"at": at} if at else None)
