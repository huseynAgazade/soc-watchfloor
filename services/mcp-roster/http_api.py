"""HTTP facade for the roster connector — read the SOAR monthly_shift_roster and
serve it to the core (and, later, the assistant via MCP). Read-only."""
from __future__ import annotations

import datetime
import os

from fastapi import FastAPI, HTTPException

import roster as roster_mod
from soar_client import SoarClient, SoarError

app = FastAPI(title="mcp-roster HTTP facade", version="0.1.0")

LIST_ID = os.environ.get("ROSTER_LIST_ID", "43")
_client: SoarClient | None = None
_cache: dict = {"at": None, "roster": None}


def _client_get() -> SoarClient:
    global _client
    if _client is None:
        _client = SoarClient()
    return _client


def _roster() -> dict:
    # short cache so the page can refresh without hammering SOAR
    now = datetime.datetime.now(datetime.timezone.utc)
    if _cache["roster"] and _cache["at"] and (now - _cache["at"]).total_seconds() < 60:
        return _cache["roster"]
    try:
        content = _client_get().decided_list(LIST_ID)
    except SoarError as e:
        raise HTTPException(502, f"soar: {e}")
    parsed = roster_mod.parse(content)
    _cache["roster"], _cache["at"] = parsed, now
    return parsed


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/roster")
def roster():
    """The analyst monthly roster: days + per-person shift codes."""
    return _roster()


@app.get("/on-shift")
def on_shift(at: str | None = None):
    """Who is on each window right now (or at an ISO datetime `at`)."""
    when = datetime.datetime.fromisoformat(at) if at else datetime.datetime.now()
    return roster_mod.on_shift(_roster(), when)
