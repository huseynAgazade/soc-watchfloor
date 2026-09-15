"""HTTP facade for the roster connector — read the SOAR monthly_shift_roster and
serve it to the core (and, later, the assistant via MCP). Read-only.

"Now" and "today" are the org timezone's (ORG_TIMEZONE, default Asia/Dubai), never
the server clock's — the shift windows are defined in local time."""
from __future__ import annotations

import datetime
import os
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException

import roster as roster_mod
from soar_client import SoarClient, SoarError

app = FastAPI(title="mcp-roster HTTP facade", version="0.2.0")

LIST_NAME = os.environ.get("ROSTER_LIST_NAME", "monthly_shift_roster")
LIST_ID = os.environ.get("ROSTER_LIST_ID", "")      # optional pin; the list must still carry LIST_NAME
TZ = ZoneInfo(os.environ.get("ORG_TIMEZONE", "Asia/Dubai"))
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
        c = _client_get()
        record = c.decided_list(LIST_ID) if LIST_ID else c.decided_list_by_name(LIST_NAME)
        if record.get("name") != LIST_NAME:
            raise SoarError(f"list {record.get('id')} is {record.get('name')!r}, not {LIST_NAME!r}")
    except SoarError as e:
        raise HTTPException(502, f"soar: {e}")
    parsed = {**roster_mod.parse(record.get("content") or []),
              "list": {"id": record.get("id"), "name": record.get("name")}}
    _cache["roster"], _cache["at"] = parsed, now
    return parsed


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/roster")
def roster():
    """The analyst monthly roster: days + per-person shift codes, plus the org's
    current date and hour so the page never guesses from the browser clock."""
    now = datetime.datetime.now(TZ)
    return {**_roster(), "today": now.date().isoformat(), "hour": now.hour, "timezone": TZ.key}


@app.get("/on-shift")
def on_shift(at: str | None = None):
    """Who is on each window right now (or at ISO datetime `at`; a value without
    an offset is read as org-local time)."""
    if at:
        try:
            when = datetime.datetime.fromisoformat(at)
        except ValueError:
            raise HTTPException(422, "at must be an ISO datetime")
        when = when.replace(tzinfo=TZ) if when.tzinfo is None else when.astimezone(TZ)
    else:
        when = datetime.datetime.now(TZ)
    return {**roster_mod.on_shift(_roster(), when), "timezone": TZ.key}
