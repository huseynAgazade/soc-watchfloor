"""HTTP facade for the detection connector.

Serves ATT&CK coverage + rule inventory computed from the pipeline's
_all_rules_combined.json (the export scripts from detection-attck-mapper, run
here). The export is re-run daily, at start-up when the data is over a day old,
and on demand via POST /refresh — see refresher.py. Read-only toward the SIEM/EDR.
"""
from __future__ import annotations

import datetime
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

import adapter
from refresher import Refresher

_HERE = os.path.dirname(__file__)
COMBINED = os.environ.get("DETECTION_COMBINED_JSON",
                          os.path.join(_HERE, "pipeline", "rules", "_all_rules_combined.json"))
REFRESHER = Refresher(
    os.path.join(_HERE, "pipeline"), COMBINED,
    secrets_file=os.environ.get("DETECTION_SECRETS_FILE", os.path.join(_HERE, "secrets.env")),
    at=os.environ.get("DETECTION_REFRESH_AT", "06:00"),
    tz=os.environ.get("ORG_TIMEZONE", "Asia/Dubai"),
    timeout=int(os.environ.get("DETECTION_REFRESH_TIMEOUT", "900")),
)
_cache: dict = {"rules": None, "synced_at": None}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if os.environ.get("DETECTION_REFRESH_ENABLED", "true").lower() not in ("0", "false", "no"):
        REFRESHER.start_scheduler()
    yield


app = FastAPI(title="mcp-detection HTTP facade", version="0.3.0", lifespan=lifespan)


def _synced_at() -> str | None:
    try:
        ts = os.path.getmtime(COMBINED)
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()
    except OSError:
        return None


def _rules() -> list[dict]:
    synced = _synced_at()
    if _cache["rules"] is None or _cache["synced_at"] != synced:
        if not os.path.isfile(COMBINED):
            raise HTTPException(503, "no detection export yet — run /refresh")
        _cache["rules"] = adapter.load(COMBINED)
        _cache["synced_at"] = synced
    return _cache["rules"]


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "synced_at": _synced_at()}


@app.get("/detection")
def detection(tenants: str | None = None) -> dict:
    """Coverage + inventory. Without `tenants`, every tenant; with it (comma-
    separated, possibly empty), only those tenants."""
    scope = None if tenants is None else [t for t in tenants.split(",") if t]
    d = adapter.dataset(_rules(), scope)
    d["synced_at"] = _synced_at()
    return d


@app.get("/status")
def status() -> dict:
    """When the rules were last synced, the last attempt and its outcome, and the next scheduled run."""
    return REFRESHER.status()


class RefreshIn(BaseModel):
    trigger: str = Field("manual", max_length=96)


@app.post("/refresh")
def refresh(body: RefreshIn | None = None) -> dict:
    """Start a re-export (poll Splunk + Falcon) in the background. Poll /status."""
    started = REFRESHER.start((body.trigger if body else "manual") or "manual")
    return {**REFRESHER.status(), "status": started}
