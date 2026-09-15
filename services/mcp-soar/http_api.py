"""HTTP facade over the SOAR/SLA tools.

The same tool functions the MCP server exposes to the model, also reachable over
HTTP so the core service can fetch them for the dashboards — one connector, two
consumers (model via MCP, dashboards via HTTP). Read-only. The core applies auth
and tenant scope before/after calling here; this service itself is internal.

Every endpoint takes `start` and `end` as ISO-8601 UTC timestamps (the core
resolves periods); `window` (24h|7d|30d|60d|90d) is accepted when they are absent.
"""
from __future__ import annotations

import os
import re
import threading
import time
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import queries
import tools
from splunk_client import SplunkClient, SplunkError

app = FastAPI(title="mcp-soar HTTP facade", version="0.2.0")

_client: SplunkClient | None = None

# A long window costs dozens of restsoar calls, and the dashboards ask for it on
# every page load, so results for the same window are reused for a few minutes.
# Windows ending "now" share a cache entry within one CACHE_SECONDS bucket.
CACHE_SECONDS = int(os.environ.get("SOAR_CACHE_SECONDS", "300"))
_cache: dict = {}
_cache_lock = threading.Lock()


def _cached(name: str, s: datetime, e: datetime, extra: str, fn):
    if CACHE_SECONDS <= 0:
        return fn()
    key = (name, s.isoformat(), int(e.timestamp()) // CACHE_SECONDS, extra)
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < CACHE_SECONDS:
            return hit[1]
    rows = fn()                      # errors propagate and are never cached
    with _cache_lock:
        for k in [k for k, v in _cache.items() if now - v[0] >= CACHE_SECONDS]:
            del _cache[k]
        _cache[key] = (now, rows)
    return rows


def client() -> SplunkClient:
    global _client
    if _client is None:
        c = SplunkClient()
        c.login()
        _client = c
    return _client


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


# Writing commands are refused here too, as a second check behind the core's
# catalog validation (app/datasources/spl.py).
_BLOCKED = re.compile(r"(?:\A|\|)\s*(delete|collect|outputlookup|outputcsv|outputtext|tscollect|sendemail|"
                      r"sendalert|sendresults|script|run|runshellscript|mcollect|meventcollect|dbxoutput)\b", re.I)


class SearchIn(BaseModel):
    spl: str
    earliest: float | None = None
    latest: float | None = None
    max_rows: int = 5000


@app.post("/search")
def search(body: SearchIn) -> dict:
    """Run SPL the core has already rendered and scoped, bounded to [earliest, latest)."""
    m = _BLOCKED.search(body.spl)
    if m:
        raise HTTPException(422, f"writing command not allowed: {m.group(1)}")
    spl = body.spl.strip()
    if not spl.startswith("|"):
        spl = "search " + spl
    limit = max(1, min(body.max_rows, 50000))
    try:
        rows = client().oneshot(spl, body.earliest, body.latest, count=limit)
    except SplunkError as e:
        raise HTTPException(502, f"splunk: {e}")
    except Exception as e:  # noqa: BLE001
        global _client
        _client = None
        raise HTTPException(502, f"connector error: {e}")
    return {"rows": rows[:limit], "truncated": len(rows) >= limit}


def _bounds(start: str | None, end: str | None, window: str | None) -> tuple[datetime, datetime]:
    try:
        if start or end:
            s, e = datetime.fromisoformat(start or ""), datetime.fromisoformat(end or "")
            s = s if s.tzinfo else s.replace(tzinfo=timezone.utc)
            e = e if e.tzinfo else e.replace(tzinfo=timezone.utc)
        else:
            s, e = queries.bounds_for_window(window or "7d")
        queries.check_bounds(s, e)
    except ValueError as err:
        raise HTTPException(422, f"bad window: {err}")
    return s, e


def _guard(fn):
    try:
        return {"rows": fn()}
    except SplunkError as e:
        raise HTTPException(502, f"splunk: {e}")
    except Exception as e:  # noqa: BLE001
        # a dropped session — drop the client so the next call re-authenticates
        global _client
        _client = None
        raise HTTPException(502, f"connector error: {e}")


@app.get("/sla")
def sla(start: str | None = None, end: str | None = None, window: str | None = None, tenant: str = "all"):
    s, e = _bounds(start, end, window)
    return _guard(lambda: _cached("sla", s, e, tenant, lambda: tools.get_sla_by_customer(client(), s, e, tenant)))


@app.get("/analysts")
def analysts(start: str | None = None, end: str | None = None, window: str | None = None):
    s, e = _bounds(start, end, window or "30d")
    return _guard(lambda: _cached("analysts", s, e, "", lambda: tools.get_analyst_performance(client(), s, e)))


@app.get("/status_mix")
def status_mix(start: str | None = None, end: str | None = None, window: str | None = None, tenant: str = "all"):
    s, e = _bounds(start, end, window)
    return _guard(lambda: _cached("status_mix", s, e, tenant, lambda: tools.get_status_mix(client(), s, e, tenant)))


@app.get("/case_volume")
def case_volume(start: str | None = None, end: str | None = None, window: str | None = None, tenant: str = "all"):
    s, e = _bounds(start, end, window)
    return _guard(lambda: _cached("case_volume", s, e, tenant, lambda: tools.get_case_volume(client(), s, e, tenant)))
