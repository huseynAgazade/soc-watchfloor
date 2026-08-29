"""HTTP facade over the SOAR/SLA tools.

The same tool functions the MCP server exposes to the model, also reachable over
HTTP so the core service can fetch them for the dashboards — one connector, two
consumers (model via MCP, dashboards via HTTP). Read-only. The core applies auth
and tenant scope before/after calling here; this service itself is internal.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException

import tools
from splunk_client import SplunkClient, SplunkError

app = FastAPI(title="mcp-soar HTTP facade", version="0.1.0")

_client: SplunkClient | None = None


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
def sla(window: str = "7d", tenant: str = "all"):
    return _guard(lambda: tools.get_sla_by_customer(client(), window, tenant))


@app.get("/analysts")
def analysts(window: str = "30d"):
    return _guard(lambda: tools.get_analyst_performance(client(), window))


@app.get("/status_mix")
def status_mix(window: str = "7d"):
    return _guard(lambda: tools.get_status_mix(client(), window))


@app.get("/case_volume")
def case_volume(window: str = "7d", tenant: str = "all"):
    return _guard(lambda: tools.get_case_volume(client(), window, tenant))
