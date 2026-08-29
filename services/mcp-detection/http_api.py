"""HTTP facade for the detection connector.

Serves ATT&CK coverage + rule inventory computed from the pipeline's
_all_rules_combined.json (the team's export scripts, now run here). /refresh re-runs
the export (poll Splunk + Falcon) and rebuilds — that is the on-demand path; a
scheduler does the same on a cadence. Read-only toward the SIEM/EDR.
"""
from __future__ import annotations

import datetime
import os
import subprocess
import sys
import threading

from fastapi import FastAPI, HTTPException

import adapter

app = FastAPI(title="mcp-detection HTTP facade", version="0.1.0")

_HERE = os.path.dirname(__file__)
COMBINED = os.environ.get("DETECTION_COMBINED_JSON",
                          os.path.join(_HERE, "pipeline", "rules", "_all_rules_combined.json"))
_cache: dict = {"data": None, "built_at": None, "synced_at": None}
_refresh_lock = threading.Lock()


def _synced_at() -> str | None:
    try:
        ts = os.path.getmtime(COMBINED)
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()
    except OSError:
        return None


def _data() -> dict:
    synced = _synced_at()
    if _cache["data"] is None or _cache["synced_at"] != synced:
        if not os.path.isfile(COMBINED):
            raise HTTPException(503, "no detection export yet — run /refresh")
        _cache["data"] = adapter.build(COMBINED)
        _cache["synced_at"] = synced
    return _cache["data"]


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "synced_at": _synced_at()}


@app.get("/detection")
def detection() -> dict:
    d = dict(_data())
    d["synced_at"] = _synced_at()
    return d


def _run_export() -> None:
    pipe = os.path.join(_HERE, "pipeline")
    subprocess.run([sys.executable, "automatic.py", "--config", "customers.yaml",
                    "--combined-output", "rules/_all_rules_combined.json"],
                   cwd=pipe, check=False)


@app.post("/refresh")
def refresh() -> dict:
    """Kick off a re-export (poll Splunk + Falcon) in the background. The dataset
    updates once it finishes; poll /health synced_at to see the new timestamp."""
    if not _refresh_lock.acquire(blocking=False):
        return {"status": "already-running"}

    def _job():
        try:
            _run_export()
        finally:
            _refresh_lock.release()

    threading.Thread(target=_job, daemon=True).start()
    return {"status": "started", "was_synced_at": _synced_at()}
