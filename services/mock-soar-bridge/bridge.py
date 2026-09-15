"""Mock SOAR tool bridge for the PUBLIC DEMO — serves synthetic container data
so the assistant is fully live (real Claude) over fake, safe tenants. It speaks
the same /tools + /call contract as the real splunk-soar-mcp bridge, so the
core's authorization proxy runs unchanged. No real SOAR, no secrets."""
from __future__ import annotations
from fastapi import FastAPI
from pydantic import BaseModel
import json

app = FastAPI(title="mock-soar-bridge (demo)")

_S = {"type": "object", "properties": {}}
def _c(**props): return {"type": "object", "properties": props}

TOOLS = [
    {"name": "soar_system_info", "description": "SOAR system version and status.", "input_schema": _S},
    {"name": "soar_list_container_statuses", "description": "Valid container statuses.", "input_schema": _S},
    {"name": "soar_list_severities", "description": "Valid severities.", "input_schema": _S},
    {"name": "soar_list_containers", "description": "List cases/containers; filter by customer label.",
     "input_schema": _c(label={"type": "string"}, page_size={"type": "integer"})},
    {"name": "soar_get_container", "description": "Get one container by id.",
     "input_schema": _c(container_id={"type": "integer"})},
    {"name": "soar_list_artifacts", "description": "Artifacts on a container.",
     "input_schema": _c(container_id={"type": "integer"})},
    {"name": "soar_list_notes", "description": "Notes on a container.",
     "input_schema": _c(container_id={"type": "integer"})},
    {"name": "soar_list_playbooks", "description": "Available playbooks.", "input_schema": _S},
]

# synthetic, safe tenants
C = [
    {"id": 5007, "name": "WebShield WAF — SQLi attempt blocked", "label": "acme_corp",   "status": "new",        "severity": "high",   "create_time": "2026-08-29T08:41:00Z"},
    {"id": 5006, "name": "WebShield WAF — XSS probe",            "label": "acme_corp",   "status": "open",       "severity": "medium", "create_time": "2026-08-29T08:12:00Z"},
    {"id": 5005, "name": "CrowdStrike — suspicious PowerShell",  "label": "initech",     "status": "in_progress","severity": "high",   "create_time": "2026-08-29T07:55:00Z"},
    {"id": 5004, "name": "Phishing report — credential lure",   "label": "initech",     "status": "new",        "severity": "medium", "create_time": "2026-08-29T07:20:00Z"},
    {"id": 5003, "name": "Impossible travel — VPN + Dubai",      "label": "umbrella_co", "status": "resolved",   "severity": "low",    "create_time": "2026-08-28T22:03:00Z"},
    {"id": 5002, "name": "Multiple failed logins — brute force","label": "globex_co",   "status": "open",       "severity": "medium", "create_time": "2026-08-28T19:31:00Z"},
    {"id": 5001, "name": "Sysmon — scheduled task created",     "label": "hooli_media", "status": "closed",     "severity": "low",    "create_time": "2026-08-28T14:10:00Z"},
]

class CallIn(BaseModel):
    name: str
    arguments: dict = {}

@app.get("/health")
def health(): return {"status": "ok", "mock": True}

@app.get("/tools")
def tools(): return {"tools": TOOLS}

@app.post("/call")
def call(body: CallIn):
    n, a = body.name, body.arguments or {}
    if n == "soar_system_info":
        return _ok({"product": "Splunk SOAR (demo)", "version": "6.2.1", "status": "healthy"})
    if n == "soar_list_container_statuses":
        return _ok(["new", "open", "in_progress", "resolved", "closed"])
    if n == "soar_list_severities":
        return _ok(["low", "medium", "high", "critical"])
    if n == "soar_list_containers":
        rows = C
        lab = a.get("label")
        if lab:
            def norm(s): return "".join(ch if ch.isalnum() else "_" for ch in str(s).lower()).strip("_")
            q = norm(lab)
            rows = [c for c in rows if q in norm(c["label"]) or norm(c["label"]) in q
                    or q in norm(c["name"])]
        rows = rows[: int(a.get("page_size") or 10)]
        return _ok({"count": len(rows), "containers": rows})
    if n == "soar_get_container":
        cid = a.get("container_id") or a.get("container") or a.get("id")
        for c in C:
            if c["id"] == cid: return _ok(c)
        return _ok({"error": f"no container {cid}"})
    if n == "soar_list_artifacts":
        return _ok({"container_id": a.get("container_id"), "artifacts": [
            {"id": 1, "name": "sourceAddress", "cef": {"sourceAddress": "203.0.113.44"}},
            {"id": 2, "name": "requestURL", "cef": {"requestURL": "/login?id=1' OR '1'='1"}}]})
    if n == "soar_list_notes":
        return _ok({"container_id": a.get("container_id"), "notes": [
            {"author": "analyst1", "content": "Triaged; WAF blocked. Monitoring source IP."}]})
    if n == "soar_list_playbooks":
        return _ok(["waf_enrich_block", "phishing_triage", "edr_isolate_host"])
    return {"ok": False, "is_error": True, "text": f"mock: unknown tool {n}"}

def _ok(obj): return {"ok": True, "is_error": False, "text": json.dumps(obj, indent=2)}
