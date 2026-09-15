"""Watchfloor's own data as assistant tools.

Each tool runs as the signed-in user through the same code the dashboards use
(app/datasources/service.py, the roster and detection connectors), so a chat
answer can never see more than that user's pages show.
"""
from __future__ import annotations

import json

from ..connectors import detection as detection_conn
from ..connectors import roster as roster_conn
from ..connectors import splunk
from ..datasources import service
from ..models import User
from .. import periods

PERIOD_KEYS = ["24h", "d7", "d30", "d60", "d90", "mtd", "prev", "custom"]
_PERIOD = {
    "period": {"type": "string", "enum": PERIOD_KEYS,
               "description": "Reporting window in the org timezone (default d7). custom needs date_from and date_to."},
    "date_from": {"type": "string", "description": "YYYY-MM-DD, only with period=custom"},
    "date_to": {"type": "string", "description": "YYYY-MM-DD, only with period=custom"},
}
_TENANT = {"tenant": {"type": "string", "description": "A tenant id from watchfloor_tenants, or \"all\" (default)."}}
_ROWS = {"max_rows": {"type": "integer", "minimum": 1, "maximum": 200, "description": "Rows to return (default 50)."}}

TOOL_DEFS: dict[str, tuple[str, dict, list[str]]] = {
    "watchfloor_tenants": (
        "List the customers (tenants) the current user may see: id, name, SOAR label.", {}, []),
    "watchfloor_list_data_queries": (
        "List the Watchfloor query catalog — the exact queries behind the dashboard panels (SLA, L1 analysts, "
        "overview trends, agentic AI performance, and custom ones). Returns id, name, category, output columns and "
        "description. Run one with watchfloor_run_data_query.",
        {"category": {"type": "string", "enum": ["sla", "l1", "overview", "agentic", "custom"]}}, []),
    "watchfloor_run_data_query": (
        "Run one catalog query and get its rows, exactly as the dashboards show them. The server applies the "
        "user's tenant scope.",
        {"query_id": {"type": "string"}, **_PERIOD, **_TENANT, **_ROWS}, ["query_id"]),
    "watchfloor_run_spl": (
        "Run a read-only Splunk SPL query you write yourself, when no catalog query fits. The search job is "
        "bounded to the period. Writing commands are rejected. Tokens: $earliest$ $latest$ (epoch), $tenants$ "
        "and $tenant_labels$ (quoted lists for IN (...)), $soar_containers$ (SOAR containers created in the "
        "period), $include:sla.head$ (containers with SLA stage fields). Always show the SPL you ran to the "
        "user in a ```spl block.",
        {"spl": {"type": "string"}, **_PERIOD, **_TENANT, **_ROWS}, ["spl"]),
    "watchfloor_roster": (
        "Who is on each SOC analyst shift window (Morning 08-16, Evening 16-00, Night 00-08, org timezone) on a "
        "date, and how far the published roster runs.",
        {"date": {"type": "string", "description": "YYYY-MM-DD; default today"}}, []),
    "watchfloor_detection_coverage": (
        "MITRE ATT&CK detection coverage and rule counts for a tenant (or all tenants in scope): covered top-level "
        "techniques, phantom cells, enabled/disabled/unmapped rules and the weakest tactics.",
        {**_TENANT}, []),
}


class ToolDenied(Exception):
    def __init__(self, message: str, kind: str = "scope"):
        super().__init__(message)
        self.kind = kind


def is_watchfloor(name: str) -> bool:
    return name.startswith("watchfloor_")


def allowed_names(user: User) -> list[str]:
    return [n for n in TOOL_DEFS if n != "watchfloor_run_spl" or service.can_run_adhoc(user)]


def tools_for(user: User) -> list[dict]:
    return [{"name": n, "description": TOOL_DEFS[n][0],
             "input_schema": {"type": "object", "properties": TOOL_DEFS[n][1], "required": TOOL_DEFS[n][2]}}
            for n in allowed_names(user)]


def _period(args: dict) -> periods.Period:
    try:
        return periods.resolve(args.get("period") or "d7", args.get("date_from"), args.get("date_to"))
    except periods.PeriodError as e:
        raise ToolDenied(str(e), "args")


def _rows(args: dict) -> int:
    try:
        return max(1, min(int(args.get("max_rows") or 50), 200))
    except (TypeError, ValueError):
        return 50


def _table_preview(res: dict, extra: dict | None = None) -> dict:
    rows = res.get("rows", [])
    cols = list(rows[0].keys()) if rows else list(res.get("columns") or [])
    return {"kind": "table", "columns": cols, "rows": rows[:25], "row_count": res.get("row_count", len(rows)),
            "truncated": res.get("truncated", False), "period": res.get("period"), "tenant": res.get("tenant"),
            **(extra or {})}


async def run(user: User, name: str, args: dict) -> tuple[str, dict | None]:
    """(text for the model, structured preview for the chat UI)."""
    if name not in allowed_names(user):
        raise ToolDenied(f"'{name}' is not available to you.", "role")
    try:
        if name == "watchfloor_tenants":
            rows = [{"id": t.id, "name": t.name, "soar_label": t.label or t.id}
                    for t in await service.tenants_in_scope(user)]
            return json.dumps({"tenants": rows}), None

        if name == "watchfloor_list_data_queries":
            show_spl = service.can_run_adhoc(user)
            rows = [{"id": q.id, "name": q.name, "category": q.category, "columns": q.columns,
                     "description": q.description, **({"spl": q.spl} if show_spl else {})}
                    for q in await service.list_queries(args.get("category"))]
            return json.dumps({"queries": rows}), None

        if name == "watchfloor_run_data_query":
            n = _rows(args)
            res = await service.run_query(user, str(args.get("query_id") or ""), _period(args),
                                          args.get("tenant") or "all", n)
            body = {k: res[k] for k in ("query", "period", "tenant", "row_count", "truncated")}
            return json.dumps({**body, "rows": res["rows"][:n]}, default=str), \
                _table_preview(res, {"query": res["query"]})

        if name == "watchfloor_run_spl":
            n = _rows(args)
            spl = str(args.get("spl") or "")
            res = await service.run_adhoc(user, spl, _period(args), args.get("tenant") or "all", n)
            body = {k: res[k] for k in ("period", "tenant", "row_count", "truncated")}
            return json.dumps({**body, "rows": res["rows"][:n]}, default=str), _table_preview(res, {"spl": spl})

        if name == "watchfloor_roster":
            data = await roster_conn.roster()
            at = f"{args['date']}T12:00:00" if args.get("date") else None
            now = await roster_conn.on_shift(at)
            last = data["days"][-1]["iso"] if data.get("days") else None
            out = {"roster_month": data.get("month"), "published_through": last, "today": data.get("today"),
                   "date": now.get("date"), "current_window": now.get("current"),
                   "roster_covers_date": now.get("covered"),
                   "on_shift": {"Morning 08-16": now["windows"].get("M", []),
                                "Evening 16-00": now["windows"].get("E", []),
                                "Night 00-08": now["windows"].get("N", [])}}
            return json.dumps(out), None

        if name == "watchfloor_detection_coverage":
            scope = await service.resolve_scope(user, args.get("tenant") or "all")
            data = await detection_conn.detection(tenants=None if scope.all_tenants and scope.tenant == "all"
                                                  else scope.ids)
            key = scope.tenant if scope.tenant != "all" else "all"
            summary = (data.get("summary") or {}).get(key)
            if summary is None:
                return json.dumps({"tenant": key, "note": "this tenant is not in the detection pipeline"}), None
            weakest = sorted((data.get("tactics") or {}).get(key, []), key=lambda t: t["pct"])[:5]
            return json.dumps({"tenant": key, "summary": summary, "synced_at": data.get("synced_at"),
                               "weakest_tactics": [{k: t[k] for k in ("name", "code", "cov", "tot", "pct", "rules")}
                                                   for t in weakest]}), None
    except service.ScopeDenied as e:
        raise ToolDenied(str(e), "scope")
    except service.QueryError as e:
        raise ToolDenied(str(e), "args")
    except (splunk.ConnectorError, roster_conn.RosterError, detection_conn.DetectionError) as e:
        raise ToolDenied(f"data source unavailable: {e}", "exec")
    raise ToolDenied(f"'{name}' is not implemented.", "role")
