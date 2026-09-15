"""Dashboard endpoints — auth-required and tenant-scoped.

SLA, L1, case outcomes and case volume run catalog queries (app/datasources) for
the selected period and tenant; the query text is editable in Data sources. The
roster and detection endpoints read their connectors directly.

Parameters: `period` (d7|d30|d60|d90|mtd|prev|24h|custom with `from`/`to`),
`tenant` (a tenant id in the caller's scope, or all).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select

from .. import audit, periods
from ..db import SessionLocal
from ..connectors import detection as detection_conn
from ..connectors import roster as roster_conn
from ..datasources import service
from ..deps import active_user, all_tenants, require_capability, user_capabilities
from ..models import User
from ..rbac import Capability
from .common import guard, period_param

router = APIRouter()


@router.get("/sla")
async def sla(user: User = Depends(active_user), p: periods.Period = Depends(period_param("d7")),
              tenant: str = Query("all")):
    res = await guard(service.run_query(user, "sla.by_customer", p, tenant))
    return {"period": res["period"], "tenant": res["tenant"], "rows": res["rows"],
            "scope": "all" if all_tenants(user) else (user.allowed_customer_ids or [])}


@router.get("/l1")
async def l1(user: User = Depends(active_user), p: periods.Period = Depends(period_param("d30")),
             tenant: str = Query("all")):
    # L1 performance is per-analyst; visible to shift leads and above only.
    if Capability.view_team_performance not in user_capabilities(user):
        raise HTTPException(403, "requires view_team_performance")
    res = await guard(service.run_query(user, "l1.by_analyst", p, tenant))
    return {"period": res["period"], "tenant": res["tenant"], "rows": res["rows"]}


@router.get("/status-mix")
async def status_mix(user: User = Depends(active_user), p: periods.Period = Depends(period_param("d7")),
                     tenant: str = Query("all")):
    res = await guard(service.run_query(user, "sla.status_mix", p, tenant))
    counts: dict[str, int] = {}
    for r in res["rows"]:
        counts[str(r.get("status", ""))] = counts.get(str(r.get("status", "")), 0) + int(r.get("count") or 0)
    total = sum(counts.values())
    out = [{"status": s, "count": c, "pct": round(100 * c / total, 1) if total else 0.0}
           for s, c in sorted(counts.items(), key=lambda kv: -kv[1])]
    return {"period": res["period"], "tenant": res["tenant"], "rows": out}


@router.get("/case-volume")
async def case_volume(user: User = Depends(active_user), p: periods.Period = Depends(period_param("d7")),
                      tenant: str = Query("all")):
    res = await guard(service.run_query(user, "sla.case_volume", p, tenant))
    return {"period": res["period"], "tenant": res["tenant"], "rows": res["rows"]}


@router.get("/roster")
async def roster(user: User = Depends(active_user)):
    """Live analyst monthly roster (SOAR list monthly_shift_roster). Visible to any
    authenticated user. `coverage` says which tenants each rostered person covers
    ("all", or tenant ids — only ids inside the caller's own scope are shown), so
    the page can narrow the rota to one tenant."""
    try:
        data = await roster_conn.roster()
    except roster_conn.RosterError as e:
        raise HTTPException(503, str(e))
    names = [p.get("u") for p in data.get("people", []) if p.get("u")]
    visible = {t.id for t in await service.tenants_in_scope(user)}
    async with SessionLocal() as db:
        people = (await db.execute(select(User).where(User.username.in_(names)))).scalars().all()
    data["coverage"] = {u.username: ("all" if all_tenants(u) else sorted(set(u.allowed_customer_ids or []) & visible))
                        for u in people}
    return data


@router.get("/on-shift")
async def on_shift(user: User = Depends(active_user), at: str | None = None):
    """Who is on each analyst window now (or at ISO datetime `at`, org timezone
    when no offset is given)."""
    try:
        return await roster_conn.on_shift(at)
    except roster_conn.RosterError as e:
        raise HTTPException(503, str(e))


_STATUS_PUBLIC = ("synced_at", "running", "running_since", "last_attempt_at", "last_success_at", "ok",
                  "next_run_at", "schedule", "duration_s")


@router.get("/detection/status")
async def detection_status(user: User = Depends(active_user)) -> dict:
    """When the detection rules were last synced and when they refresh next.
    The failure text, the trigger and per-customer rule counts go only to users
    who may refresh (they can name customers)."""
    try:
        s = await detection_conn.status()
    except detection_conn.DetectionError as e:
        raise HTTPException(503, str(e))
    can = Capability.edit_detection in user_capabilities(user)
    out = {k: s.get(k) for k in _STATUS_PUBLIC}
    out["can_refresh"] = can
    if can:
        out.update(error=s.get("error"), last_attempt_trigger=s.get("last_attempt_trigger"),
                   running_trigger=s.get("running_trigger"))
        if all_tenants(user):
            out["rules"] = s.get("rules")
    return out


@router.post("/detection/refresh")
async def detection_refresh(user: User = Depends(require_capability(Capability.edit_detection))) -> dict:
    """Re-run the detection export now (Splunk + Falcon, no LLM). Runs in the background."""
    try:
        s = await detection_conn.refresh(f"manual:{user.username}")
    except detection_conn.DetectionError as e:
        raise HTTPException(503, str(e))
    await audit.record("detection.refresh", s.get("status", ""), user.username)
    return {"status": s.get("status"), "running": s.get("running"), "running_since": s.get("running_since")}


@router.get("/detection")
async def detection(user: User = Depends(active_user)):
    """ATT&CK coverage + rule inventory, computed over the caller's tenants only."""
    try:
        return await detection_conn.detection(
            tenants=None if all_tenants(user) else (user.allowed_customer_ids or []))
    except detection_conn.DetectionError as e:
        raise HTTPException(503, str(e))
