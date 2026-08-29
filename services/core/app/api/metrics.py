"""Live metric endpoints for the dashboards — auth-required and tenant-scoped.

The browser never talks to Splunk/SOAR. It calls these endpoints; the core
resolves the caller's tenant scope from the session (server-side) and fetches
from the mcp-soar connector. The response is shaped for the front-end so the SLA
and L1 pages can render live data in place of their embedded snapshots.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ..connectors import detection as detection_conn
from ..connectors import roster as roster_conn
from ..connectors import soar
from ..deps import active_user, all_tenants, current_user
from ..models import User

router = APIRouter()

_ALLOWED_WINDOWS = {"24h", "7d", "30d", "60d"}


def _scope_ids(user: User) -> list[str] | None:
    """None == all tenants; else the caller's fixed allow-list."""
    return None if all_tenants(user) else (user.allowed_customer_ids or [])


def _window(w: str) -> str:
    return w if w in _ALLOWED_WINDOWS else "7d"


@router.get("/sla")
async def sla(user: User = Depends(active_user), window: str = Query("7d")):
    ids = _scope_ids(user)
    try:
        rows = await soar.sla_by_customer(_window(window), "all")
    except soar.ConnectorError as e:
        raise HTTPException(503, str(e))
    if ids is not None:  # enforce scope server-side, over whatever the connector returned
        rows = [r for r in rows if r.get("customer") in ids]
    return {"window": _window(window), "scope": "all" if ids is None else ids, "rows": rows}


@router.get("/l1")
async def l1(user: User = Depends(active_user), window: str = Query("30d")):
    # L1 performance is per-analyst; visible to shift leads and above only.
    from ..deps import user_capabilities
    from ..rbac import Capability
    caps = user_capabilities(user)
    if Capability.view_team_performance not in caps:
        raise HTTPException(403, "requires view_team_performance")
    try:
        rows = await soar.analyst_performance(_window(window))
    except soar.ConnectorError as e:
        raise HTTPException(503, str(e))
    return {"window": _window(window), "rows": rows}


@router.get("/status-mix")
async def status_mix(user: User = Depends(active_user), window: str = Query("7d")):
    try:
        rows = await soar.status_mix(_window(window))
    except soar.ConnectorError as e:
        raise HTTPException(503, str(e))
    return {"window": _window(window), "rows": rows}


@router.get("/case-volume")
async def case_volume(user: User = Depends(active_user), window: str = Query("7d")):
    ids = _scope_ids(user)
    try:
        rows = await soar.case_volume(_window(window), "all")
    except soar.ConnectorError as e:
        raise HTTPException(503, str(e))
    if ids is not None:
        rows = [r for r in rows if r.get("customer") in ids]
    return {"window": _window(window), "rows": rows}


@router.get("/roster")
async def roster(user: User = Depends(active_user)):
    """Live analyst monthly roster (SOAR list 43). Visible to any authenticated user."""
    try:
        return await roster_conn.roster()
    except roster_conn.RosterError as e:
        raise HTTPException(503, str(e))


@router.get("/on-shift")
async def on_shift(user: User = Depends(active_user), at: str | None = None):
    """Who is on each analyst window now (or at ISO datetime `at`)."""
    try:
        return await roster_conn.on_shift(at)
    except roster_conn.RosterError as e:
        raise HTTPException(503, str(e))


@router.get("/detection")
async def detection(user: User = Depends(active_user)):
    """ATT&CK coverage + rule inventory (MSSP-internal detection posture)."""
    try:
        return await detection_conn.detection()
    except detection_conn.DetectionError as e:
        raise HTTPException(503, str(e))
