"""First-party usage statistics.

The portal reports a page view (POST /api/usage) only when the viewer allowed
usage statistics in the cookie banner. Stored as daily counts per page and role —
never who, never from where. Nothing is sent to a third party. Administrators
read the totals at GET /admin/usage.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from ..config import settings
from ..db import SessionLocal
from ..deps import active_user, require_capability
from ..models import UsageCount, User
from ..rbac import Capability

router = APIRouter()
admin_router = APIRouter()

VIEWS = frozenset({"overview", "analysts", "engineers", "sla", "l1", "mitre", "rules", "agentic", "chat",
                   "admin", "settings"})
KEEP_DAYS = 400


class ViewIn(BaseModel):
    view: str = Field(max_length=32)


def _today():
    return datetime.now(ZoneInfo(settings.org_timezone)).date()


@router.post("/usage", status_code=204)
async def record_view(body: ViewIn, user: User = Depends(active_user)) -> Response:
    if not settings.analytics_enabled:
        return Response(status_code=204)
    if body.view not in VIEWS:
        raise HTTPException(422, "unknown page")
    day = _today().isoformat()
    for _ in range(2):   # a concurrent first view of the day may win the insert; then update
        async with SessionLocal() as db:
            row = (await db.execute(select(UsageCount).where(UsageCount.day == day, UsageCount.view == body.view,
                                                             UsageCount.role == user.role))).scalar_one_or_none()
            if row:
                row.count += 1
            else:
                db.add(UsageCount(day=day, view=body.view, role=user.role, count=1))
            try:
                await db.commit()
                break
            except IntegrityError:
                await db.rollback()
    return Response(status_code=204)


@admin_router.get("")
async def usage_report(days: int = Query(30, ge=1, le=365),
                       user: User = Depends(require_capability(Capability.manage_users))) -> dict:
    today = _today()
    since = (today - timedelta(days=days - 1)).isoformat()
    async with SessionLocal() as db:
        await db.execute(delete(UsageCount).where(UsageCount.day < (today - timedelta(days=KEEP_DAYS)).isoformat()))
        await db.commit()
        rows = (await db.execute(select(UsageCount).where(UsageCount.day >= since))).scalars().all()
    views: dict[str, int] = {}
    roles: dict[str, int] = {}
    daily: dict[str, int] = {}
    for r in rows:
        views[r.view] = views.get(r.view, 0) + r.count
        roles[r.role] = roles.get(r.role, 0) + r.count
        daily[r.day] = daily.get(r.day, 0) + r.count
    by_count = lambda d, key: [{key: k, "count": v} for k, v in sorted(d.items(), key=lambda x: -x[1])]
    return {"days": days, "since": since, "total": sum(views.values()), "views": by_count(views, "view"),
            "roles": by_count(roles, "role"), "daily": [{"day": k, "count": daily[k]} for k in sorted(daily)]}
