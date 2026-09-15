"""Read access to the audit trail (managers). Newest first; optionally filtered
by kind prefix (e.g. `chat.`, `scope.denied`, `login.`) or actor."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import require_capability
from ..models import AuditEvent, User
from ..rbac import Capability

router = APIRouter()
_admin = require_capability(Capability.manage_users)


@router.get("")
async def list_audit(admin: User = Depends(_admin), db: AsyncSession = Depends(get_db),
                     limit: int = Query(200, ge=1, le=1000),
                     kind: str | None = Query(None, max_length=48),
                     actor: str | None = Query(None, max_length=64)) -> list[dict]:
    q = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)
    if kind:
        q = q.where(AuditEvent.kind.startswith(kind, autoescape=True))
    if actor:
        q = q.where(AuditEvent.actor == actor)
    rows = (await db.execute(q)).scalars().all()
    return [{"id": r.id, "kind": r.kind, "detail": r.detail, "actor": r.actor,
             "at": r.at.isoformat() if r.at else None} for r in rows]
