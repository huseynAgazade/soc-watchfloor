"""Admin tenant management — create, list, update and archive customers.

Gated by the manage_tenants capability (managers). Tenants are rows: the toolbar
selector, the SLA page, and every user's scope list read from this table, so
adding a customer once makes it appear everywhere with no deployment.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import active_user, all_tenants, require_capability
from ..models import AuditEvent, Tenant, User
from ..rbac import Capability
from ..schemas import TenantCreateIn, TenantOut, TenantUpdateIn

router = APIRouter()
_admin = require_capability(Capability.manage_tenants)


def _out(t: Tenant) -> TenantOut:
    return TenantOut(id=t.id, name=t.name, label=t.label, contact=t.contact, phone=t.phone,
                     tier=t.tier, modules=t.modules or [], onboarded=t.onboarded, state=t.state)


# --- read: any authenticated user (needed by the toolbar selector + scope lists) ---
@router.get("", response_model=list[TenantOut])
async def list_tenants(user: User = Depends(active_user), db: AsyncSession = Depends(get_db),
                       include_archived: bool = False):
    rows = (await db.execute(select(Tenant).order_by(Tenant.name))).scalars().all()
    if not include_archived:
        rows = [t for t in rows if t.state == "active"]
    # least privilege: a scoped user only sees the customers in their own scope
    if not all_tenants(user):
        allowed = set(user.allowed_customer_ids or [])
        rows = [t for t in rows if t.id in allowed]
    return [_out(t) for t in rows]


# --- writes: managers only ---
@router.post("", response_model=TenantOut, status_code=201)
async def create_tenant(body: TenantCreateIn, admin: User = Depends(_admin),
                        db: AsyncSession = Depends(get_db)):
    if (await db.execute(select(Tenant).where(Tenant.id == body.id))).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "tenant id already exists")
    t = Tenant(id=body.id, name=body.name, label=body.label or body.id, contact=body.contact,
               phone=body.phone, tier=body.tier, modules=body.modules, onboarded=body.onboarded,
               state="active", created_by=admin.username)
    db.add(t)
    db.add(AuditEvent(kind="tenant.created", detail=f"{t.id} · {t.tier}", actor=admin.username))
    await db.commit()
    return _out(t)


@router.patch("/{tenant_id}", response_model=TenantOut)
async def update_tenant(tenant_id: str, body: TenantUpdateIn, admin: User = Depends(_admin),
                        db: AsyncSession = Depends(get_db)):
    t = (await db.execute(select(Tenant).where(Tenant.id == tenant_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such tenant")
    data = body.model_dump(exclude_none=True)
    if "state" in data and data["state"] not in ("active", "archived"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "state must be active|archived")
    for k, v in data.items():
        setattr(t, k, v)
    db.add(AuditEvent(kind="tenant.updated", detail=f"{t.id} · by {admin.username}", actor=admin.username))
    await db.commit()
    return _out(t)


@router.delete("/{tenant_id}")
async def archive_tenant(tenant_id: str, admin: User = Depends(_admin),
                         db: AsyncSession = Depends(get_db)) -> dict:
    t = (await db.execute(select(Tenant).where(Tenant.id == tenant_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such tenant")
    t.state = "archived"      # archived, never deleted — history stays intact
    db.add(AuditEvent(kind="tenant.archived", detail=t.id, actor=admin.username))
    await db.commit()
    return {"ok": True, "state": "archived"}
