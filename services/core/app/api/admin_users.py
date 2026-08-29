"""Admin user management — create, list, update and disable accounts.

Gated by the manage_users capability (managers only). This is the real backend
behind the prototype's Users tab: role, team, grade, rota grants, tenant scope
and a temporary password the user must change at first login.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import all_tenants, require_capability
from ..models import AuditEvent, User
from ..rbac import (GRANTABLE, Capability, Role, DEFAULT_ROTA_GRANTS)
from ..schemas import UserCreateIn, UserOut, UserUpdateIn
from ..security.passwords import hash_password

router = APIRouter()
_admin = require_capability(Capability.manage_users)


def _to_out(u: User) -> UserOut:
    return UserOut(
        id=u.id, username=u.username, full_name=u.full_name, email=u.email,
        phone=u.phone, chat_handle=u.chat_handle, role=u.role, team=u.team,
        grade=u.grade, grants=u.grants or [], allowed_customer_ids=u.allowed_customer_ids or [],
        all_tenants=all_tenants(u), state=u.state, mfa_enrolled=u.mfa_enrolled,
        last_login_at=u.last_login_at.isoformat() if u.last_login_at else None,
    )


def _valid_role(role: str) -> Role:
    try:
        return Role(role)
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown role: {role}")


def _clean_grants(grants: list[str]) -> list[str]:
    allowed = {c.value for c in GRANTABLE}
    return [g for g in grants if g in allowed]


@router.get("", response_model=list[UserOut])
async def list_users(admin: User = Depends(_admin), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(User).order_by(User.username))).scalars().all()
    return [_to_out(u) for u in rows]


@router.post("", response_model=UserOut, status_code=201)
async def create_user(body: UserCreateIn, admin: User = Depends(_admin),
                      db: AsyncSession = Depends(get_db)):
    role = _valid_role(body.role)
    exists = (await db.execute(select(User).where(User.username == body.username))).scalar_one_or_none()
    if exists:
        raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")

    grants = _clean_grants(body.grants) or [c.value for c in DEFAULT_ROTA_GRANTS.get(role, set())]
    u = User(
        username=body.username, full_name=body.full_name, email=body.email or "",
        phone=body.phone, chat_handle=body.chat_handle, role=role.value,
        team=body.team, grade=body.grade, grants=grants,
        allowed_customer_ids=body.allowed_customer_ids,
        password_hash=hash_password(body.temporary_password),
        must_change_password=True, mfa_enrolled=False,
        state="pending", created_by=admin.username,
    )
    db.add(u)
    db.add(AuditEvent(kind="user.created",
                      detail=f"{u.username} · {u.role} · team {u.team}", actor=admin.username))
    await db.commit()
    await db.refresh(u)
    return _to_out(u)


@router.get("/{username}", response_model=UserOut)
async def get_user(username: str, admin: User = Depends(_admin), db: AsyncSession = Depends(get_db)):
    u = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if not u:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    return _to_out(u)


@router.patch("/{username}", response_model=UserOut)
async def update_user(username: str, body: UserUpdateIn, admin: User = Depends(_admin),
                      db: AsyncSession = Depends(get_db)):
    u = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if not u:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    data = body.model_dump(exclude_none=True)
    if "role" in data:
        _valid_role(data["role"])
    if "grants" in data:
        data["grants"] = _clean_grants(data["grants"])
    if "state" in data and data["state"] not in ("active", "disabled"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "state must be active|disabled")
    for k, v in data.items():
        setattr(u, k, v)
    db.add(AuditEvent(kind="user.updated", detail=f"{u.username} · by {admin.username}",
                      actor=admin.username))
    await db.commit()
    await db.refresh(u)
    return _to_out(u)


@router.delete("/{username}")
async def disable_user(username: str, admin: User = Depends(_admin),
                       db: AsyncSession = Depends(get_db)) -> dict:
    u = (await db.execute(select(User).where(User.username == username))).scalar_one_or_none()
    if not u:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    if u.username == admin.username:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "you cannot disable your own account")
    u.state = "disabled"  # disabled, never deleted — audit still resolves the name
    db.add(AuditEvent(kind="user.disabled", detail=u.username, actor=admin.username))
    await db.commit()
    return {"ok": True, "state": "disabled"}


@router.get("/roles/matrix", tags=["rbac"])
async def role_matrix(admin: User = Depends(_admin)) -> dict:
    from ..rbac import ROLE_CAPABILITIES
    return {
        "roles": [r.value for r in Role],
        "capabilities": [c.value for c in Capability],
        "grantable": [c.value for c in GRANTABLE],
        "matrix": {r.value: sorted(c.value for c in caps) for r, caps in ROLE_CAPABILITIES.items()},
        "default_rota_grants": {r.value: sorted(c.value for c in g) for r, g in DEFAULT_ROTA_GRANTS.items()},
    }
