"""Request dependencies — this is where authorization is actually enforced.

current_user resolves the session cookie to a live, non-disabled user. The tenant
scope and capability set come from the DB record, server-side, and cannot be
influenced by anything the client sends. require_capability / require_tenant gate
individual endpoints.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .db import get_db
from .models import Session as SessionModel
from .models import User
from .rbac import Capability, Role, effective_capabilities
from .security.tokens import token_hash


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def current_user(
    request: Request, db: AsyncSession = Depends(get_db)
) -> User:
    token = request.cookies.get(settings.session_cookie)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    th = token_hash(token)
    sess = (await db.execute(
        select(SessionModel).where(SessionModel.token_hash == th)
    )).scalar_one_or_none()
    if not sess or sess.revoked:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid session")

    now = _now()
    exp = sess.expires_at if sess.expires_at.tzinfo else sess.expires_at.replace(tzinfo=timezone.utc)
    seen = sess.last_seen_at if sess.last_seen_at.tzinfo else sess.last_seen_at.replace(tzinfo=timezone.utc)
    if now > exp:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session expired")
    if now - seen > timedelta(minutes=settings.session_idle_minutes):
        sess.revoked = True
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session idle-timed out")

    user = (await db.execute(select(User).where(User.id == sess.user_id))).scalar_one_or_none()
    if not user or user.state == "disabled":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "account not active")

    # OTP gate: if the policy requires OTP and this session hasn't cleared it
    if settings.otp_required and user.mfa_enrolled and not sess.mfa_ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "otp required")

    sess.last_seen_at = now
    await db.commit()
    request.state.session = sess
    return user


def user_capabilities(user: User) -> set[Capability]:
    try:
        role = Role(user.role)
    except ValueError:
        return set()
    grants = {Capability(g) for g in (user.grants or []) if g in set(Capability)}
    return effective_capabilities(role, grants)


async def active_user(user: User = Depends(current_user)) -> User:
    """A fully-active session: authenticated and past the forced first-login
    password change. Data and admin endpoints require this, so a temporary
    credential cannot read anything before it is changed."""
    if user.must_change_password:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "must change password before continuing")
    return user


def require_capability(cap: Capability):
    async def _dep(user: User = Depends(active_user)) -> User:
        if cap not in user_capabilities(user):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"missing capability: {cap}")
        return user
    return _dep


def all_tenants(user: User) -> bool:
    return (Capability.cross_tenant in user_capabilities(user)
            and not (user.allowed_customer_ids or []))


def in_scope(user: User, customer_id: str) -> bool:
    if all_tenants(user):
        return True
    return customer_id in (user.allowed_customer_ids or [])
