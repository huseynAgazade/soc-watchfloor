"""Authentication: login, logout, current user, first-login password change, and
optional TOTP enrolment. Sessions are server-side; the cookie holds only an
opaque token."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_db
from ..deps import all_tenants, current_user, user_capabilities
from ..models import AuditEvent
from ..models import Session as SessionModel
from ..models import User
from ..schemas import ChangePasswordIn, LoginIn, MeOut
from ..security import totp
from ..security.passwords import hash_password, needs_rehash, verify_password
from ..security.tokens import new_token, token_hash

router = APIRouter()


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _audit(db: AsyncSession, kind: str, detail: str, actor: str) -> None:
    db.add(AuditEvent(kind=kind, detail=detail, actor=actor))


@router.post("/login")
async def login(body: LoginIn, response: Response, db: AsyncSession = Depends(get_db)) -> dict:
    user = (await db.execute(select(User).where(User.username == body.username))).scalar_one_or_none()
    # Uniform failure — never reveal whether the username exists.
    invalid = HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    if not user or user.state == "disabled":
        raise invalid

    now = _now()
    if user.locked_until:
        lu = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=timezone.utc)
        if now < lu:
            raise HTTPException(status.HTTP_423_LOCKED, "account temporarily locked")

    if not user.password_hash or not verify_password(user.password_hash, body.password):
        user.failed_attempts += 1
        if user.failed_attempts >= settings.lockout_attempts:
            user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
            user.failed_attempts = 0
            await _audit(db, "login.locked", user.username, user.username)
        await _audit(db, "login.failed", f"{user.username} attempt", user.username)
        await db.commit()
        raise invalid

    # OTP step, only if the policy is on and the user is enrolled
    mfa_ok = True
    if settings.otp_required and user.mfa_enrolled:
        if not totp.verify(user.totp_secret, body.otp or ""):
            await _audit(db, "login.otp_failed", user.username, user.username)
            await db.commit()
            raise invalid

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)

    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    if user.state == "pending":
        user.state = "active"

    token = new_token()
    sess = SessionModel(
        token_hash=token_hash(token), user_id=user.id,
        expires_at=now + timedelta(hours=settings.session_ttl_hours), mfa_ok=mfa_ok,
    )
    db.add(sess)
    await _audit(db, "login.success", f"{user.username} · {user.role}", user.username)
    await db.commit()

    response.set_cookie(
        settings.session_cookie, token, httponly=True, samesite="lax",
        secure=settings.cookie_secure, max_age=settings.session_ttl_hours * 3600,
    )
    return {"ok": True, "must_change_password": user.must_change_password}


@router.post("/logout")
async def logout(response: Response, user: User = Depends(current_user),
                 db: AsyncSession = Depends(get_db)) -> dict:
    # current_user stashed the session on request.state, but re-revoke defensively
    from sqlalchemy import update
    await db.execute(update(SessionModel).where(
        SessionModel.user_id == user.id, SessionModel.revoked == False  # noqa: E712
    ).values(revoked=True))
    await db.commit()
    response.delete_cookie(settings.session_cookie)
    return {"ok": True}


@router.get("/me", response_model=MeOut)
async def me(user: User = Depends(current_user)) -> MeOut:
    caps = sorted(c.value for c in user_capabilities(user))
    return MeOut(
        username=user.username, full_name=user.full_name, role=user.role,
        team=user.team, grade=user.grade, capabilities=caps,
        allowed_customer_ids=user.allowed_customer_ids or [],
        all_tenants=all_tenants(user),
        must_change_password=user.must_change_password, mfa_enrolled=user.mfa_enrolled,
    )


@router.post("/change-password")
async def change_password(body: ChangePasswordIn, user: User = Depends(current_user),
                          db: AsyncSession = Depends(get_db)) -> dict:
    if not verify_password(user.password_hash, body.current_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "current password is wrong")
    if len(body.new_password) < settings.password_min_length:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"password must be at least {settings.password_min_length} characters")
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    await _audit(db, "password.changed", user.username, user.username)
    await db.commit()
    return {"ok": True}


@router.post("/totp/enroll")
async def totp_enroll(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)) -> dict:
    secret = totp.new_secret()
    user.totp_secret = secret
    user.mfa_enrolled = False  # not enrolled until a code is verified
    await db.commit()
    return {"secret": secret, "uri": totp.provisioning_uri(secret, user.username)}


@router.post("/totp/verify")
async def totp_verify(code: str, user: User = Depends(current_user),
                      db: AsyncSession = Depends(get_db)) -> dict:
    if not totp.verify(user.totp_secret, code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "code did not match")
    user.mfa_enrolled = True
    await _audit(db, "totp.enrolled", user.username, user.username)
    await db.commit()
    return {"ok": True}
