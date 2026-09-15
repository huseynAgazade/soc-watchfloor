"""Authentication: login, logout, current user, password change, and optional
TOTP enrolment. Sessions are server-side; the cookie holds only an opaque token."""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import event
from ..config import settings
from ..db import get_db
from ..deps import active_user, all_tenants, current_user, user_capabilities
from ..models import Session as SessionModel
from ..models import User
from ..schemas import ChangePasswordIn, LoginIn, MeOut, TotpEnrollIn, TotpVerifyIn
from ..security import totp
from ..security.passwords import hash_password, needs_rehash, verify_password
from ..security.policy import password_problem
from ..security.sessions import revoke_sessions
from ..security.throttle import client_ip, login_throttle
from ..security.tokens import new_token, token_hash

router = APIRouter()

TOTP_VERIFY_ATTEMPTS = 5   # wrong codes before a pending enrolment is discarded


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _locked(user: User, now: datetime) -> bool:
    if not user.locked_until:
        return False
    lu = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=timezone.utc)
    return now < lu


def _register_failure(db: AsyncSession, user: User, kind: str, now: datetime) -> None:
    """Count a failed credential check; lock the account at the threshold."""
    user.failed_attempts += 1
    if user.failed_attempts >= settings.lockout_attempts:
        user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
        user.failed_attempts = 0
        db.add(event("login.locked", user.username, user.username))
    db.add(event(kind, f"{user.username} attempt", user.username))


@router.post("/login")
async def login(body: LoginIn, request: Request, response: Response, db: AsyncSession = Depends(get_db)) -> dict:
    ip = client_ip(request)
    wait = login_throttle.retry_after(ip, settings.login_ip_attempts, settings.login_ip_window_seconds)
    if wait:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f"too many failed sign-ins from this address — try again in {math.ceil(wait / 60)} min",
                            headers={"Retry-After": str(wait)})
    if len(body.username) > 64 or len(body.password) > 1024 or len(body.otp or "") > 16:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "username, password or code is too long")
    # Uniform failure — never reveal whether the username exists.
    invalid = HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    async def failed(kind: str | None = None, detail: str = "") -> None:
        if login_throttle.fail(ip, settings.login_ip_window_seconds) == settings.login_ip_attempts:
            db.add(event("login.throttled", f"{ip} · {settings.login_ip_attempts} failed sign-ins", "anonymous"))
        if kind:
            db.add(event(kind, detail, "anonymous"))
        await db.commit()

    if body.website:   # honeypot: hidden from people, filled in by form-spamming bots
        await failed("login.honeypot", ip)
        raise invalid

    user = (await db.execute(select(User).where(User.username == body.username))).scalar_one_or_none()
    if not user or user.state == "disabled":
        await failed()
        raise invalid

    now = _now()
    if _locked(user, now):
        raise HTTPException(status.HTTP_423_LOCKED, "account temporarily locked")

    if not user.password_hash or not verify_password(user.password_hash, body.password):
        _register_failure(db, user, "login.failed", now)
        await failed()
        raise invalid

    # OTP step, only if the policy is on and the user is enrolled
    mfa_ok = True
    if settings.otp_required and user.mfa_enrolled:
        if not totp.verify(user.totp_secret, body.otp or ""):
            db.add(event("login.otp_failed", user.username, user.username))
            await failed()
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
    db.add(event("login.success", f"{user.username} · {user.role}", user.username))
    await db.commit()

    response.set_cookie(
        settings.session_cookie, token, httponly=True, samesite="lax",
        secure=settings.cookie_secure, max_age=settings.session_ttl_hours * 3600,
    )
    return {"ok": True, "must_change_password": user.must_change_password}


@router.post("/logout")
async def logout(response: Response, user: User = Depends(current_user),
                 db: AsyncSession = Depends(get_db)) -> dict:
    await revoke_sessions(db, user.id)
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
async def change_password(body: ChangePasswordIn, request: Request, user: User = Depends(current_user),
                          db: AsyncSession = Depends(get_db)) -> dict:
    now = _now()
    if _locked(user, now):
        raise HTTPException(status.HTTP_423_LOCKED, "account temporarily locked")
    if not user.password_hash or not verify_password(user.password_hash, body.current_password):
        _register_failure(db, user, "password.change_failed", now)
        await db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "current password is wrong")
    problem = password_problem(body.new_password, user.username)
    if problem:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, problem)
    if verify_password(user.password_hash, body.new_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "new password must differ from the current one")
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    user.failed_attempts = 0
    # every other session is signed out; the one making the change stays
    sess = getattr(request.state, "session", None)
    await revoke_sessions(db, user.id, keep_session_id=sess.id if sess else None)
    db.add(event("password.changed", user.username, user.username))
    await db.commit()
    return {"ok": True}


@router.post("/totp/enroll")
async def totp_enroll(body: TotpEnrollIn, user: User = Depends(active_user),
                      db: AsyncSession = Depends(get_db)) -> dict:
    """Start (re-)enrolment. Needs the account password, and — when a secret is
    already enrolled — a current code from it, so a session alone can never
    replace or remove someone's second factor. The existing secret stays in force
    until /totp/verify confirms the new one."""
    now = _now()
    if _locked(user, now):
        raise HTTPException(status.HTTP_423_LOCKED, "account temporarily locked")
    if not user.password_hash or not verify_password(user.password_hash, body.password):
        _register_failure(db, user, "totp.enroll_denied", now)
        await db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "password is wrong")
    if user.mfa_enrolled and not totp.verify(user.totp_secret, body.otp or ""):
        _register_failure(db, user, "totp.enroll_denied", now)
        await db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "enter a current code from your existing authenticator")
    secret = totp.new_secret()
    user.totp_pending_secret = secret
    user.totp_pending_attempts = 0
    db.add(event("totp.enroll_started", user.username, user.username))
    await db.commit()
    return {"secret": secret, "uri": totp.provisioning_uri(secret, user.username)}


@router.post("/totp/verify")
async def totp_verify(body: TotpVerifyIn, user: User = Depends(active_user),
                      db: AsyncSession = Depends(get_db)) -> dict:
    if not user.totp_pending_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "start enrolment first")
    if not totp.verify(user.totp_pending_secret, body.code):
        user.totp_pending_attempts += 1
        if user.totp_pending_attempts >= TOTP_VERIFY_ATTEMPTS:
            user.totp_pending_secret = ""
            user.totp_pending_attempts = 0
            db.add(event("totp.enroll_abandoned", f"{user.username} · too many wrong codes", user.username))
            await db.commit()
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "too many wrong codes — start enrolment again")
        await db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "code did not match")
    user.totp_secret = user.totp_pending_secret
    user.totp_pending_secret = ""
    user.totp_pending_attempts = 0
    user.mfa_enrolled = True
    db.add(event("totp.enrolled", user.username, user.username))
    await db.commit()
    return {"ok": True}
