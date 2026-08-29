"""ORM models. Users are admin-provisioned; leavers are disabled, never deleted,
so audit records keep resolving to a real name."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(128))
    email: Mapped[str] = mapped_column(String(128), default="")
    phone: Mapped[str] = mapped_column(String(48), default="")
    chat_handle: Mapped[str] = mapped_column(String(48), default="")

    role: Mapped[str] = mapped_column(String(32))
    team: Mapped[str] = mapped_column(String(32), default="")        # analysts|engineers|mgmt
    grade: Mapped[str] = mapped_column(String(32), default="")
    # extra per-user capability grants (rota publishing), as a JSON list of strings
    grants: Mapped[list] = mapped_column(JSON, default=list)
    # tenant scope: [] means "all" when combined with cross_tenant, else a fixed list
    allowed_customer_ids: Mapped[list] = mapped_column(JSON, default=list)

    password_hash: Mapped[str] = mapped_column(String(255), default="")
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    totp_secret: Mapped[str] = mapped_column(String(64), default="")
    mfa_enrolled: Mapped[bool] = mapped_column(Boolean, default=False)

    state: Mapped[str] = mapped_column(String(16), default="pending")  # active|pending|disabled
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    mfa_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(48), index=True)
    detail: Mapped[str] = mapped_column(String(512), default="")
    actor: Mapped[str] = mapped_column(String(64), default="")
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)   # = SOAR label / customer id
    name: Mapped[str] = mapped_column(String(128))
    label: Mapped[str] = mapped_column(String(64), default="")       # SOAR container label (join key)
    contact: Mapped[str] = mapped_column(String(128), default="")
    phone: Mapped[str] = mapped_column(String(48), default="")
    tier: Mapped[str] = mapped_column(String(48), default="")
    modules: Mapped[list] = mapped_column(JSON, default=list)        # sla|mitre|rules|brief
    state: Mapped[str] = mapped_column(String(16), default="active") # active|archived
    onboarded: Mapped[str] = mapped_column(String(16), default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class RoleCaps(Base):
    __tablename__ = "role_caps"

    role: Mapped[str] = mapped_column(String(32), primary_key=True)
    capabilities: Mapped[list] = mapped_column(JSON, default=list)   # capability value strings
    updated_by: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
