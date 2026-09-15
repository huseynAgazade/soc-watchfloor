"""ORM models. Users are admin-provisioned; leavers are disabled, never deleted,
so audit records keep resolving to a real name."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text, UniqueConstraint
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
    # enrolment in progress: the new secret only replaces totp_secret once a code
    # from it verifies, so starting enrolment never weakens an existing one
    totp_pending_secret: Mapped[str] = mapped_column(String(64), default="")
    totp_pending_attempts: Mapped[int] = mapped_column(Integer, default=0)

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
    modules: Mapped[list] = mapped_column(JSON, default=list)        # sla|mitre|rules|agentic
    state: Mapped[str] = mapped_column(String(16), default="active") # active|archived
    onboarded: Mapped[str] = mapped_column(String(16), default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class DataQuery(Base):
    """One entry of the query catalog. Every dashboard panel and every assistant
    data tool runs one of these; the SPL is editable (with version history) and
    carries tokens the server fills per run — see app/datasources/spl.py."""
    __tablename__ = "data_queries"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)        # e.g. sla.by_customer
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(String(512), default="")
    category: Mapped[str] = mapped_column(String(32), default="custom")  # overview|sla|l1|agentic|fragment|custom
    source: Mapped[str] = mapped_column(String(16), default="splunk")
    spl: Mapped[str] = mapped_column(Text, default="")
    columns: Mapped[list] = mapped_column(JSON, default=list)           # the result contract panels read
    scope_mode: Mapped[str] = mapped_column(String(16), default="tenant_token")  # tenant_token|global
    scope_field: Mapped[str] = mapped_column(String(64), default="")    # result column holding the tenant
    cache_seconds: Mapped[int] = mapped_column(Integer, default=300)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class DataQueryVersion(Base):
    __tablename__ = "data_query_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    query_id: Mapped[str] = mapped_column(String(96), index=True)
    version: Mapped[int] = mapped_column(Integer)
    spl: Mapped[str] = mapped_column(Text, default="")
    note: Mapped[str] = mapped_column(String(256), default="")
    changed_by: Mapped[str] = mapped_column(String(64), default="")
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ChatConversation(Base):
    """A saved assistant conversation. Private to the user who had it — no other
    account, admins included, can list or open it through the API."""
    __tablename__ = "chat_conversations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)          # random, unguessable
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    title: Mapped[str] = mapped_column(String(160), default="")
    # the tenants whose data it may hold: ["*"] for all, else tenant ids. It opens
    # only while the user's current scope still covers them.
    scope: Mapped[list] = mapped_column(JSON, default=list)
    turns: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ChatTurn(Base):
    """One answered question: what was asked, the answer, and the tool steps and
    text in the order the page drew them, so a saved chat redraws the same."""
    __tablename__ = "chat_turns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    conversation_id: Mapped[str] = mapped_column(String(32), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    question: Mapped[str] = mapped_column(Text, default="")
    reply: Mapped[str] = mapped_column(Text, default="")
    events: Mapped[list] = mapped_column(JSON, default=list)
    stopped: Mapped[str] = mapped_column(String(24), default="")
    tenant: Mapped[str] = mapped_column(String(64), default="")      # what the portal was showing
    period: Mapped[str] = mapped_column(String(16), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class UsageCount(Base):
    """First-party usage statistics: how often each portal page was opened, per
    day and role. Deliberately no user, session or address — counts only, and
    only from people who allowed usage statistics."""
    __tablename__ = "usage_counts"
    __table_args__ = (UniqueConstraint("day", "view", "role"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    day: Mapped[str] = mapped_column(String(10), index=True)          # YYYY-MM-DD, org timezone
    view: Mapped[str] = mapped_column(String(32))
    role: Mapped[str] = mapped_column(String(32))
    count: Mapped[int] = mapped_column(Integer, default=0)


class RoleCaps(Base):
    __tablename__ = "role_caps"

    role: Mapped[str] = mapped_column(String(32), primary_key=True)
    capabilities: Mapped[list] = mapped_column(JSON, default=list)   # capability value strings
    updated_by: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
