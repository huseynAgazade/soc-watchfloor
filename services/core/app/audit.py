"""Audit trail writer. Security-relevant actions land in audit_events through
this helper, so the event shape and column limits live in one place.
Append-only: nothing in the application updates or deletes audit rows."""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from .db import SessionLocal
from .models import AuditEvent


def event(kind: str, detail: str, actor: str) -> AuditEvent:
    return AuditEvent(kind=kind[:48], detail=(detail or "")[:512], actor=(actor or "")[:64])


async def record(kind: str, detail: str, actor: str, db: AsyncSession | None = None) -> None:
    """With `db`, join the caller's transaction (the caller commits). Without,
    write and commit in a session of its own — for long-running flows such as
    the assistant, which must not hold a request's session open."""
    if db is not None:
        db.add(event(kind, detail, actor))
        return
    async with SessionLocal() as own:
        own.add(event(kind, detail, actor))
        await own.commit()
