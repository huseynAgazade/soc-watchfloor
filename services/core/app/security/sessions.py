"""Server-side session revocation."""
from __future__ import annotations

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Session as SessionModel


async def revoke_sessions(db: AsyncSession, user_id: int, keep_session_id: int | None = None) -> None:
    """Revoke every live session of a user, optionally sparing the caller's own."""
    q = update(SessionModel).where(SessionModel.user_id == user_id,
                                   SessionModel.revoked == False)  # noqa: E712
    if keep_session_id is not None:
        q = q.where(SessionModel.id != keep_session_id)
    await db.execute(q.values(revoked=True))
