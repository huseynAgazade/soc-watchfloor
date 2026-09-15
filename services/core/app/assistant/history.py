"""Saved assistant conversations.

Each answered question is stored with its answer and the tool steps (including
the row previews the page showed), so a user can reopen a chat later and see it
as it was answered. Follow-up questions in a saved chat take their history from
the database, not from the browser.

Privacy and scope:
  * a conversation belongs to one user; any other account gets the same 404 as
    for a conversation that does not exist (no id probing);
  * a conversation remembers which tenants' data it may hold. If the user's
    tenant access is later narrowed, it can no longer be opened or continued —
    only deleted — so saved rows never outlive the access that produced them;
  * conversations expire after `assistant_saved_chat_days` and each user keeps at
    most `assistant_saved_chats_per_user`.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from ..config import settings
from ..db import SessionLocal
from ..deps import all_tenants
from ..models import ChatConversation, ChatTurn, User

ALL = "*"


class NotFound(Exception):
    pass


class ScopeChanged(Exception):
    pass


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return _utc(dt).isoformat()


def scope_of(user: User) -> list[str]:
    return [ALL] if all_tenants(user) else sorted(set(user.allowed_customer_ids or []))


def covers(user: User, saved: list[str]) -> bool:
    if all_tenants(user):
        return True
    return ALL not in saved and set(saved) <= set(user.allowed_customer_ids or [])


def title_from(question: str) -> str:
    text = " ".join(question.split())
    return text if len(text) <= 80 else text[:79].rstrip() + "…"


def compact(events: list[dict]) -> list[dict]:
    """The events worth redrawing: text (merged), tool steps and errors."""
    out: list[dict] = []
    for ev in events:
        kind = ev.get("type")
        if kind == "text":
            if out and out[-1]["type"] == "text":
                out[-1]["delta"] += ev.get("delta", "")
            else:
                out.append({"type": "text", "delta": ev.get("delta", "")})
        elif kind in ("tool_start", "tool_end", "error"):
            out.append(dict(ev))
    out = json.loads(json.dumps(out, default=str))
    if len(json.dumps(out)) > settings.assistant_saved_turn_chars:
        for ev in out:
            if isinstance(ev.get("preview"), dict):
                ev["preview"] = {**ev["preview"], "rows": [], "rows_not_saved": True}
    return out


async def _owned(db, user: User, conversation_id: str) -> ChatConversation:
    conv = await db.get(ChatConversation, conversation_id)
    if conv is None or conv.user_id != user.id:
        raise NotFound(conversation_id)
    return conv


async def get(user: User, conversation_id: str) -> ChatConversation:
    """The user's own conversation, if their current scope still covers it."""
    async with SessionLocal() as db:
        conv = await _owned(db, user, conversation_id)
    if not covers(user, conv.scope or []):
        raise ScopeChanged("your tenant access has changed since this chat was saved, so it can no longer be "
                           "opened or continued — you can delete it")
    return conv


async def as_history(conversation_id: str) -> list[dict]:
    async with SessionLocal() as db:
        turns = (await db.execute(select(ChatTurn).where(ChatTurn.conversation_id == conversation_id)
                                  .order_by(ChatTurn.seq))).scalars().all()
    out: list[dict] = []
    for t in turns:
        out += [{"role": "user", "content": t.question}, {"role": "assistant", "content": t.reply}]
    return out


async def save_turn(user: User, conv: ChatConversation | None, question: str, done: dict, events: list[dict],
                    tenant: str | None, period: str | None) -> str:
    now = datetime.now(timezone.utc)
    async with SessionLocal() as db:
        row = await db.get(ChatConversation, conv.id) if conv is not None else None
        if row is None or row.user_id != user.id:    # new, or deleted while it was being answered
            row = ChatConversation(id=uuid.uuid4().hex, user_id=user.id, title=title_from(question),
                                   scope=[], turns=0, created_at=now)
            db.add(row)
        saved = row.scope or []
        row.scope = [ALL] if ALL in saved or all_tenants(user) else sorted(set(saved) | set(scope_of(user)))
        row.turns = (row.turns or 0) + 1
        row.updated_at = now
        db.add(ChatTurn(conversation_id=row.id, seq=row.turns, question=question, reply=done.get("reply") or "",
                        events=compact(events), stopped=done.get("stopped") or "",
                        tenant=(tenant or "")[:64], period=(period or "")[:16], created_at=now))
        await db.commit()
        conversation_id = row.id
    await prune()
    return conversation_id


async def prune(user_id: int | None = None) -> int:
    """Remove expired conversations and each user's oldest beyond the cap."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.assistant_saved_chat_days)
    async with SessionLocal() as db:
        q = select(ChatConversation.id, ChatConversation.user_id, ChatConversation.updated_at)
        if user_id is not None:
            q = q.where(ChatConversation.user_id == user_id)
        rows = (await db.execute(q.order_by(ChatConversation.updated_at.desc()))).all()
        kept: dict[int, int] = {}
        drop = []
        for cid, uid, updated in rows:
            kept[uid] = kept.get(uid, 0) + 1
            if _utc(updated) < cutoff or kept[uid] > settings.assistant_saved_chats_per_user:
                drop.append(cid)
        if drop:
            await db.execute(delete(ChatTurn).where(ChatTurn.conversation_id.in_(drop)))
            await db.execute(delete(ChatConversation).where(ChatConversation.id.in_(drop)))
            await db.commit()
    return len(drop)


async def list_for(user: User) -> list[dict]:
    await prune(user.id)
    async with SessionLocal() as db:
        rows = (await db.execute(select(ChatConversation).where(ChatConversation.user_id == user.id)
                                 .order_by(ChatConversation.updated_at.desc()))).scalars().all()
    return [{"id": c.id, "title": c.title, "turns": c.turns, "created_at": _iso(c.created_at),
             "updated_at": _iso(c.updated_at), "locked": not covers(user, c.scope or [])} for c in rows]


async def read(user: User, conversation_id: str) -> dict:
    conv = await get(user, conversation_id)
    async with SessionLocal() as db:
        turns = (await db.execute(select(ChatTurn).where(ChatTurn.conversation_id == conv.id)
                                  .order_by(ChatTurn.seq))).scalars().all()
    return {"id": conv.id, "title": conv.title, "created_at": _iso(conv.created_at),
            "updated_at": _iso(conv.updated_at),
            "turns": [{"question": t.question, "reply": t.reply, "events": t.events or [], "stopped": t.stopped or None,
                       "tenant": t.tenant, "period": t.period, "at": _iso(t.created_at)} for t in turns]}


async def remove(user: User, conversation_id: str) -> int:
    """Delete one of the user's conversations — allowed even when it is locked."""
    async with SessionLocal() as db:
        conv = await _owned(db, user, conversation_id)
        turns = conv.turns
        await db.execute(delete(ChatTurn).where(ChatTurn.conversation_id == conv.id))
        await db.delete(conv)
        await db.commit()
    return turns


async def remove_all(user: User) -> int:
    async with SessionLocal() as db:
        ids = (await db.execute(select(ChatConversation.id).where(ChatConversation.user_id == user.id))).scalars().all()
        if ids:
            await db.execute(delete(ChatTurn).where(ChatTurn.conversation_id.in_(ids)))
            await db.execute(delete(ChatConversation).where(ChatConversation.id.in_(ids)))
            await db.commit()
    return len(ids)
