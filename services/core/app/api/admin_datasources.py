"""Data sources — edit the query catalog (edit_data_sources capability).

Every save validates the SPL (read-only commands, known tokens, a tenant filter
for tenant-scoped queries), bumps the version, keeps the previous text in the
history and writes an audit line. Built-in queries can be reset to their
shipped text; custom queries and unused fragments can be deleted.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import delete, select

from ..audit import event
from ..datasources import service
from ..datasources import spl as spl_mod
from ..datasources.catalog import SEED_BY_ID
from ..db import SessionLocal
from ..deps import require_capability
from ..models import DataQuery, DataQueryVersion, User, _now
from ..rbac import Capability
from .common import guard, resolve_period
from .data import query_out

router = APIRouter()
_editor = require_capability(Capability.edit_data_sources)
_ID = re.compile(r"^[a-z0-9][a-z0-9_.\-]{2,95}$")
CATEGORIES = ("overview", "sla", "l1", "agentic", "fragment", "custom")


class QueryIn(BaseModel):
    id: str
    name: str = Field(min_length=1, max_length=160)
    description: str = Field("", max_length=512)
    category: str = "custom"
    spl: str
    columns: list[str] = []
    scope_mode: str = "tenant_token"
    scope_field: str = Field("", max_length=64)
    cache_seconds: int = Field(300, ge=0, le=3600)


class QueryPatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=160)
    description: str | None = Field(None, max_length=512)
    spl: str | None = None
    columns: list[str] | None = None
    scope_mode: str | None = None
    scope_field: str | None = Field(None, max_length=64)
    cache_seconds: int | None = Field(None, ge=0, le=3600)
    note: str = Field("", max_length=256)


class TestIn(BaseModel):
    spl: str
    scope_mode: str = "tenant_token"
    scope_field: str = ""
    columns: list[str] = []
    period: str | None = None
    date_from: str | None = Field(None, alias="from")
    date_to: str | None = Field(None, alias="to")
    tenant: str = "all"


def _check(spl: str, category: str, scope_mode: str, fragments: dict[str, str]) -> None:
    issues = spl_mod.problems(spl, fragments, None if category == "fragment" else scope_mode)
    if issues:
        raise HTTPException(422, "; ".join(issues))


def _used_by(cat: dict, fragment_id: str) -> list[str]:
    return sorted(q.id for q in cat.values() if fragment_id in spl_mod.includes(q.spl))


@router.get("")
async def list_all(user: User = Depends(_editor)) -> list[dict]:
    cat = await service.catalog()
    out = []
    for q in sorted(cat.values(), key=lambda q: (q.category, q.id)):
        d = query_out(q, True)
        if q.category == "fragment":
            d["used_by"] = _used_by(cat, q.id)
        out.append(d)
    return out


@router.post("", status_code=201)
async def create(body: QueryIn, user: User = Depends(_editor)) -> dict:
    if not _ID.match(body.id):
        raise HTTPException(422, "id: lowercase letters, digits, dot, dash, underscore (3–96)")
    if body.category not in CATEGORIES:
        raise HTTPException(422, f"category must be one of {', '.join(CATEGORIES)}")
    cat = await service.catalog()
    if body.id in cat:
        raise HTTPException(409, "a query with that id exists")
    _check(body.spl, body.category, body.scope_mode, service.fragments_of(cat))
    async with SessionLocal() as db:
        q = DataQuery(**body.model_dump(), builtin=False, version=1, updated_by=user.username)
        db.add(q)
        db.add(DataQueryVersion(query_id=q.id, version=1, spl=q.spl, note="created", changed_by=user.username))
        db.add(event("datasource.created", f"{q.id} · {q.category}", user.username))
        await db.commit()
        return query_out(q, True)


async def _save(query_id: str, changes: dict, note: str, user: User, audit_kind: str) -> dict:
    cat = await service.catalog()
    if query_id not in cat:
        raise HTTPException(404, "no such query")
    async with SessionLocal() as db:
        q = (await db.execute(select(DataQuery).where(DataQuery.id == query_id))).scalar_one()
        spl_text = changes.get("spl", q.spl)
        scope_mode = changes.get("scope_mode", q.scope_mode)
        fragments = service.fragments_of(cat)
        if q.category == "fragment":
            fragments[q.id] = spl_text          # validate with the new text in place
        _check(spl_text, q.category, scope_mode, fragments)
        spl_changed = spl_text != q.spl
        for k, v in changes.items():
            setattr(q, k, v)
        q.version += 1
        q.updated_by, q.updated_at = user.username, _now()
        db.add(DataQueryVersion(query_id=q.id, version=q.version, spl=q.spl, note=note[:256], changed_by=user.username))
        db.add(event(audit_kind, f"{q.id} → v{q.version}{' · SPL changed' if spl_changed else ''}"
                                 f"{' · ' + note if note else ''}", user.username))
        await db.commit()
        return query_out(q, True)


@router.patch("/{query_id}")
async def update(query_id: str, body: QueryPatch, user: User = Depends(_editor)) -> dict:
    changes = body.model_dump(exclude_none=True, exclude={"note"})
    if not changes:
        raise HTTPException(422, "nothing to change")
    return await _save(query_id, changes, body.note, user, "datasource.changed")


@router.get("/{query_id}/versions")
async def versions(query_id: str, user: User = Depends(_editor)) -> list[dict]:
    async with SessionLocal() as db:
        rows = (await db.execute(select(DataQueryVersion).where(DataQueryVersion.query_id == query_id)
                                 .order_by(DataQueryVersion.version.desc()))).scalars().all()
    if not rows:
        raise HTTPException(404, "no such query")
    return [{"version": v.version, "spl": v.spl, "note": v.note, "changed_by": v.changed_by,
             "changed_at": v.changed_at.isoformat() if v.changed_at else None} for v in rows]


class RollbackIn(BaseModel):
    version: int


@router.post("/{query_id}/rollback")
async def rollback(query_id: str, body: RollbackIn, user: User = Depends(_editor)) -> dict:
    async with SessionLocal() as db:
        v = (await db.execute(select(DataQueryVersion).where(DataQueryVersion.query_id == query_id,
                                                             DataQueryVersion.version == body.version))).scalar_one_or_none()
    if v is None:
        raise HTTPException(404, "no such version")
    return await _save(query_id, {"spl": v.spl}, f"rollback to v{body.version}", user, "datasource.rolled_back")


@router.post("/{query_id}/reset")
async def reset(query_id: str, user: User = Depends(_editor)) -> dict:
    seed = SEED_BY_ID.get(query_id)
    if seed is None:
        raise HTTPException(400, "only built-in queries can be reset")
    changes = {k: seed[k] for k in ("name", "description", "spl", "columns", "scope_mode", "scope_field",
                                    "cache_seconds")}
    return await _save(query_id, changes, "reset to built-in", user, "datasource.reset")


@router.delete("/{query_id}")
async def remove(query_id: str, user: User = Depends(_editor)) -> dict:
    cat = await service.catalog()
    q = cat.get(query_id)
    if q is None:
        raise HTTPException(404, "no such query")
    if q.builtin:
        raise HTTPException(400, "built-in queries cannot be deleted — reset them instead")
    users = _used_by(cat, query_id)
    if users:
        raise HTTPException(409, f"still included by: {', '.join(users)}")
    async with SessionLocal() as db:
        await db.execute(delete(DataQuery).where(DataQuery.id == query_id))
        db.add(event("datasource.deleted", query_id, user.username))
        await db.commit()
    return {"ok": True}


@router.post("/test")
async def test(body: TestIn, user: User = Depends(_editor)) -> dict:
    p = resolve_period(body.period, body.date_from, body.date_to)
    return await guard(service.test_query(user, body.spl, body.scope_mode, body.scope_field, p,
                                          body.tenant, body.columns))
