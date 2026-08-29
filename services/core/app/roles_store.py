"""Persisted role -> capability matrix. Seeds from the rbac defaults on first run,
loads into the rbac overlay at startup, and saves edits back."""
from __future__ import annotations

from sqlalchemy import select

from . import rbac
from .db import SessionLocal
from .models import RoleCaps
from .rbac import LOCKED_ROLE, ROLE_CAPABILITIES, Role


async def seed_roles() -> None:
    async with SessionLocal() as db:
        existing = (await db.execute(select(RoleCaps).limit(1))).scalar_one_or_none()
        if existing:
            return
        for role in Role:
            if role == LOCKED_ROLE:
                continue
            caps = sorted(c.value for c in ROLE_CAPABILITIES.get(role, set()))
            db.add(RoleCaps(role=role.value, capabilities=caps, updated_by="system"))
        await db.commit()


async def load_override() -> None:
    async with SessionLocal() as db:
        rows = (await db.execute(select(RoleCaps))).scalars().all()
    rbac.set_override({r.role: r.capabilities or [] for r in rows})


async def save_role(role: str, capabilities: list[str], actor: str) -> None:
    async with SessionLocal() as db:
        row = (await db.execute(select(RoleCaps).where(RoleCaps.role == role))).scalar_one_or_none()
        if row is None:
            row = RoleCaps(role=role)
            db.add(row)
        row.capabilities = capabilities
        row.updated_by = actor
        await db.commit()
    await load_override()
