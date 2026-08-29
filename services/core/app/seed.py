"""Seed the initial admin on an empty user table, so the very first login is
possible. Idempotent: does nothing once any user exists."""
from __future__ import annotations

from sqlalchemy import select

from .config import settings
from .db import SessionLocal
from .models import AuditEvent, User
from .rbac import Capability, Role
from .security.passwords import hash_password


async def seed_admin() -> None:
    async with SessionLocal() as db:
        any_user = (await db.execute(select(User).limit(1))).scalar_one_or_none()
        if any_user:
            return
        admin = User(
            username=settings.seed_admin_username,
            full_name="Initial Administrator",
            email=settings.seed_admin_email,
            role=Role.soc_manager.value, team="mgmt", grade="Manager",
            grants=[Capability.publish_analyst_rota.value, Capability.publish_engineer_rota.value],
            allowed_customer_ids=[],  # empty + cross_tenant(manager) = all tenants
            password_hash=hash_password(settings.seed_admin_password),
            must_change_password=False, state="active", created_by="system",
        )
        db.add(admin)
        db.add(AuditEvent(kind="user.seeded", detail=admin.username, actor="system"))
        await db.commit()


async def seed_tenants() -> None:
    from .models import Tenant
    async with SessionLocal() as db:
        any_t = (await db.execute(select(Tenant).limit(1))).scalar_one_or_none()
        if any_t:
            return
        real = [
            ("umbrella_co", "Umbrella Co", "Managed detection", ["sla", "mitre", "rules", "brief"], "2024-02-11"),
            ("initech", "Initech", "Managed detection", ["sla", "mitre", "rules", "brief"], "2023-09-04"),
            ("hooli_media", "Hooli Media", "Monitoring only", ["sla", "rules"], "2026-05-19"),
            ("acme_corp", "Acme Corp", "Managed detection + IR", ["sla", "mitre", "rules", "brief"], "2024-11-25"),
            ("globex_co", "Globex", "Managed detection + IR", ["sla", "mitre", "rules", "brief"], "2025-01-13"),
        ]
        for cid, name, tier, mods, since in real:
            db.add(Tenant(id=cid, name=name, label=cid, tier=tier, modules=mods,
                          onboarded=since, state="active", created_by="system"))
        db.add(AuditEvent(kind="tenants.seeded", detail=f"{len(real)} customers", actor="system"))
        await db.commit()


async def seed_team() -> None:
    """Create the real SOC team if they are not present yet. Idempotent: skips a
    username that already exists. Temporary password; each must change it."""
    from .security.passwords import hash_password
    from .rbac import Capability
    ANALYST = "l1_analyst"
    team = [
        # analysts (list 43), scoped to the customers they cover
        ("analyst1", "Analyst One", ANALYST, "analysts", "L1", ["umbrella_co", "initech"], []),
        ("analyst2", "Analyst Two", ANALYST, "analysts", "L1", ["umbrella_co", "initech", "hooli_media"], []),
        ("analyst3", "Analyst Three", ANALYST, "analysts", "L1", ["globex_co", "acme_corp"], []),
        ("analyst4", "Analyst Four", ANALYST, "analysts", "L1", ["globex_co", "acme_corp"], []),
        ("analyst5", "Analyst Five", ANALYST, "analysts", "L1", ["umbrella_co", "hooli_media"], []),
        ("analyst6", "Analyst Six", ANALYST, "analysts", "L1", ["initech", "globex_co"], []),
        # shift lead
        ("lead1", "Shift Lead", "shift_lead", "analysts", "Shift lead", [], [Capability.publish_analyst_rota.value]),
        # security engineers (cross-tenant by role)
        ("engineer1", "Engineer One", "soc_engineer", "engineers", "Senior engineer", [], [Capability.publish_engineer_rota.value]),
        ("engineer2", "Engineer Two", "soc_engineer", "engineers", "Engineer", [], []),
        ("engineer3", "Engineer Three", "soc_engineer", "engineers", "Engineer", [], []),
        ("engineer4", "Engineer Four", "soc_engineer", "engineers", "Engineer", [], []),
    ]
    async with SessionLocal() as db:
        for u, name, role, tm, grade, scope, grants in team:
            exists = (await db.execute(select(User).where(User.username == u))).scalar_one_or_none()
            if exists:
                continue
            db.add(User(username=u, full_name=name, email=f"{u}@soc.example", role=role, team=tm,
                        grade=grade, grants=grants, allowed_customer_ids=scope,
                        password_hash=hash_password("changeme-temp"),
                        must_change_password=True, state="active", created_by="system"))
        await db.commit()
