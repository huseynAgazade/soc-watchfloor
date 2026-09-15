"""First-run data: the initial admin and the tenant rows. Idempotent.

Accounts other than the initial admin are never seeded — an admin creates every
account and sets its password (Users tab / POST /admin/users)."""
from __future__ import annotations

import secrets
import sys

from sqlalchemy import select

from .audit import event
from .config import settings
from .db import SessionLocal
from .models import User
from .rbac import Capability, Role
from .security.passwords import hash_password, verify_password
from .security.policy import (COMMITTED_ADMIN_PASSWORDS, KNOWN_LEAKED,
                              SHARED_TEMP_PASSWORDS)
from .security.sessions import revoke_sessions


async def seed_admin() -> None:
    async with SessionLocal() as db:
        any_user = (await db.execute(select(User).limit(1))).scalar_one_or_none()
        if any_user:
            return
        password = settings.seed_admin_password
        generated = not password or password in KNOWN_LEAKED
        if generated:
            password = secrets.token_urlsafe(18)
        admin = User(
            username=settings.seed_admin_username,
            full_name="Initial Administrator",
            email=settings.seed_admin_email,
            role=Role.soc_manager.value, team="mgmt", grade="Manager",
            grants=[Capability.publish_analyst_rota.value, Capability.publish_engineer_rota.value],
            allowed_customer_ids=[],  # empty + cross_tenant(manager) = all tenants
            password_hash=hash_password(password),
            must_change_password=generated, state="active", created_by="system",
        )
        db.add(admin)
        db.add(event("user.seeded", admin.username + (" · generated password" if generated else ""), "system"))
        await db.commit()
    if generated:
        print(f"\n*** SOC Watchfloor: initial admin '{settings.seed_admin_username}' created with a "
              f"generated password: {password}\n*** It must be changed at first sign-in.\n",
              file=sys.stderr, flush=True)


async def seed_tenants() -> None:
    """Seeds the built-in tenants once per database. After that an empty tenant
    table stays empty — tenants cleared on purpose are not brought back."""
    from .models import AuditEvent, Tenant
    async with SessionLocal() as db:
        any_t = (await db.execute(select(Tenant).limit(1))).scalar_one_or_none()
        seeded = (await db.execute(select(AuditEvent.id).where(
            AuditEvent.kind.in_(("tenants.seeded", "tenants.reset"))).limit(1))).first()
        if any_t or seeded:
            return
        real = [
            ("umbrella_co", "Umbrella Co", "Managed detection", ["sla", "mitre", "rules", "agentic"], "2024-02-11"),
            ("initech", "Initech", "Managed detection", ["sla", "mitre", "rules", "agentic"], "2023-09-04"),
            ("hooli_media", "Hooli Media", "Monitoring only", ["sla", "rules"], "2026-05-19"),
            ("acme_corp", "Acme Corp", "Managed detection + IR", ["sla", "mitre", "rules", "agentic"], "2024-11-25"),
            ("globex_co", "Globex", "Managed detection + IR", ["sla", "mitre", "rules", "agentic"], "2025-01-13"),
        ]
        for cid, name, tier, mods, since in real:
            db.add(Tenant(id=cid, name=name, label=cid, tier=tier, modules=mods,
                          onboarded=since, state="active", created_by="system"))
        db.add(event("tenants.seeded", f"{len(real)} customers", "system"))
        await db.commit()


_SWEEP_KIND = "security.leaked_pw_sweep"


async def retire_leaked_passwords() -> None:
    """One-time sweep per database. Earlier builds seeded the team with one shared
    temporary password and committed the admin password to the repo:
      * an account still on the shared temporary password loses it — it cannot
        sign in until an admin sets a new password;
      * an account still on a committed admin password must change it at its
        next sign-in.
    Their sessions are revoked. The outcome is written to the audit trail."""
    async with SessionLocal() as db:
        from .models import AuditEvent
        done = (await db.execute(select(AuditEvent.id).where(AuditEvent.kind == _SWEEP_KIND).limit(1))).first()
        if done:
            return
        retired, forced = [], []
        for u in (await db.execute(select(User))).scalars().all():
            if not u.password_hash:
                continue
            if any(verify_password(u.password_hash, p) for p in SHARED_TEMP_PASSWORDS):
                u.password_hash = ""
                u.must_change_password = True
                if u.state == "active":
                    u.state = "pending"
                retired.append(u.username)
                await revoke_sessions(db, u.id)
            elif any(verify_password(u.password_hash, p) for p in COMMITTED_ADMIN_PASSWORDS):
                u.must_change_password = True
                forced.append(u.username)
                await revoke_sessions(db, u.id)
        db.add(event(_SWEEP_KIND, f"password removed: {', '.join(retired) or 'none'} · "
                                  f"must change: {', '.join(forced) or 'none'}", "system"))
        await db.commit()
    if retired or forced:
        print(f"*** SOC Watchfloor: leaked-password sweep — password removed (admin must set one): "
              f"{', '.join(retired) or 'none'}; must change at next sign-in: {', '.join(forced) or 'none'}",
              file=sys.stderr, flush=True)
