"""Editable role -> capability matrix. Admin-only (manage_roles capability, which
only the manager role holds). The manager row is locked to all capabilities so
the editor can never lock everyone out; the two rota-publishing capabilities are
per-user grants, not role capabilities, so they are not editable here.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db  # noqa: F401  (kept for symmetry / future use)
from ..deps import require_capability
from ..models import AuditEvent, User
from ..rbac import (GRANTABLE, LOCKED_ROLE, MANAGER_ONLY, Capability, Role,
                    current_matrix)
from ..roles_store import save_role

router = APIRouter()
_admin = require_capability(Capability.manage_roles)

# Human labels for the capabilities the matrix exposes (mirrors the UI wording).
CAP_LABEL = {
    Capability.view_dashboards: "View dashboards inside tenant scope",
    Capability.use_assistant: "Use the assistant (read-only tools)",
    Capability.view_own_performance: "View own performance",
    Capability.view_team_performance: "View the whole team's performance",
    Capability.approve_absences: "Approve absences for own team",
    Capability.edit_detection: "Edit detection rules and ATT&CK mappings",
    Capability.approve_reports: "Approve customer-facing SLA reports",
    Capability.cross_tenant: "Cross-tenant scope",
    Capability.edit_data_sources: "Edit data-source queries (SPL)",
    Capability.manage_users: "Create, edit and disable users",
    Capability.manage_tenants: "Create and archive tenants",
    Capability.manage_roles: "Edit the role matrix",
    Capability.change_auth_policy: "Change authentication policy",
    Capability.publish_analyst_rota: "Publish the SOC analyst rota",
    Capability.publish_engineer_rota: "Publish the security engineer rota",
}


def _editable_caps() -> list[Capability]:
    # everything except the per-user grants and the manager-only keys
    return [c for c in Capability if c not in GRANTABLE and c not in MANAGER_ONLY]


@router.get("")
async def get_roles(admin: User = Depends(_admin)) -> dict:
    matrix = current_matrix()
    return {
        "roles": [r.value for r in Role],
        "locked_role": LOCKED_ROLE.value,
        "editable_capabilities": [{"id": c.value, "label": CAP_LABEL.get(c, c.value)}
                                  for c in _editable_caps()],
        "manager_only": [c.value for c in MANAGER_ONLY],
        "grants": [{"id": c.value, "label": CAP_LABEL.get(c, c.value)} for c in GRANTABLE],
        "matrix": {r.value: sorted(c.value for c in caps) for r, caps in matrix.items()},
    }


@router.patch("/{role}")
async def set_role(role: str, capabilities: list[str] = Body(..., embed=True),
                   admin: User = Depends(_admin)) -> dict:
    try:
        r = Role(role)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown role: {role}")
    if r == LOCKED_ROLE:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "the manager role is the superuser and cannot be edited")
    allowed = {c.value for c in _editable_caps()}
    caps = [c for c in capabilities if c in allowed]   # ignore grants / manager-only / unknown
    await save_role(r.value, caps, admin.username)
    from ..db import SessionLocal
    async with SessionLocal() as db:
        db.add(AuditEvent(kind="role.changed", detail=f"{r.value}: {len(caps)} caps · by {admin.username}",
                          actor=admin.username))
        await db.commit()
    return {"ok": True, "role": r.value, "capabilities": caps}
