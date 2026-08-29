"""Roles, capabilities and tenant scope — the authorization model.

Enforced server-side in every request (see deps.py). A role grants a base set of
capabilities; two rota-publishing capabilities are *per-user grants* on top,
because the analyst and engineer rotas belong to two different teams and holding
one must never imply the other. Mirrors the role matrix in the prototype UI.
"""
from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    read_only = "read_only"
    l1_analyst = "l1_analyst"
    l2_analyst = "l2_analyst"
    shift_lead = "shift_lead"
    soc_engineer = "soc_engineer"
    soc_manager = "soc_manager"


class Capability(StrEnum):
    view_dashboards = "view_dashboards"          # dashboards inside tenant scope
    use_assistant = "use_assistant"              # the read-only chat tools
    view_own_performance = "view_own_performance"
    view_team_performance = "view_team_performance"
    publish_analyst_rota = "publish_analyst_rota"   # grant, not implied by role
    publish_engineer_rota = "publish_engineer_rota" # grant, not implied by role
    approve_absences = "approve_absences"
    edit_detection = "edit_detection"            # rules + ATT&CK mappings
    approve_reports = "approve_reports"           # customer-facing SLA reports
    cross_tenant = "cross_tenant"                 # scope beyond a fixed list
    manage_users = "manage_users"
    manage_tenants = "manage_tenants"
    change_auth_policy = "change_auth_policy"
    edit_data_sources = "edit_data_sources"       # editable SPL / query catalog
    manage_roles = "manage_roles"                 # edit the role->capability matrix


# Base capabilities per role (rota grants handled separately, per-user).
ROLE_CAPABILITIES: dict[Role, set[Capability]] = {
    Role.read_only: {
        Capability.view_dashboards,
    },
    Role.l1_analyst: {
        Capability.view_dashboards, Capability.use_assistant,
        Capability.view_own_performance,
    },
    Role.l2_analyst: {
        Capability.view_dashboards, Capability.use_assistant,
        Capability.view_own_performance,
    },
    Role.shift_lead: {
        Capability.view_dashboards, Capability.use_assistant,
        Capability.view_own_performance, Capability.view_team_performance,
        Capability.approve_absences, Capability.cross_tenant,
    },
    Role.soc_engineer: {
        Capability.view_dashboards, Capability.use_assistant,
        Capability.view_own_performance, Capability.view_team_performance,
        Capability.approve_absences, Capability.edit_detection,
        Capability.cross_tenant,
    },
    Role.soc_manager: set(Capability),  # everything
}

# Which rota grant each role is created with by default (still stored per-user).
DEFAULT_ROTA_GRANTS: dict[Role, set[Capability]] = {
    Role.shift_lead: {Capability.publish_analyst_rota},
    Role.soc_engineer: {Capability.publish_engineer_rota},
    Role.soc_manager: {Capability.publish_analyst_rota, Capability.publish_engineer_rota},
}

# Grants an admin may toggle on a user, over and above the role.
GRANTABLE = {Capability.publish_analyst_rota, Capability.publish_engineer_rota}

# The manager role is the superuser: it always holds every capability and its
# row is not editable, so the matrix editor can never lock everyone out.
LOCKED_ROLE = Role.soc_manager
# Capabilities that only ever belong to the manager and are not offered per-role.
MANAGER_ONLY = {Capability.manage_users, Capability.manage_tenants,
                Capability.manage_roles, Capability.change_auth_policy}

# Runtime overlay: when loaded from the DB it replaces the defaults below for the
# non-locked roles. None => use the hardcoded defaults.
_OVERRIDE: dict = {}


def set_override(matrix: dict) -> None:
    """matrix: {role_value: set/list of capability_value}. Manager stays full."""
    global _OVERRIDE
    clean = {}
    for role in Role:
        if role == LOCKED_ROLE:
            continue
        caps = matrix.get(role.value)
        if caps is None:
            continue
        valid = {Capability(c) for c in caps if c in set(Capability)}
        valid -= GRANTABLE            # rota publishing is a per-user grant, not a role cap
        valid -= MANAGER_ONLY         # never grantable to non-manager roles
        clean[role] = valid
    _OVERRIDE = clean


def current_matrix() -> dict:
    """The effective base capabilities per role (override if set, else defaults)."""
    out = {}
    for role in Role:
        if role == LOCKED_ROLE:
            out[role] = set(Capability)
        else:
            out[role] = set(_OVERRIDE.get(role, ROLE_CAPABILITIES.get(role, set())))
    return out


def effective_capabilities(role: Role, extra_grants: set[Capability]) -> set[Capability]:
    if role == LOCKED_ROLE:
        base = set(Capability)
    else:
        base = set(_OVERRIDE.get(role, ROLE_CAPABILITIES.get(role, set())))
    base |= (set(extra_grants) & GRANTABLE)
    return base


def has_capability(role: Role, extra_grants: set[Capability], cap: Capability) -> bool:
    return cap in effective_capabilities(role, extra_grants)
