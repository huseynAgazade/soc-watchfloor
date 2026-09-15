"""Authorization proxy — the security boundary between the model and SOAR.

Every tool call the model proposes passes through here first:
  1. the tool must be in the caller's role allowlist (fail-closed);
  2. arguments are validated against the tool's schema — unknown/injected keys
     are dropped, so a prompt-injected extra argument cannot smuggle scope;
  3. tenant (customer-label) scope is enforced server-side from the session, not
     trusted from the model. A list call must name one of the caller's labels;
     a by-id call is allowed only after the container's label is read from the
     structured SOAR record (never from free text a case name could spoof) and
     found in the caller's scope.
The MCP server itself stays read-only and private; this is what makes it safe to
put a language model in front of it.
"""
from __future__ import annotations

import json
import os

import httpx
from sqlalchemy import select

from ..db import SessionLocal
from ..deps import all_tenants
from ..models import Tenant, User
from ..rbac import Role
from . import policy, watchfloor

BRIDGE = os.environ.get("SOAR_CHAT_BRIDGE_URL", "http://mcp-soar-chat:9011").rstrip("/")
_TIMEOUT = float(os.environ.get("SOAR_CHAT_TIMEOUT", "40"))
_catalogue: dict | None = None


class Denied(Exception):
    """A refused tool call. `kind` is role | scope | args | exec, for the audit trail."""

    def __init__(self, message: str, kind: str = "role"):
        super().__init__(message)
        self.kind = kind


async def _bridge_tools() -> dict:
    global _catalogue
    if _catalogue is None:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{BRIDGE}/tools")
        r.raise_for_status()
        _catalogue = {t["name"]: t for t in r.json()["tools"]}
    return _catalogue


async def _bridge_exec(name: str, args: dict) -> tuple[bool, str]:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.post(f"{BRIDGE}/call", json={"name": name, "arguments": args})
    if r.status_code != 200:
        raise Denied(f"tool execution failed ({r.status_code})", "exec")
    d = r.json()
    return bool(d.get("ok", True)), d.get("text", "")


async def _bridge_call(name: str, args: dict) -> str:
    return (await _bridge_exec(name, args))[1]


def _role(user: User) -> Role:
    try:
        return Role(user.role)
    except ValueError:
        return Role.read_only


async def scope_labels(user: User) -> set[str]:
    """The SOAR container labels a scoped user may reach: the label (join key) of
    each tenant in their scope, read from the tenant table."""
    ids = set(user.allowed_customer_ids or [])
    if not ids:
        return set()
    async with SessionLocal() as db:
        rows = (await db.execute(select(Tenant).where(Tenant.id.in_(ids)))).scalars().all()
    return {t.label or t.id for t in rows}


async def tools_for(user: User) -> list[dict]:
    """The tool schemas this user may use — what the model is shown: the SOAR
    tools their role allows (when the bridge is reachable) plus Watchfloor's own."""
    allowed = policy.allowed_tools(_role(user))
    if not all_tenants(user):
        allowed -= policy.SCOPE_UNRESOLVABLE       # scoped users never get unresolvable tools
    try:
        cat = await _bridge_tools()
    except httpx.HTTPError:
        cat = {}                                   # SOAR bridge down — Watchfloor tools still work
    return [cat[n] for n in sorted(allowed) if n in cat] + watchfloor.tools_for(user)


async def execute(user: User, name: str, args: dict, labels: set[str] | None = None) -> tuple[str, dict | None]:
    """Run one tool call: (text for the model, structured preview for the UI)."""
    if watchfloor.is_watchfloor(name):
        try:
            return await watchfloor.run(user, name, args or {})
        except watchfloor.ToolDenied as e:
            raise Denied(str(e), e.kind)
    return await run(user, name, args, labels=labels), None


def _validate_args(name: str, args: dict, cat: dict) -> dict:
    schema = (cat.get(name) or {}).get("input_schema") or {}
    props = set((schema.get("properties") or {}).keys())
    if not props:
        return dict(args or {})
    return {k: v for k, v in (args or {}).items() if k in props}   # drop unknown/injected keys


def _container_id(args: dict) -> int:
    raw = args.get("container_id")
    if isinstance(raw, bool) or raw is None:
        raise Denied("A numeric container id is required.", "args")
    try:
        cid = int(str(raw).strip())
    except ValueError:
        raise Denied("A numeric container id is required.", "args")
    if cid <= 0:
        raise Denied("A numeric container id is required.", "args")
    return cid


def container_label(record_text: str) -> str | None:
    """The label from soar_get_container's JSON output, or None if it is not a
    well-formed container record."""
    try:
        record = json.loads(record_text)
    except ValueError:
        return None
    if not isinstance(record, dict):
        return None
    label = record.get("label")
    return label if isinstance(label, str) and label else None


async def run(user: User, name: str, args: dict, labels: set[str] | None = None) -> str:
    """Execute one tool call for `user`, or raise Denied. `labels` is the caller's
    label scope when already resolved (the chat resolves it once per question)."""
    role = _role(user)
    allowed = policy.allowed_tools(role)
    cat = await _bridge_tools()

    if name not in allowed:
        raise Denied(f"'{name}' is not permitted for the {role.value} role.", "role")
    args = _validate_args(name, args, cat)

    # all-tenants callers (cross-tenant roles) — no customer-label restriction
    if all_tenants(user):
        return await _bridge_call(name, args)

    if labels is None:
        labels = await scope_labels(user)
    if name in policy.SCOPE_UNRESOLVABLE:
        raise Denied("This tool is not available to a tenant-scoped account.", "scope")

    if name in policy.LABEL_LIST_TOOLS:
        label = args.get("label")
        if not label:
            raise Denied("Specify a customer. Yours are: " + (", ".join(sorted(labels)) or "none") + ".", "args")
        if not isinstance(label, str) or label not in labels:
            raise Denied("That customer is outside your scope.", "scope")
        return await _bridge_call(name, args)

    if name in policy.CONTAINER_ID_TOOLS:
        cid = _container_id(args)
        args["container_id"] = cid      # the id that was checked is the id that runs
        ok, record = await _bridge_exec("soar_get_container", {"container_id": cid, "as_json": True})
        label = container_label(record) if ok else None
        if label is None or label not in labels:
            # one answer for "missing" and "someone else's", so ids cannot be probed
            raise Denied("That case does not exist or is outside your customer scope.", "scope")
        if name == "soar_get_container" and args.get("as_json"):
            return record
        return await _bridge_call(name, args)

    # non-tenant tools (discovery, metadata) the role is allowed → pass through
    return await _bridge_call(name, args)
