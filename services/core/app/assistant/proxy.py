"""Authorization proxy — the security boundary between the model and SOAR.

Every tool call the model proposes passes through here first:
  1. the tool must be in the caller's role allowlist (fail-closed);
  2. arguments are validated against the tool's schema — unknown/injected keys
     are dropped, so a prompt-injected extra argument cannot smuggle scope;
  3. tenant (customer-label) scope is enforced server-side from the session, not
     trusted from the model — a scoped analyst can only reach their customers'
     cases, and label-bearing arguments are validated or the container's label is
     resolved and checked before any data is returned.
The MCP server itself stays read-only and private; this is what makes it safe to
put a language model in front of it.
"""
from __future__ import annotations

import os
import re

import httpx

from ..deps import all_tenants
from ..models import User
from ..rbac import Role
from . import policy

BRIDGE = os.environ.get("SOAR_CHAT_BRIDGE_URL", "http://mcp-soar-chat:9011").rstrip("/")
_TIMEOUT = float(os.environ.get("SOAR_CHAT_TIMEOUT", "40"))
_catalogue: dict | None = None


class Denied(Exception):
    pass


async def _bridge_tools() -> dict:
    global _catalogue
    if _catalogue is None:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{BRIDGE}/tools")
        r.raise_for_status()
        _catalogue = {t["name"]: t for t in r.json()["tools"]}
    return _catalogue


async def _bridge_call(name: str, args: dict) -> str:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.post(f"{BRIDGE}/call", json={"name": name, "arguments": args})
    if r.status_code != 200:
        raise Denied(f"tool execution failed ({r.status_code})")
    d = r.json()
    return d.get("text", "")


def _role(user: User) -> Role:
    try:
        return Role(user.role)
    except ValueError:
        return Role.read_only


async def tools_for(user: User) -> list[dict]:
    """The tool schemas this user's role may use — what the model is shown."""
    allowed = policy.allowed_tools(_role(user))
    if not all_tenants(user):
        allowed -= policy.SCOPE_UNRESOLVABLE       # scoped users never get unresolvable tools
    cat = await _bridge_tools()
    return [cat[n] for n in sorted(allowed) if n in cat]


def _validate_args(name: str, args: dict, cat: dict) -> dict:
    schema = (cat.get(name) or {}).get("input_schema") or {}
    props = set((schema.get("properties") or {}).keys())
    if not props:
        return dict(args or {})
    return {k: v for k, v in (args or {}).items() if k in props}   # drop unknown/injected keys


_LABEL_RE = re.compile(r"\blabel\b\s*[:=]?\s*([A-Za-z0-9_\-]+)")


async def run(user: User, name: str, args: dict) -> str:
    role = _role(user)
    allowed = policy.allowed_tools(role)
    cat = await _bridge_tools()

    if name not in allowed:
        raise Denied(f"'{name}' is not permitted for the {role.value} role.")
    args = _validate_args(name, args, cat)

    # all-tenants callers (cross-tenant roles) — no customer-label restriction
    if all_tenants(user):
        return await _bridge_call(name, args)

    scope = set(user.allowed_customer_ids or [])
    if name in policy.SCOPE_UNRESOLVABLE:
        raise Denied("This tool is not available to a tenant-scoped account.")

    if name in policy.LABEL_LIST_TOOLS:
        label = args.get("label")
        if not label:
            raise Denied("Specify a customer. Yours are: " + ", ".join(sorted(scope)) + ".")
        if label not in scope:
            raise Denied("That customer is outside your scope.")
        return await _bridge_call(name, args)

    if name in policy.CONTAINER_ID_TOOLS:
        cid = args.get("container_id") or args.get("container") or args.get("id")
        if not cid:
            raise Denied("A container id is required.")
        # resolve the container's label server-side and check scope before returning data
        info = await _bridge_call("soar_get_container", {"container_id": cid})
        m = _LABEL_RE.search(info)
        label = m.group(1) if m else None
        if label is None or label not in scope:
            raise Denied("That case is outside your customer scope.")
        return info if name == "soar_get_container" else await _bridge_call(name, args)

    # non-tenant tools (discovery, metadata) the role is allowed → pass through
    return await _bridge_call(name, args)
