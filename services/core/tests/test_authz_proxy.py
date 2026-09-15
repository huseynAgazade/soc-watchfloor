"""Authorization-proxy enforcement test (no LLM). Runs each check as a simulated
portal user against the live splunk-soar-mcp bridge, proving role-based tool
gating, tenant-label scoping on lists and on by-id case lookups, argument
sanitization and fail-closed refusals."""
import asyncio
import json
import os
import sys

os.environ.setdefault("SOAR_CHAT_BRIDGE_URL", "http://127.0.0.1:9011")
sys.path.insert(0, ".")

from app.assistant import proxy  # noqa: E402
from app.models import User  # noqa: E402

passed = failed = 0
def ok(name, cond, extra=""):
    global passed, failed
    passed += bool(cond); failed += (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  <<< " + str(extra)))


def mk(role, scope):
    # cross_tenant roles with empty scope = all tenants; scoped roles carry a list
    return User(username="t", full_name="t", role=role, allowed_customer_ids=scope, grants=[])


L1_LABELS = {"initech", "globex_co"}


async def denied(user, name, args, labels=None):
    try:
        await proxy.run(user, name, args, labels=labels); return None
    except proxy.Denied as e:
        return str(e)


async def first_container_id(manager, label):
    text = await proxy.run(manager, "soar_list_containers", {"label": label, "page_size": 1, "as_json": True})
    rows = json.loads(text)
    return rows[0]["id"] if rows else None


async def main():
    manager = mk("soc_manager", [])
    l1 = mk("l1_analyst", sorted(L1_LABELS))
    readonly = mk("read_only", ["umbrella_co"])

    # 1. role-based tool catalogue
    mtools = {t["name"] for t in await proxy.tools_for(manager)}
    l1tools = {t["name"] for t in await proxy.tools_for(l1)}
    ok("manager sees far more tools than L1", len(mtools) > len(l1tools), f"{len(mtools)} vs {len(l1tools)}")
    ok("L1 is NOT offered admin/user tools", "soar_list_users" not in l1tools and "soar_get_system_settings" not in l1tools)
    ok("L1 is NOT offered raw REST", "soar_rest_get" not in l1tools)
    ok("manager IS offered admin + raw", "soar_list_users" in mtools and "soar_rest_get" in mtools)
    ok("L1 (scoped) is NOT offered get_artifact (unresolvable scope)", "soar_get_artifact" not in l1tools)

    # 2. fail-closed: calling a tool outside the role is refused even if invoked directly
    ok("L1 calling soar_list_users is DENIED", await denied(l1, "soar_list_users", {}, L1_LABELS) is not None)
    ok("readonly calling soar_get_system_settings is DENIED",
       await denied(readonly, "soar_get_system_settings", {}, {"umbrella_co"}) is not None)

    # 3. tenant scope on list: scoped user must name an in-scope customer
    d = await denied(l1, "soar_list_containers", {}, L1_LABELS)
    ok("L1 list_containers with no label is DENIED (must name a customer)", d is not None and "customer" in d.lower())
    d2 = await denied(l1, "soar_list_containers", {"label": "acme_corp"}, L1_LABELS)
    ok("L1 list_containers for an out-of-scope customer is DENIED", d2 is not None and "scope" in d2.lower())
    try:
        res = await proxy.run(l1, "soar_list_containers", {"label": "initech", "page_size": 2}, labels=L1_LABELS)
        ok("L1 list_containers for an IN-scope customer works", isinstance(res, str))
    except proxy.Denied as e:
        ok("L1 list_containers for an IN-scope customer works", False, e)

    # 4. by-id case lookups: label resolved from the real SOAR record
    mine = await first_container_id(manager, "initech")
    theirs = await first_container_id(manager, "acme_corp")
    if mine:
        try:
            out = await proxy.run(l1, "soar_get_container", {"container_id": mine}, labels=L1_LABELS)
            ok("L1 reads an in-scope case by id", "initech" in out, out[:200])
        except proxy.Denied as e:
            ok("L1 reads an in-scope case by id", False, e)
    if theirs:
        ok("L1 is DENIED another customer's case by id",
           await denied(l1, "soar_get_container", {"container_id": theirs}, L1_LABELS) is not None)
        ok("L1 is DENIED another customer's case notes by id",
           await denied(l1, "soar_list_notes", {"container_id": theirs}, L1_LABELS) is not None)
    ok("L1 is DENIED a non-existent case id (same refusal)",
       await denied(l1, "soar_get_container", {"container_id": 999999999}, L1_LABELS) is not None)

    # 5. argument sanitization — injected extra args are dropped
    cat = await proxy._bridge_tools()
    cleaned = proxy._validate_args("soar_list_containers", {"label": "initech", "evil": "x", "page_size": 1}, cat)
    ok("injected 'evil' arg is stripped before execution", "evil" not in cleaned and "label" in cleaned)

    # 6. manager (all tenants) can list any customer
    try:
        await proxy.run(manager, "soar_list_containers", {"label": "acme_corp", "page_size": 1})
        ok("manager can list any customer", True)
    except proxy.Denied as e:
        ok("manager can list any customer", False, e)

    print(f"\n===== {passed} passed, {failed} failed =====")

asyncio.run(main())
