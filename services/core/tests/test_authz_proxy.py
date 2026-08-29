"""Authorization-proxy enforcement test (no LLM). Runs each check as a simulated
portal user against the live splunk-soar-mcp bridge, proving role-based tool
gating, tenant-label scoping, argument sanitization and fail-closed refusals."""
import asyncio
import os
import sys

os.environ.setdefault("SOAR_CHAT_BRIDGE_URL", "http://127.0.0.1:9011")
sys.path.insert(0, ".")

from app.assistant import policy, proxy  # noqa: E402
from app.models import User  # noqa: E402

passed = failed = 0
def ok(name, cond, extra=""):
    global passed, failed
    passed += cond; failed += (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  <<< " + str(extra)))


def mk(role, scope):
    # cross_tenant roles with empty scope = all tenants; scoped roles carry a list
    return User(username="t", full_name="t", role=role, allowed_customer_ids=scope, grants=[])


async def denied(user, name, args):
    try:
        await proxy.run(user, name, args); return None
    except proxy.Denied as e:
        return str(e)


async def main():
    manager = mk("soc_manager", [])
    l1 = mk("l1_analyst", ["initech", "globex_co"])
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
    ok("L1 calling soar_list_users is DENIED", await denied(l1, "soar_list_users", {}) is not None)
    ok("readonly calling soar_get_system_settings is DENIED", await denied(readonly, "soar_get_system_settings", {}) is not None)

    # 3. tenant scope on list: scoped user must name an in-scope customer
    d = await denied(l1, "soar_list_containers", {})
    ok("L1 list_containers with no label is DENIED (must name a customer)", d is not None and "customer" in d.lower())
    d2 = await denied(l1, "soar_list_containers", {"label": "acme_corp"})   # not in L1's scope
    ok("L1 list_containers for an out-of-scope customer is DENIED", d2 is not None and "scope" in d2.lower())
    # in-scope label works
    try:
        res = await proxy.run(l1, "soar_list_containers", {"label": "initech", "page_size": 2})
        ok("L1 list_containers for an IN-scope customer works", isinstance(res, str))
    except proxy.Denied as e:
        ok("L1 list_containers for an IN-scope customer works", False, e)

    # 4. argument sanitization — injected extra args are dropped
    cat = await proxy._bridge_tools()
    cleaned = proxy._validate_args("soar_list_containers", {"label": "initech", "evil": "x", "page_size": 1}, cat)
    ok("injected 'evil' arg is stripped before execution", "evil" not in cleaned and "label" in cleaned)

    # 5. manager (all tenants) can list any customer
    try:
        await proxy.run(manager, "soar_list_containers", {"label": "acme_corp", "page_size": 1})
        ok("manager can list any customer", True)
    except proxy.Denied as e:
        ok("manager can list any customer", False, e)

    print(f"\n===== {passed} passed, {failed} failed =====")

asyncio.run(main())
