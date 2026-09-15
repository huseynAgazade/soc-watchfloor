"""End-to-end auth + RBAC test, run in-process (no network socket).
Proves: seeded admin login, /me capabilities, only an admin creates accounts and
sets their password (policy-checked), first-login password change, RBAC denial,
tenant scope, lockout."""
import asyncio
import os
import sys

ADMIN_PW = "Admin-Test-Password-2026"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test.db"
os.environ["SEED_ADMIN_PASSWORD"] = ADMIN_PW
if os.path.exists("test.db"):
    os.remove("test.db")
sys.path.insert(0, ".")

import httpx  # noqa: E402

from app.db import init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.seed import seed_admin, seed_tenants  # noqa: E402

passed = 0
failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS  " + name)
    else:
        failed += 1
        print("  FAIL  " + name)


async def main():
    await init_db()
    await seed_admin()
    await seed_tenants()
    tr = httpx.ASGITransport(app=app)
    body = {"username": "analyst7", "full_name": "E. Scott", "role": "l1_analyst",
            "team": "analysts", "grade": "L1", "allowed_customer_ids": ["umbrella_co", "initech"],
            "require_otp": False}

    async with httpx.AsyncClient(transport=tr, base_url="http://t") as admin:
        r = await admin.post("/auth/login", json={"username": "admin", "password": ADMIN_PW})
        check("admin login 200", r.status_code == 200)
        check("env-provided admin password is not force-changed", r.json().get("must_change_password") is False)
        me = (await admin.get("/auth/me")).json()
        check("admin role soc_manager", me["role"] == "soc_manager")
        check("admin all_tenants", me["all_tenants"] is True)
        check("admin has manage_users", "manage_users" in me["capabilities"])
        rm = (await admin.get("/admin/users/roles/matrix")).json()
        check("role matrix has 6 roles", len(rm["roles"]) == 6)
        check("l1 lacks manage_users in matrix", "manage_users" not in rm["matrix"]["l1_analyst"])
        r = await admin.post("/admin/users", json={**body, "temporary_password": "short-pass"})
        check("admin-set password below 14 chars rejected (422)", r.status_code == 422)
        r = await admin.post("/admin/users", json={**body, "temporary_password": "changeme-temp"})
        check("publicly leaked password rejected (422)", r.status_code == 422)
        r = await admin.post("/admin/users", json={**body, "temporary_password": "temp-pass-1234"})
        check("create user 201", r.status_code == 201)
        u = r.json()
        check("new user scoped (not all)",
              u["all_tenants"] is False and u["allowed_customer_ids"] == ["umbrella_co", "initech"])
        check("new user pending", u["state"] == "pending")
        check("2 users listed", len((await admin.get("/admin/users")).json()) == 2)

    async with httpx.AsyncClient(transport=tr, base_url="http://t") as l1:
        r = await l1.post("/auth/login", json={"username": "analyst7", "password": "temp-pass-1234"})
        check("l1 login 200", r.status_code == 200)
        check("l1 must change the admin-set password", r.json().get("must_change_password") is True)
        me = (await l1.get("/auth/me")).json()
        check("l1 role l1_analyst", me["role"] == "l1_analyst")
        check("l1 NOT all_tenants", me["all_tenants"] is False)
        check("l1 scope = its tenants", me["allowed_customer_ids"] == ["umbrella_co", "initech"])
        check("l1 has use_assistant", "use_assistant" in me["capabilities"])
        check("l1 lacks manage_users", "manage_users" not in me["capabilities"])
        check("l1 blocked from /admin/users (403)", (await l1.get("/admin/users")).status_code == 403)
        check("l1 cannot create accounts (403)",
              (await l1.post("/admin/users", json={**body, "username": "x.y",
                                                   "temporary_password": "another-pass-1234"})).status_code == 403)
        check("before changing: data blocked (403)", (await l1.get("/admin/tenants")).status_code == 403)
        check("GET / sends a must-change session to the change form",
              (await l1.get("/")).headers.get("location") == "/login?change=1")
        r = await l1.post("/auth/change-password",
                          json={"current_password": "temp-pass-1234", "new_password": "temp-pass-1234"})
        check("new password must differ from the current one (400)", r.status_code == 400)
        r = await l1.post("/auth/change-password",
                          json={"current_password": "temp-pass-1234", "new_password": "a-brand-new-strong-pass"})
        check("password change ok", r.status_code == 200)
        check("must_change cleared", (await l1.get("/auth/me")).json()["must_change_password"] is False)
        check("after changing: data allowed (200)", (await l1.get("/admin/tenants")).status_code == 200)

    async with httpx.AsyncClient(transport=tr, base_url="http://t") as bad:
        codes = [(await bad.post("/auth/login", json={"username": "analyst7", "password": "wrong"})).status_code
                 for _ in range(6)]
        check("wrong password 401", codes[0] == 401)
        check("locks after threshold (423 seen)", 423 in codes)

    print(f"\n>>> RESULT: {passed} passed, {failed} failed")


asyncio.run(main())
