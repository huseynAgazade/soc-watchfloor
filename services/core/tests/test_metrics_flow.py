"""Integration test for the live-metrics endpoints + web serving, in-process.
The mcp-soar connector is stubbed (its live behaviour is proven in mcp-soar's own
test); here we prove auth, tenant scope, RBAC and shaping around it."""
import asyncio
import os
import sys

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_metrics.db"
os.environ["WEB_DIR"] = "../../prototype"
if os.path.exists("test_metrics.db"):
    os.remove("test_metrics.db")
sys.path.insert(0, ".")

import httpx  # noqa: E402

from app.connectors import soar  # noqa: E402
from app.db import init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.seed import seed_admin  # noqa: E402

# --- stub the connector (live path proven in services/mcp-soar/test_live.py) ---
_SLA = [
    {"customer": "umbrella_co", "cases": 147, "MTTA": 45, "MTTT": 70, "MTTR": 987, "MTTTres": 3591, "MTTCR": 2234,
     "compliance_MTTA": 100, "compliance_MTTT": 98.6, "compliance_MTTR": 98.6, "compliance_MTTCR": 100},
    {"customer": "initech", "cases": 88, "MTTA": 15, "MTTT": 14, "MTTR": 4483, "MTTTres": 6395, "MTTCR": 1812,
     "compliance_MTTA": 100, "compliance_MTTT": 100, "compliance_MTTR": 93.2, "compliance_MTTCR": 100},
    {"customer": "globex_co", "cases": 39, "MTTA": 41, "MTTT": 61, "MTTR": 839, "MTTTres": 34865, "MTTCR": 28663,
     "compliance_MTTA": 100, "compliance_MTTT": 100, "compliance_MTTR": 100, "compliance_MTTCR": 100},
]
_L1 = [{"analyst": "analyst6", "cases": 157, "triage_p50": 22, "MTTA": 23, "MTTR": 1743, "MTTTres": 10115, "triage_sla": 100}]

async def _sla(window, tenant): return list(_SLA)
async def _l1(window): return list(_L1)
soar.sla_by_customer = _sla
soar.analyst_performance = _l1

passed = failed = 0
def check(name, cond):
    global passed, failed
    passed += cond; failed += (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name)


async def mk_user(admin, username, role, scope, grants=None):
    return await admin.post("/admin/users", json={
        "username": username, "full_name": username, "role": role,
        "allowed_customer_ids": scope, "grants": grants or [],
        "temporary_password": "temp-pass-1234", "require_otp": False})


async def main():
    await init_db(); await seed_admin()
    tr = httpx.ASGITransport(app=app)

    # unauthenticated
    async with httpx.AsyncClient(transport=tr, base_url="http://t") as anon:
        check("SLA needs auth (401)", (await anon.get("/api/metrics/sla")).status_code == 401)
        check("GET /login serves page", (await anon.get("/login")).status_code == 200)
        idx = await anon.get("/")
        check("GET / serves portal html", idx.status_code == 200 and "SOC Watchfloor" in idx.text)

    async with httpx.AsyncClient(transport=tr, base_url="http://t") as admin:
        await admin.post("/auth/login", json={"username": "admin", "password": "changeme-admin-1234"})
        r = await admin.get("/api/metrics/sla")
        check("admin SLA 200", r.status_code == 200)
        check("admin sees all 3 customers", len(r.json()["rows"]) == 3)
        check("admin L1 200 (has team perf)", (await admin.get("/api/metrics/l1")).status_code == 200)
        await mk_user(admin, "e.mammadov", "l1_analyst", ["umbrella_co", "initech"])
        await mk_user(admin, "lead1", "shift_lead", [])

    async with httpx.AsyncClient(transport=tr, base_url="http://t") as l1:
        await l1.post("/auth/login", json={"username": "e.mammadov", "password": "temp-pass-1234"})
        rows = (await l1.get("/api/metrics/sla")).json()["rows"]
        check("L1 scope filters SLA to its 2 tenants",
              {r["customer"] for r in rows} == {"umbrella_co", "initech"})
        check("L1 blocked from /l1 (403, no team perf)", (await l1.get("/api/metrics/l1")).status_code == 403)

    async with httpx.AsyncClient(transport=tr, base_url="http://t") as lead:
        await lead.post("/auth/login", json={"username": "lead1", "password": "temp-pass-1234"})
        check("shift_lead sees all SLA rows", len((await lead.get("/api/metrics/sla")).json()["rows"]) == 3)
        check("shift_lead L1 200", (await lead.get("/api/metrics/l1")).status_code == 200)

    print(f"\n>>> RESULT: {passed} passed, {failed} failed")


asyncio.run(main())
