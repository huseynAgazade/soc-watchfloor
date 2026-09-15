"""Dashboard + data-catalog endpoints, in-process. Splunk is stubbed at the
connector (app.connectors.splunk.search), so the real catalog, token rendering,
scope rules, versioning and error mapping all run. Also checks the served page
carries no embedded snapshot data."""
import asyncio
import os
import sys

ADMIN_PW = "Admin-Test-Password-2026"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_metrics.db"
os.environ["WEB_DIR"] = "../../prototype"
os.environ["SEED_ADMIN_PASSWORD"] = ADMIN_PW
if os.path.exists("test_metrics.db"):
    os.remove("test_metrics.db")
sys.path.insert(0, ".")

import httpx  # noqa: E402

from app.connectors import detection as detection_conn  # noqa: E402
from app.connectors import splunk  # noqa: E402
from app.datasources import spl as spl_mod  # noqa: E402
from app.datasources.catalog import seed_data_queries  # noqa: E402
from app.db import SessionLocal, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import AuditEvent  # noqa: E402
from app.seed import seed_admin, seed_tenants  # noqa: E402
from sqlalchemy import select  # noqa: E402

# ---- Splunk stub: answers by query shape, records what it was sent ----
_SLA = [
    {"customer": "umbrella_co", "cases": "147", "breached": "3", "MTTA": "45", "MTTT": "70", "MTTR": "987", "MTTTres": "3591",
     "MTTCR": "2234", "compliance_all": "98.0", "compliance_MTTA": "100", "compliance_MTTT": "98.6",
     "compliance_MTTR": "98.6", "compliance_MTTCR": "100"},
    {"customer": "initech", "cases": "88", "breached": "6", "MTTA": "15", "MTTT": "14", "MTTR": "4483",
     "MTTTres": "6395", "MTTCR": "1812", "compliance_all": "93.2", "compliance_MTTA": "100", "compliance_MTTT": "100",
     "compliance_MTTR": "93.2", "compliance_MTTCR": "100"},
    {"customer": "globex_co", "cases": "39", "breached": "0", "MTTA": "41", "MTTT": "61", "MTTR": "839",
     "MTTTres": "34865", "MTTCR": "28663", "compliance_all": "100", "compliance_MTTA": "100", "compliance_MTTT": "100",
     "compliance_MTTR": "100", "compliance_MTTCR": "100"},
    {"customer": "events", "cases": "999", "breached": "0"},       # a label outside every scope
]
_MIX = [{"customer": "umbrella_co", "status": "closed", "count": "6"}, {"customer": "initech", "status": "closed", "count": "4"},
        {"customer": "globex_co", "status": "false positive", "count": "90"}]
sent = []

async def fake_search(spl, start, end, max_rows):
    sent.append({"spl": spl, "start": start, "end": end})
    if "sum(any_breach) as breached count as cases by label" in spl:
        return [dict(r) for r in _SLA], False
    if "stats count by label status" in spl:
        return [dict(r) for r in _MIX], False
    if "by sla_owner_name" in spl:
        return [{"analyst": "analyst6", "cases": "157", "triage_p50": "22", "triage_sla": "100"}], False
    if "by day label" in spl:
        return [{"day": "2026-09-10", "customer": "umbrella_co", "cases": "20", "breached": "1"}], False
    if "aisoc" in spl:
        return [{"incidents": "212"}], False
    return [{"x": "1"}], False

seen_tenants = []
async def _det(tenants=None):
    seen_tenants.append(tenants)
    return {"summary": {"all": {}}, "onboarded": sorted(tenants) if tenants is not None else ["umbrella_co", "initech"]}

async def _roster():
    return {"days": [], "month": "", "people": [{"u": "analyst7", "s": []}, {"u": "lead1", "s": []},
                                                {"u": "not.an.account", "s": []}]}

refresh_triggers = []
async def _det_status():
    return {"synced_at": "2026-09-15T02:00:00+00:00", "running": False, "ok": False, "error": "[globex] 401 unauthorized",
            "last_attempt_trigger": "schedule", "rules": {"globex": {"splunk": 3}}, "next_run_at": "2026-09-16T02:00:00+00:00"}

async def _det_refresh(trigger):
    refresh_triggers.append(trigger)
    return {"status": "started", "running": True, "running_since": "2026-09-15T09:00:00+00:00"}

splunk.search = fake_search
detection_conn.detection = _det
detection_conn.status = _det_status
detection_conn.refresh = _det_refresh
from app.connectors import roster as roster_conn  # noqa: E402
roster_conn.roster = _roster

passed = failed = 0
def check(name, cond, extra=""):
    global passed, failed
    passed += bool(cond); failed += (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else f"  <<< {extra}"))


async def mk_user(admin, username, role, scope, grants=None):
    return await admin.post("/admin/users", json={
        "username": username, "full_name": username, "role": role,
        "allowed_customer_ids": scope, "grants": grants or [],
        "temporary_password": "temp-pass-1234", "require_password_change": False, "require_otp": False})


async def main():
    await init_db(); await seed_admin(); await seed_tenants(); await seed_data_queries()
    tr = httpx.ASGITransport(app=app)

    # ---- token rendering ----
    fr = {"f.one": "| eval a=1 $include:f.two$", "f.two": "| eval b=$earliest$"}
    from datetime import datetime, timezone
    s, e = datetime(2026, 6, 15, tzinfo=timezone.utc), datetime(2026, 9, 14, tzinfo=timezone.utc)
    out = spl_mod.render('$soar_containers$ | search label IN ($tenant_labels$) $include:f.one$', fr, start=s, end=e,
                         tenant_ids=["a"], tenant_labels=["initech", 'bad" OR label=*'], soar_server="soc_soar")
    check("tokens render: sliced restsoar, fragments, epoch, quoted labels",
          out.count("| append [") == 6 and 'label IN ("initech")' in out and f"b={int(s.timestamp())}" in out)
    check("an unsafe label value is dropped, not quoted into the SPL", "OR label=*" not in out)
    check("fragment include cycles are refused",
          spl_mod.problems("$include:c.a$ $tenants$", {"c.a": "$include:c.b$", "c.b": "$include:c.a$"}) != [])
    check("writing commands are refused (also first command, any case)",
          all(spl_mod.problems(q, {}, "global") for q in ("index=x | OutputLookup a.csv", "delete index=x", "| makeresults | collect index=y")))

    async with httpx.AsyncClient(transport=tr, base_url="http://t") as anon:
        check("SLA needs auth (401)", (await anon.get("/api/metrics/sla")).status_code == 401)
        check("data catalog needs auth (401)", (await anon.get("/api/data/queries")).status_code == 401)
        idx = await anon.get("/")
        check("GET / redirects anonymous callers to /login", idx.status_code == 302 and idx.headers.get("location") == "/login")

    async with httpx.AsyncClient(transport=tr, base_url="http://t", timeout=30) as admin:
        await admin.post("/auth/login", json={"username": "admin", "password": ADMIN_PW})
        page = await admin.get("/")
        check("served portal has no snapshot data", page.status_code == 200 and "snapshot:" not in page.text
              and "engineer1@soc.example" not in page.text and "@every 0h10m" not in page.text)
        r = await admin.get("/api/metrics/sla?period=d30")
        rows = r.json()["rows"]
        check("admin SLA: the three known customers, the out-of-scope label filtered out",
              r.status_code == 200 and {x["customer"] for x in rows} == {"umbrella_co", "initech", "globex_co"}, rows)
        check("numbers come back typed", rows[0]["cases"] == 147 and isinstance(rows[0]["compliance_all"], float))
        check("the SOAR head filters to every tenant's label",
              'label IN ("acme_corp","globex_co","hooli_media","initech","umbrella_co")' in sent[-1]["spl"])
        check("d30 bounds reach the search, ~31 days", 30 <= (sent[-1]["end"] - sent[-1]["start"]).days <= 31)
        r = await admin.get("/api/metrics/sla?period=d7&tenant=initech")
        check("tenant=initech renders a single-label filter and returns that row",
              'label IN ("initech")' in sent[-1]["spl"] and [x["customer"] for x in r.json()["rows"]] == ["initech"])
        check("unknown period rejected (422)", (await admin.get("/api/metrics/sla?period=d365")).status_code == 422)
        check("custom range over 92 days rejected (422)",
              (await admin.get("/api/metrics/sla?period=custom&from=2026-01-01&to=2026-06-30")).status_code == 422)
        r = await admin.get("/api/metrics/l1?period=d7&tenant=globex_co")
        check("L1 for one tenant filters the SOAR head to that label",
              r.status_code == 200 and 'label IN ("globex_co")' in sent[-1]["spl"] and r.json()["rows"][0]["analyst"] == "analyst6")
        mix = (await admin.get("/api/metrics/status-mix")).json()["rows"]
        check("admin status mix aggregates every customer", sum(m["count"] for m in mix) == 100)
        check("status mix for one tenant", sum(m["count"] for m in (await admin.get("/api/metrics/status-mix?tenant=umbrella_co")).json()["rows"]) == 6)
        await admin.get("/api/metrics/detection")
        check("admin detection requested for all tenants", seen_tenants[-1] is None)
        st = (await admin.get("/api/metrics/detection/status")).json()
        check("detection sync status tells an admin the last sync, next run, failure text and rule counts",
              st["synced_at"] and st["next_run_at"] and st["can_refresh"] and "401" in st["error"] and st["rules"], st)
        r = await admin.post("/api/metrics/detection/refresh")
        check("an admin can start a detection refresh, tagged with their name",
              r.status_code == 200 and r.json()["status"] == "started" and refresh_triggers[-1].startswith("manual:"), r.text)
        async with SessionLocal() as db:
            kinds = [a.kind for a in (await db.execute(select(AuditEvent))).scalars().all()]
        check("a detection refresh is audited", "detection.refresh" in kinds)

        # ---- catalog + batch ----
        qs = (await admin.get("/api/data/queries")).json()
        ids = {q["id"] for q in qs}
        check("catalog lists SLA, L1, overview and agentic queries, not fragments",
              {"sla.by_customer", "l1.by_analyst", "sla.daily", "agentic.incidents"} <= ids and "sla.head" not in ids)
        b = (await admin.post("/api/data/run-batch", json={"ids": ["sla.daily", "agentic.incidents", "nope"], "period": "d7",
                                                           "tenant": "umbrella_co"})).json()
        check("batch runs several queries for one tenant",
              b["results"]["sla.daily"]["rows"][0]["customer"] == "umbrella_co" and b["results"]["agentic.incidents"]["rows"][0]["incidents"] == 212
              and b["results"]["nope"]["status"] == 404, b)
        check("agentic queries filter the tenant field", 'tenant IN ("umbrella_co")' in sent[-1]["spl"] or any('tenant IN ("umbrella_co")' in x["spl"] for x in sent[-3:]))

        # ---- ad-hoc SPL ----
        r = await admin.post("/api/data/adhoc", json={"spl": "index=main | stats count", "period": "d7"})
        check("manager runs ad-hoc SPL (200)", r.status_code == 200 and r.json()["rows"] == [{"x": 1}], r.text)
        r = await admin.post("/api/data/adhoc", json={"spl": 'index=main tenant="umbrella_co" | stats count', "period": "d7",
                                                      "tenant": "initech"})
        check("ad-hoc SPL with its own tenant filter runs for an all-tenants account whatever the selector says",
              r.status_code == 200, r.text)
        r = await admin.post("/api/data/adhoc", json={"spl": "index=soc_aisoc | outputlookup x.csv", "period": "d7"})
        check("ad-hoc writing command rejected (422)", r.status_code == 422)
        async with SessionLocal() as db:
            kinds = [a.kind for a in (await db.execute(select(AuditEvent))).scalars().all()]
        check("ad-hoc queries are audited", "data.adhoc_query" in kinds)

        # ---- data-source editing ----
        orig = next(q for q in (await admin.get("/admin/datasources")).json() if q["id"] == "sla.status_mix")
        r = await admin.patch("/admin/datasources/sla.status_mix", json={"spl": "$include:sla.head$ | collect index=x"})
        check("saving a writing command is refused (422)", r.status_code == 422)
        r = await admin.patch("/admin/datasources/sla.status_mix", json={"spl": "index=x | stats count by status"})
        check("saving a tenant-scoped query without a tenant token is refused (422)", r.status_code == 422, r.text)
        new_spl = orig["spl"] + "\n| sort - count"
        r = await admin.patch("/admin/datasources/sla.status_mix", json={"spl": new_spl, "note": "sort"})
        check("valid edit saves as v2", r.status_code == 200 and r.json()["version"] == 2)
        await admin.get("/api/metrics/status-mix?period=d7")
        check("the next run uses the edited SPL", sent[-1]["spl"].rstrip().endswith("| sort - count"))
        vs = (await admin.get("/admin/datasources/sla.status_mix/versions")).json()
        check("history keeps both versions", [v["version"] for v in vs] == [2, 1])
        r = await admin.post("/admin/datasources/sla.status_mix/rollback", json={"version": 1})
        check("rollback restores v1 text as v3", r.json()["version"] == 3 and r.json()["spl"] == orig["spl"])
        r = await admin.post("/admin/datasources/sla.status_mix/reset", json={})
        check("reset to built-in saves v4", r.json()["version"] == 4)
        from app.models import DataQuery
        async with SessionLocal() as db:
            q = (await db.execute(select(DataQuery).where(DataQuery.id == "agentic.incidents"))).scalar_one()
            q.spl = "old shipped text $tenants$"
            db.add(DataQuery(id="agentic.retired", name="retired", category="agentic", spl="x $tenants$",
                             builtin=True, updated_by="system"))
            await db.commit()
        await seed_data_queries()
        cat = {q["id"]: q for q in (await admin.get("/admin/datasources")).json()}
        check("an unedited built-in follows the shipped definition as a new version",
              "old shipped" not in cat["agentic.incidents"]["spl"] and cat["agentic.incidents"]["version"] == 2)
        check("a built-in dropped from the code is removed when nobody edited it", "agentic.retired" not in cat)
        check("a built-in a person touched is left alone", cat["sla.status_mix"]["version"] == 4)
        r = await admin.post("/admin/datasources/test", json={"spl": "index=soc_aisoc tenant IN ($tenants$) | stats count",
                                                            "columns": ["count", "tenant"], "period": "d7"})
        check("test run reports missing result columns", r.status_code == 200 and set(r.json()["missing_columns"]) == {"count", "tenant"}, r.text)
        r = await admin.post("/admin/datasources", json={"id": "custom.global_health", "name": "Global health", "category": "custom",
                                                       "spl": "index=soc_aisoc event_type=infra_health | stats count", "scope_mode": "global"})
        check("create a custom global query (201)", r.status_code == 201, r.text)
        check("built-ins cannot be deleted (400)", (await admin.delete("/admin/datasources/sla.by_customer")).status_code == 400)
        check("fragments in use cannot be deleted", (await admin.delete("/admin/datasources/sla.head")).status_code in (400, 409))
        await mk_user(admin, "analyst7", "l1_analyst", ["umbrella_co", "initech"])
        await mk_user(admin, "lead1", "shift_lead", [])

    async with httpx.AsyncClient(transport=tr, base_url="http://t") as l1:
        await l1.post("/auth/login", json={"username": "analyst7", "password": "temp-pass-1234"})
        rows = (await l1.get("/api/metrics/sla")).json()["rows"]
        check("L1 scope filters SLA to its 2 tenants", {r["customer"] for r in rows} == {"umbrella_co", "initech"})
        check("…and the SPL itself only names its labels", 'label IN ("initech","umbrella_co")' in sent[-1]["spl"])
        check("L1 asking for a tenant outside its scope is refused (403)",
              (await l1.get("/api/metrics/sla?tenant=globex_co")).status_code == 403)
        check("L1 blocked from /l1 (403, no team perf)", (await l1.get("/api/metrics/l1")).status_code == 403)
        mix = (await l1.get("/api/metrics/status-mix")).json()["rows"]
        check("L1 status mix counts only its tenants", mix == [{"status": "closed", "count": 10, "pct": 100.0}])
        await l1.get("/api/metrics/detection")
        check("L1 detection requested for its tenants only", seen_tenants[-1] == ["umbrella_co", "initech"])
        st = (await l1.get("/api/metrics/detection/status")).json()
        check("L1 sees when rules were synced but not the failure text or other customers' rule counts",
              st["synced_at"] and st["can_refresh"] is False and "error" not in st and "rules" not in st, st)
        n = len(refresh_triggers)
        r = await l1.post("/api/metrics/detection/refresh")
        check("L1 cannot start a detection refresh (403)", r.status_code == 403 and len(refresh_triggers) == n, r.status_code)
        qs = (await l1.get("/api/data/queries")).json()
        check("L1 sees the catalog without SPL", qs and all("spl" not in q for q in qs))
        r = await l1.get("/api/data/run/custom.global_health")
        check("L1 cannot run a global (not tenant-scoped) query (403)", r.status_code == 403)
        check("L1 cannot run ad-hoc SPL (403)",
              (await l1.post("/api/data/adhoc", json={"spl": "index=x | stats count"})).status_code == 403)
        check("L1 cannot edit data sources (403)", (await l1.get("/admin/datasources")).status_code == 403)
        cov = (await l1.get("/api/metrics/roster")).json()["coverage"]
        check("roster says which tenants each rostered account covers (only within the viewer's scope)",
              cov == {"analyst7": ["initech", "umbrella_co"], "lead1": "all"}, cov)

    async with httpx.AsyncClient(transport=tr, base_url="http://t") as lead:
        await lead.post("/auth/login", json={"username": "lead1", "password": "temp-pass-1234"})
        check("shift_lead sees all SLA rows", len((await lead.get("/api/metrics/sla")).json()["rows"]) == 3)
        check("shift_lead L1 200", (await lead.get("/api/metrics/l1")).status_code == 200)
        check("shift_lead runs the global query (all tenants)", (await lead.get("/api/data/run/custom.global_health")).status_code == 200)
        check("shift_lead lacks ad-hoc SPL by default (403)",
              (await lead.post("/api/data/adhoc", json={"spl": "index=x | stats count"})).status_code == 403)

    print(f"\n>>> RESULT: {passed} passed, {failed} failed")


asyncio.run(main())
