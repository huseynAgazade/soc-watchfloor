"""Access-control / IDOR audit against the running stack — creates its own
dedicated test subjects so it is repeatable regardless of prior state.

    ADMIN_PASSWORD=... python tests/test_access_control.py
"""
import os
import secrets
import sys

import httpx

B = os.environ.get("PORTAL_URL", "http://127.0.0.1:8000")
ADMIN_USER = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PW = os.environ.get("ADMIN_PASSWORD")
if not ADMIN_PW:
    sys.exit("set ADMIN_PASSWORD (the admin account's password) first")
TMP = "Audit-" + secrets.token_urlsafe(12)       # admin-set password for the subjects
passed = failed = 0
findings = []

def ok(name, cond, detail=""):
    global passed, failed
    if cond: passed += 1; print(f"  PASS  {name}")
    else: failed += 1; print(f"  FAIL  {name}  {detail}"); findings.append(name)

admin = httpx.Client(timeout=180)
admin.post(f"{B}/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PW})
ok("admin can administer", admin.get(f"{B}/admin/users").status_code == 200)

def make(username, role, scope):
    r = admin.post(f"{B}/admin/users", json={"username": username, "full_name": username, "role": role,
                                             "allowed_customer_ids": scope, "temporary_password": TMP})
    if r.status_code == 409:   # left over from an earlier run: re-enable and reset the password
        admin.patch(f"{B}/admin/users/{username}", json={"state": "active", "allowed_customer_ids": scope})
        admin.post(f"{B}/admin/users/{username}/password", json={"password": TMP, "require_change": True})

def activated_client(username):
    """Login with the admin-set password and complete the forced change -> active session."""
    c = httpx.Client(timeout=180); c.post(f"{B}/auth/login", json={"username": username, "password": TMP})
    c.post(f"{B}/auth/change-password", json={"current_password": TMP, "new_password": TMP + "-own-2026"})
    return c

make("audit.l1", "l1_analyst", ["initech", "globex_co"])
make("audit.lead", "shift_lead", [])

print("\n[anonymous -> 401 everywhere]")
anon = httpx.Client(timeout=180)
for p in ["/auth/me", "/api/metrics/sla", "/admin/users", "/admin/tenants", "/admin/roles", "/admin/audit"]:
    ok(f"anon {p} 401", anon.get(f"{B}{p}").status_code == 401)

print("\n[first-login gate: admin-set password session cannot read data]")
raw = httpx.Client(timeout=180); raw.post(f"{B}/auth/login", json={"username": "audit.l1", "password": TMP})
ok("must-change session blocked from SLA (403)", raw.get(f"{B}/api/metrics/sla").status_code == 403)
ok("must-change session still sees /auth/me", raw.get(f"{B}/auth/me").status_code == 200)

l1 = activated_client("audit.l1")
print("\n[scoped L1: tenant isolation / IDOR]")
seen = {r["customer"] for r in l1.get(f"{B}/api/metrics/sla").json().get("rows", [])}
ok("L1 SLA limited to its 2 tenants", seen <= {"initech", "globex_co"}, f"saw {seen}")
tl = {t["id"] for t in l1.get(f"{B}/admin/tenants").json()}
ok("L1 tenant list limited to its scope", tl == {"initech", "globex_co"}, f"saw {tl}")
det = l1.get(f"{B}/api/metrics/detection").json()
ok("L1 detection data limited to its scope",
   set(det.get("onboarded", [])) <= {"initech", "globex_co"}
   and {r["tenant"] for r in det.get("rules", [])} <= {"initech", "globex_co"}, det.get("onboarded"))
page = l1.get(f"{B}/").text
ok("served portal carries no embedded snapshot", "snapshot:" not in page and "engineer1@soc.example" not in page)

print("\n[scoped L1: privilege boundaries]")
ok("cannot list users (403)", l1.get(f"{B}/admin/users").status_code == 403)
ok("cannot read another user via IDOR (403)", l1.get(f"{B}/admin/users/{ADMIN_USER}").status_code == 403)
ok("cannot create a user (403)",
   l1.post(f"{B}/admin/users", json={"username": "x", "full_name": "x", "role": "soc_manager", "temporary_password": "x"*20}).status_code == 403)
ok("cannot set another user's password (403)",
   l1.post(f"{B}/admin/users/{ADMIN_USER}/password", json={"password": "Hijack-Password-2026"}).status_code == 403)
ok("cannot escalate self via PATCH (403)", l1.patch(f"{B}/admin/users/audit.l1", json={"role": "soc_manager"}).status_code == 403)
ok("cannot disable another user (403)", l1.delete(f"{B}/admin/users/{ADMIN_USER}").status_code == 403)
ok("cannot create a tenant (403)", l1.post(f"{B}/admin/tenants", json={"id": "x", "name": "x"}).status_code == 403)
ok("cannot archive a tenant (403)", l1.delete(f"{B}/admin/tenants/umbrella_co").status_code == 403)
ok("cannot read role matrix (403)", l1.get(f"{B}/admin/roles").status_code == 403)
ok("cannot edit a role (403)", l1.patch(f"{B}/admin/roles/read_only", json={"capabilities": ["manage_users"]}).status_code == 403)
ok("cannot view team performance (403)", l1.get(f"{B}/api/metrics/l1").status_code == 403)
ok("cannot read the audit trail (403)", l1.get(f"{B}/admin/audit").status_code == 403)
ok("cannot start TOTP enrolment without the password (400)",
   l1.post(f"{B}/auth/totp/enroll", json={"password": "not-my-password"}).status_code == 400)

print("\n[no secret fields leak]")
me = l1.get(f"{B}/auth/me").json()
ok("/auth/me has no password/totp", not any(k in me for k in ("password_hash", "totp_secret", "totp_pending_secret")))
alist = admin.get(f"{B}/admin/users").json()
ok("admin user list exposes no secrets",
   isinstance(alist, list) and not any(("password_hash" in u or "totp_secret" in u) for u in alist))

print("\n[shift lead: team perf yes, admin no]")
lead = activated_client("audit.lead")
ok("shift_lead views team perf (200)", lead.get(f"{B}/api/metrics/l1").status_code == 200)
ok("shift_lead cannot manage users (403)", lead.get(f"{B}/admin/users").status_code == 403)
ok("shift_lead cannot edit roles (403)", lead.get(f"{B}/admin/roles").status_code == 403)

print("\n[login hygiene]")
a = httpx.Client(timeout=180).post(f"{B}/auth/login", json={"username": "nope", "password": "x"}).status_code
b = httpx.Client(timeout=180).post(f"{B}/auth/login", json={"username": "audit.lead", "password": "wrong"}).status_code
ok("no user enumeration (both 401)", a == b == 401)
ok("shared temp password from old builds no longer works",
   httpx.Client(timeout=180).post(f"{B}/auth/login", json={"username": "analyst1", "password": "changeme-temp"}).status_code == 401)

print("\n[disabled account: live session dies]")
make("audit.probe", "read_only", [])
probe = activated_client("audit.probe")
ok("probe active before disable (200)", probe.get(f"{B}/auth/me").status_code == 200)
ok("admin disables probe (200)", admin.delete(f"{B}/admin/users/audit.probe").status_code == 200)
ok("probe live session now rejected (401)", probe.get(f"{B}/auth/me").status_code == 401)

print("\n[cookie hardening]")
sc = httpx.Client(timeout=180).post(f"{B}/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PW}).headers.get("set-cookie", "")
ok("cookie HttpOnly", "httponly" in sc.lower())
ok("cookie SameSite", "samesite" in sc.lower())

# cleanup test subjects
for u in ("audit.l1", "audit.lead", "audit.probe"):
    admin.delete(f"{B}/admin/users/{u}")

print(f"\n===== {passed} passed, {failed} failed =====")
if findings: print("REVIEW:", findings)
