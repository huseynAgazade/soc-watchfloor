"""Access-control / IDOR audit — creates its own dedicated test subjects so it is
repeatable regardless of prior state."""
import httpx

B = "http://127.0.0.1:8000"
TMP = "changeme-temp"
passed = failed = 0
findings = []

def ok(name, cond, detail=""):
    global passed, failed
    if cond: passed += 1; print(f"  PASS  {name}")
    else: failed += 1; print(f"  FAIL  {name}  {detail}"); findings.append(name)

admin = httpx.Client()
admin.post(f"{B}/auth/login", json={"username": "admin", "password": "changeme-admin"})
ok("admin (env password) is not force-changed and can administer",
   admin.get(f"{B}/admin/users").status_code == 200)

def make(username, role, scope):
    admin.post(f"{B}/admin/users", json={"username": username, "full_name": username, "role": role,
                                         "allowed_customer_ids": scope, "temporary_password": TMP})

def activated_client(username):
    """Login a temp user and complete the forced first-login change -> active session."""
    c = httpx.Client(); c.post(f"{B}/auth/login", json={"username": username, "password": TMP})
    c.post(f"{B}/auth/change-password", json={"current_password": TMP, "new_password": username + "-Str0ng-pass-2026"})
    return c

# fresh subjects
for u in ("audit.l1", "audit.lead", "audit.probe"):
    admin.delete(f"{B}/admin/users/{u}")           # disable if left over (won't allow recreate, but harmless)
make("audit.l1", "l1_analyst", ["initech", "globex_co"])
make("audit.lead", "shift_lead", [])

print("\n[anonymous -> 401 everywhere]")
anon = httpx.Client()
for p in ["/auth/me", "/api/metrics/sla", "/admin/users", "/admin/tenants", "/admin/roles"]:
    ok(f"anon {p} 401", anon.get(f"{B}{p}").status_code == 401)

print("\n[first-login gate: temp session cannot read data]")
raw = httpx.Client(); raw.post(f"{B}/auth/login", json={"username": "audit.l1", "password": TMP})
ok("temp session blocked from SLA (403)", raw.get(f"{B}/api/metrics/sla").status_code == 403)
ok("temp session still sees /auth/me", raw.get(f"{B}/auth/me").status_code == 200)

l1 = activated_client("audit.l1")
print("\n[scoped L1: tenant isolation / IDOR]")
seen = {r["customer"] for r in l1.get(f"{B}/api/metrics/sla").json().get("rows", [])}
ok("L1 SLA limited to its 2 tenants", seen == {"initech", "globex_co"}, f"saw {seen}")
tl = {t["id"] for t in l1.get(f"{B}/admin/tenants").json()}
ok("L1 tenant list limited to its scope", tl == {"initech", "globex_co"}, f"saw {tl}")

print("\n[scoped L1: privilege boundaries]")
ok("cannot list users (403)", l1.get(f"{B}/admin/users").status_code == 403)
ok("cannot read another user via IDOR (403)", l1.get(f"{B}/admin/users/admin").status_code == 403)
ok("cannot create a user (403)",
   l1.post(f"{B}/admin/users", json={"username": "x", "full_name": "x", "role": "soc_manager", "temporary_password": "x"*8}).status_code == 403)
ok("cannot escalate self via PATCH (403)", l1.patch(f"{B}/admin/users/audit.l1", json={"role": "soc_manager"}).status_code == 403)
ok("cannot disable another user (403)", l1.delete(f"{B}/admin/users/admin").status_code == 403)
ok("cannot create a tenant (403)", l1.post(f"{B}/admin/tenants", json={"id": "x", "name": "x"}).status_code == 403)
ok("cannot archive a tenant (403)", l1.delete(f"{B}/admin/tenants/umbrella_co").status_code == 403)
ok("cannot read role matrix (403)", l1.get(f"{B}/admin/roles").status_code == 403)
ok("cannot edit a role (403)", l1.patch(f"{B}/admin/roles/read_only", json={"capabilities": ["manage_users"]}).status_code == 403)
ok("cannot view team performance (403)", l1.get(f"{B}/api/metrics/l1").status_code == 403)

print("\n[no secret fields leak]")
me = l1.get(f"{B}/auth/me").json()
ok("/auth/me has no password/totp", not any(k in me for k in ("password_hash", "totp_secret", "totp_secret_enc")))
alist = admin.get(f"{B}/admin/users").json()
ok("admin user list exposes no secrets",
   isinstance(alist, list) and not any(("password_hash" in u or "totp_secret" in u) for u in alist))

print("\n[shift lead: team perf yes, admin no]")
lead = activated_client("audit.lead")
ok("shift_lead views team perf (200)", lead.get(f"{B}/api/metrics/l1").status_code == 200)
ok("shift_lead cannot manage users (403)", lead.get(f"{B}/admin/users").status_code == 403)
ok("shift_lead cannot edit roles (403)", lead.get(f"{B}/admin/roles").status_code == 403)

print("\n[login hygiene]")
a = httpx.Client().post(f"{B}/auth/login", json={"username": "nope", "password": "x"}).status_code
b = httpx.Client().post(f"{B}/auth/login", json={"username": "admin", "password": "wrong"}).status_code
ok("no user enumeration (both 401)", a == b == 401)

print("\n[disabled account: live session dies]")
make("audit.probe", "read_only", [])
probe = activated_client("audit.probe")
ok("probe active before disable (200)", probe.get(f"{B}/auth/me").status_code == 200)
ok("admin disables probe (200)", admin.delete(f"{B}/admin/users/audit.probe").status_code == 200)
ok("probe live session now rejected (401)", probe.get(f"{B}/auth/me").status_code == 401)

print("\n[cookie hardening]")
sc = httpx.Client().post(f"{B}/auth/login", json={"username": "admin", "password": "changeme-admin"}).headers.get("set-cookie", "")
ok("cookie HttpOnly", "httponly" in sc.lower())
ok("cookie SameSite", "samesite" in sc.lower())

# cleanup test subjects
for u in ("audit.l1", "audit.lead", "audit.probe"):
    admin.delete(f"{B}/admin/users/{u}")

print(f"\n===== {passed} passed, {failed} failed =====")
if findings: print("REVIEW:", findings)
