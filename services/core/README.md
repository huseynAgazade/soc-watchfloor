# services/core — SOC Core (FastAPI)

The one tool layer, and now the **auth + directory + RBAC** authority. Owns the
database (users, sessions, audit), password hashing, sessions, and the role model.
Both the dashboards (via the web BFF) and the assistant call the same functions
here, so a number can never differ between a chart and a chat answer.

## What's implemented (phase: auth)

- **Login / logout / me / change-password** (`/auth/*`) — Argon2id passwords,
  server-side sessions (opaque cookie, only a token *hash* is stored), first-login
  forced password change, failed-attempt lockout, optional TOTP.
- **Roles & RBAC** (`app/rbac.py`) — six roles → capability sets, plus two
  per-user rota-publishing grants that are never implied by a role. Enforced in
  `app/deps.py` on every request; the tenant scope comes from the DB record,
  server-side, and cannot be set by the client.
- **Admin user management** (`/admin/users`) — only an admin creates accounts and
  sets their password (`POST /admin/users`, `POST /admin/users/{u}/password`;
  policy-checked, sessions revoked on reset); update, disable. Gated by the
  `manage_users` capability (managers only). No accounts are seeded except the
  initial admin.
- **TOTP enrolment** re-authenticates: the account password, plus a current code
  when an authenticator is already enrolled; the new secret replaces the old one
  only after a code from it verifies.
- **Assistant** (`/api/chat`) — every tool call goes through the authorization
  proxy (`app/assistant/proxy.py`); per-question limits and per-user rate limits
  (`ASSISTANT_*` settings); every question, tool call, refusal and limit hit is
  written to the audit trail, readable at `GET /admin/audit`.
- **Periods** (`app/periods.py`) — dashboards send a period key; bounds are
  resolved in `ORG_TIMEZONE` before any connector is called.
- **Query catalog** (`app/datasources/`, tables `data_queries` + `data_query_versions`)
  — every SLA, L1, overview and agentic panel runs a stored, editable SPL query.
  Queries carry tokens (`$earliest$ $latest$ $tenants$ $tenant_labels$
  $soar_containers$ $include:<fragment>$`) the server fills per run from the period
  and the caller's scope; writing commands are rejected on save and at run time;
  every save is versioned and audited. Built-ins are seeded from
  `app/datasources/catalog.py` (the agentic queries are the panels of Splunk
  dashboard `initech_all_general/agentic_soc_summary`). Endpoints: `/api/data/*`
  (run, batch, ad-hoc SPL) and `/admin/datasources` (edit, test, history, rollback,
  reset). `service.run_query()` is the one code path the dashboards and the
  assistant share.
- **Assistant tools** — besides SOAR (splunk-soar-mcp) the assistant has Watchfloor
  tools (`app/assistant/watchfloor.py`: tenants, catalog list/run, roster, detection
  coverage and, with `run_adhoc_queries` on an all-tenants account, SPL it writes
  itself). `/api/chat/stream` streams text and tool calls as server-sent events.
- **Initial admin** is seeded on an empty user table so the first login works.
- **Leaked passwords** that were ever committed are retired once per database at
  startup (`app/seed.py: retire_leaked_passwords`).

## Run (dev)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload      # http://localhost:8000/docs
# first login: admin / SEED_ADMIN_PASSWORD — or, if unset, the generated
# password printed once to the log (must be changed at first sign-in)
```

Dev uses SQLite (`DATABASE_URL` default). Production swaps to Postgres by setting
`DATABASE_URL=postgresql+asyncpg://…`; the models are dialect-neutral. New model
columns are added to existing tables at startup (`app/db.py`); renames, drops and
type changes still need a real migration.

## Test

```bash
python tests/test_auth_flow.py      # in-process — auth, admin-set passwords, RBAC, lockout
python tests/test_metrics_flow.py   # in-process — scope, periods, served page has no snapshots
python tests/test_hardening.py      # in-process — sweep, TOTP, proxy label check, chat limits + audit,
                                    #   detection scoping, roster dates, SOAR slicing
# against a running stack:
ADMIN_PASSWORD=... python tests/test_access_control.py
python tests/test_authz_proxy.py    # needs the splunk-soar-mcp bridge on :9011
```

## Principles enforced in code

- **Authorization is not a prompt** — scope and capabilities are read from the DB
  server-side (`deps.py`), never from caller input.
- **The model never computes** — endpoints return figures deterministic code
  produced (connectors land next).
