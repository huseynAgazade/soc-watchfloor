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
- **Admin user management** (`/admin/users`) — create, list, update, disable
  accounts; `/admin/users/roles/matrix` returns the capability matrix. Gated by
  the `manage_users` capability (managers only).
- **Initial admin** is seeded on an empty user table so the first login works.

## Run (dev)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload      # http://localhost:8000/docs
# first login: admin / (SEED_ADMIN_PASSWORD from env; default in config.py)
```

Dev uses SQLite (`DATABASE_URL` default). Production swaps to Postgres by setting
`DATABASE_URL=postgresql+asyncpg://…`; the models are dialect-neutral.

## Test

```bash
python tests/test_auth_flow.py     # in-process, no socket — 22 checks
```

Covers: admin login, role→capabilities, scoped user creation, RBAC denial (L1
blocked from admin endpoints), tenant scope, first-login password change, lockout.

## Principles enforced in code

- **Authorization is not a prompt** — scope and capabilities are read from the DB
  server-side (`deps.py`), never from caller input.
- **The model never computes** — endpoints return figures deterministic code
  produced (connectors land next).
