"""SOC Core — API + front-end host.

Owns auth, the user directory + RBAC, the live metric endpoints (tenant-scoped),
and serves the web app so everything is one origin. On startup it creates tables
and seeds the initial admin so the first login works.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .api import admin_roles, admin_tenants, admin_users, auth, chat, health, metrics, web
from .db import init_db
from .seed import seed_admin, seed_team, seed_tenants
from .roles_store import load_override, seed_roles


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await seed_admin()
    await seed_tenants()
    await seed_team()
    await seed_roles()
    await load_override()
    yield


app = FastAPI(title="SOC Watchfloor — Core", version="0.3.0", lifespan=lifespan)

app.include_router(health.router)
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(admin_users.router, prefix="/admin/users", tags=["admin"])
app.include_router(admin_tenants.router, prefix="/admin/tenants", tags=["admin"])
app.include_router(admin_roles.router, prefix="/admin/roles", tags=["admin"])
app.include_router(metrics.router, prefix="/api/metrics", tags=["metrics"])
app.include_router(chat.router, prefix="/api/chat", tags=["assistant"])
app.include_router(web.router, tags=["web"])
