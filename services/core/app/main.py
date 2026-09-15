"""SOC Core — API + front-end host.

Owns auth, the user directory + RBAC, the live metric endpoints (tenant-scoped),
and serves the web app so everything is one origin. On startup it creates tables
(adding any new columns), seeds the initial admin and tenants, and retires
passwords that were ever committed to the repo.
"""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api import (admin_audit, admin_datasources, admin_roles, admin_tenants, admin_users, auth,
                  chat, data, health, metrics, usage, web)
from .config import settings
from .datasources.catalog import seed_data_queries
from .security.web_guard import WebGuard
from .db import init_db
from .roles_store import load_override, seed_roles
from .seed import retire_leaked_passwords, seed_admin, seed_tenants


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await seed_admin()
    await seed_tenants()
    await retire_leaked_passwords()
    await seed_data_queries()
    await seed_roles()
    await load_override()
    yield


app = FastAPI(title="SOC Watchfloor — Core", version="0.4.0", lifespan=lifespan)

app.include_router(health.router)
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(admin_users.router, prefix="/admin/users", tags=["admin"])
app.include_router(admin_tenants.router, prefix="/admin/tenants", tags=["admin"])
app.include_router(admin_roles.router, prefix="/admin/roles", tags=["admin"])
app.include_router(admin_audit.router, prefix="/admin/audit", tags=["admin"])
app.include_router(admin_datasources.router, prefix="/admin/datasources", tags=["admin"])
app.include_router(metrics.router, prefix="/api/metrics", tags=["metrics"])
app.include_router(data.router, prefix="/api/data", tags=["data"])
app.include_router(chat.router, prefix="/api/chat", tags=["assistant"])
app.include_router(usage.router, prefix="/api", tags=["usage"])
app.include_router(usage.admin_router, prefix="/admin/usage", tags=["admin"])
app.include_router(web.router, tags=["web"])
app.mount("/static", StaticFiles(directory=os.path.join(settings.web_dir, "static"), check_dir=False), name="static")
app.add_middleware(WebGuard)   # HTTPS, security headers, caching, compression


@app.exception_handler(StarletteHTTPException)
async def _http_errors(request: Request, exc: StarletteHTTPException):
    """A person who opens a page that does not exist gets the 404 page; API
    callers keep the JSON error."""
    if exc.status_code == 404 and web.wants_html(request):
        return web.not_found(request)
    return await http_exception_handler(request, exc)
