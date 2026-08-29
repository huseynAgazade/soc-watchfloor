"""Serve the front-end from the core, so the browser, the auth cookie and the
API all share one origin (no CORS, cookies just work).

`portal.html` is fragment HTML (the approved prototype); it is wrapped in a
minimal document skeleton here. Its own bootstrap script checks /auth/me and
fetches /api/metrics/* for live data, redirecting to /login when unauthenticated.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..deps import current_user, get_db

router = APIRouter()


async def _maybe_user(request: Request, db: AsyncSession):
    """Resolve the session cookie to a user, or None if unauthenticated —
    used to gate page delivery server-side (no auth-only-in-JavaScript)."""
    try:
        return await current_user(request, db)
    except HTTPException:
        return None

_SKELETON = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
             '<meta name="viewport" content="width=device-width,initial-scale=1">'
             '</head><body>{body}</body></html>')


def _read(name: str) -> str | None:
    path = os.path.join(settings.web_dir, name)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        return f.read()


@router.get("/")
async def index(request: Request, db: AsyncSession = Depends(get_db)):
    # Auth is enforced server-side: the portal page (and its data) is never
    # delivered to an unauthenticated caller — they are redirected to /login.
    user = await _maybe_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=302)
    body = _read("portal.html")
    if body is None:
        return HTMLResponse("<h1>portal.html not mounted</h1>"
                            "<p>Mount the prototype into the core's web dir.</p>", status_code=500)
    return HTMLResponse(_SKELETON.format(body=body))


@router.get("/login", response_class=HTMLResponse)
async def login_page() -> HTMLResponse:
    html = _read("login.html")
    if html is None:
        return HTMLResponse("<h1>login.html not mounted</h1>", status_code=500)
    return HTMLResponse(html)


@router.get("/favicon.ico", response_class=PlainTextResponse)
async def favicon() -> PlainTextResponse:
    return PlainTextResponse("", status_code=204)
