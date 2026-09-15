"""Serve the front-end from the core, so the browser, the auth cookie and the
API all share one origin (no CORS, cookies just work).

Pages: the portal (signed-in only), sign-in, privacy policy, terms and
conditions, and the 404 page; plus robots.txt, sitemap.xml, the web manifest
and the favicon. Every page gets its title, description, icons and link-preview
tags from PAGES below. Static files (fonts, icons, preview image) are served
from <web_dir>/static by main.py.

`portal.html` is fragment HTML (the approved prototype); it is wrapped in a
minimal document skeleton here. Its own bootstrap script checks /auth/me and
fetches /api/metrics/* for live data, redirecting to /login when unauthenticated.

Snapshots: the prototype embeds captured data (rules, SLA, analyst metrics, the
directory) so it works when opened as a plain file. That data spans every tenant
and every analyst, so it is removed before the page is served — a served page only
ever shows what the scoped API returns. Mark any new embedded dataset in
portal.html as `/*snapshot:NAME*/ ... /*/snapshot*/` and give NAME an empty value
in _EMPTY below; an unknown NAME fails the request rather than leaking.
"""
from __future__ import annotations

import html as _html
import json
import os
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..deps import current_user, get_db

router = APIRouter()

_SNAPSHOT = re.compile(r"/\*snapshot:([a-z0-9_]+)\*/.*?/\*/snapshot\*/", re.S)
_EMPTY_SUMMARY = ('{"topCovered":0,"topTotal":211,"phantom":0,"rules_total":0,"rules_detection":0,'
                  '"rules_enabled":0,"rules_disabled":0,"rules_unmapped":0,"rules_ops":0,"rules_test":0}')
_EMPTY = {
    "tenants": "[]",
    "sla": "{}",
    "l1": "{}",
    "people": "[]",
    "audit": "[]",
    "det": '{"summary":{"all":' + _EMPTY_SUMMARY + '},"tactics":{"all":[]},"tech":{"all":{}},'
           '"rules":[],"onboarded":[]}',
}

SITE = "SOC Watchfloor"
PAGES = {   # key: (title, description)
    "portal": (SITE, "SLA per customer, analyst performance, rotas, detection coverage, agentic AI performance "
                     "and the SOC assistant — the operations portal for the security operations centre."),
    "login": (f"Sign in · {SITE}", "Sign in to SOC Watchfloor, the operations portal for the security operations "
                                   "centre. Accounts are provisioned by an administrator."),
    "privacy": (f"Privacy policy · {SITE}", "What personal data SOC Watchfloor processes, why, who receives it, how "
                                            "long it is kept, which cookies it sets, and your rights."),
    "terms": (f"Terms and conditions · {SITE}", "The rules for using SOC Watchfloor: authorised use, account security, "
                                                "confidentiality of customer data, the AI assistant and monitoring."),
    "404": (f"Page not found · {SITE}", "The page you asked for does not exist or has moved."),
}
PUBLIC_PAGES = {"/login": "login.html", "/privacy": "privacy.html", "/terms": "terms.html"}
_API_PREFIXES = ("/api/", "/auth/", "/admin/", "/static/")


def strip_snapshots(html: str) -> str:
    return _SNAPSHOT.sub(lambda m: _EMPTY[m.group(1)], html)


async def _maybe_user(request: Request, db: AsyncSession):
    """Resolve the session cookie to a user, or None if unauthenticated —
    used to gate page delivery server-side (no auth-only-in-JavaScript)."""
    try:
        return await current_user(request, db)
    except HTTPException:
        return None

_SKELETON = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
             '<meta name="viewport" content="width=device-width,initial-scale=1">'
             '{head}</head><body>{body}</body></html>')


def _read(name: str) -> str | None:
    path = os.path.join(settings.web_dir, name)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        return f.read()


def base_url(request: Request) -> str:
    return (settings.public_base_url or str(request.base_url)).rstrip("/")


def head(request: Request, key: str, path: str, *, title: bool = True, fonts: bool = True) -> str:
    """Title, description, robots, icons, manifest, canonical and link-preview tags."""
    name, desc = PAGES[key]
    e = lambda s: _html.escape(s, quote=True)
    b = base_url(request)
    tags = [f"<title>{e(name)}</title>"] if title else []
    tags += [
        f'<meta name="description" content="{e(desc)}">',
        '<meta name="theme-color" content="#2a4a9c">',
        '<link rel="icon" href="/favicon.ico" sizes="48x48">',
        '<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">',
        '<link rel="apple-touch-icon" href="/static/apple-touch-icon.png">',
        '<link rel="manifest" href="/site.webmanifest">',
        f'<link rel="canonical" href="{e(b + path)}">',
        '<meta property="og:type" content="website">',
        f'<meta property="og:site_name" content="{SITE}">',
        f'<meta property="og:title" content="{e(name)}">',
        f'<meta property="og:description" content="{e(desc)}">',
        f'<meta property="og:url" content="{e(b + path)}">',
        f'<meta property="og:image" content="{e(b)}/static/og-image.png">',
        '<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">',
        '<meta property="og:image:alt" content="SOC Watchfloor — the operations portal for the security operations centre">',
        '<meta name="twitter:card" content="summary_large_image">',
        f'<meta name="twitter:title" content="{e(name)}">',
        f'<meta name="twitter:description" content="{e(desc)}">',
        f'<meta name="twitter:image" content="{e(b)}/static/og-image.png">',
    ]
    if not settings.public_site:
        tags.insert(1, '<meta name="robots" content="noindex, nofollow">')
    if fonts:
        tags.append('<link rel="stylesheet" href="/static/fonts/fonts.css">')
    return "".join(tags)


def _fill(text: str) -> str:
    """Live values quoted by the legal pages, so they never drift from the config."""
    return (text.replace("{{SESSION_HOURS}}", str(settings.session_ttl_hours))
                .replace("{{IDLE_MINUTES}}", str(settings.session_idle_minutes))
                .replace("{{CHAT_DAYS}}", str(settings.assistant_saved_chat_days))
                .replace("{{LOCKOUT_ATTEMPTS}}", str(settings.lockout_attempts))
                .replace("{{USAGE_DAYS}}", "400"))


def render(request: Request, name: str, key: str, path: str, status_code: int = 200) -> HTMLResponse:
    page = _read(name)
    if page is None:
        return HTMLResponse(f"<h1>{_html.escape(name)} not mounted</h1>", status_code=500 if status_code == 200 else status_code)
    return HTMLResponse(_fill(page.replace("<!--wf:head-->", head(request, key, path))), status_code=status_code)


def wants_html(request: Request) -> bool:
    return (request.method == "GET" and "text/html" in request.headers.get("accept", "")
            and not request.url.path.startswith(_API_PREFIXES))


def not_found(request: Request) -> HTMLResponse:
    return render(request, "404.html", "404", request.url.path, status_code=404)


@router.get("/")
async def index(request: Request, db: AsyncSession = Depends(get_db)):
    # Auth is enforced server-side: the portal page (and its data) is never
    # delivered to an unauthenticated caller — they are redirected to /login.
    user = await _maybe_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=302)
    if user.must_change_password:
        return RedirectResponse("/login?change=1", status_code=302)
    body = _read("portal.html")
    if body is None:
        return HTMLResponse("<h1>portal.html not mounted</h1>"
                            "<p>Mount the prototype into the core's web dir.</p>", status_code=500)
    return HTMLResponse(_SKELETON.format(head=head(request, "portal", "/", title=False, fonts=False),
                                         body=strip_snapshots(body)))


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    return render(request, "login.html", "login", "/login")


@router.get("/privacy", response_class=HTMLResponse)
async def privacy_page(request: Request) -> HTMLResponse:
    return render(request, "privacy.html", "privacy", "/privacy")


@router.get("/terms", response_class=HTMLResponse)
async def terms_page(request: Request) -> HTMLResponse:
    return render(request, "terms.html", "terms", "/terms")


@router.get("/robots.txt", response_class=PlainTextResponse)
async def robots(request: Request) -> PlainTextResponse:
    if not settings.public_site:
        return PlainTextResponse("# SOC Watchfloor is an internal, sign-in-only portal: keep it out of search engines.\n"
                                 "User-agent: *\nDisallow: /\n")
    allow = "".join(f"Allow: {p}\n" for p in PUBLIC_PAGES)
    return PlainTextResponse(f"User-agent: *\n{allow}Disallow: /\n\nSitemap: {base_url(request)}/sitemap.xml\n")


@router.get("/sitemap.xml")
async def sitemap(request: Request) -> Response:
    b = _html.escape(base_url(request))
    urls = []
    for path, name in PUBLIC_PAGES.items():
        file = os.path.join(settings.web_dir, name)
        lastmod = (datetime.fromtimestamp(os.path.getmtime(file), timezone.utc).date().isoformat()
                   if os.path.isfile(file) else None)
        urls.append(f"<url><loc>{b}{path}</loc>" + (f"<lastmod>{lastmod}</lastmod>" if lastmod else "") + "</url>")
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
           + "".join(urls) + "</urlset>\n")
    return Response(xml, media_type="application/xml")


@router.get("/site.webmanifest")
async def manifest() -> Response:
    data = {"name": SITE, "short_name": "Watchfloor", "start_url": "/", "display": "standalone",
            "background_color": "#eff1f5", "theme_color": "#2a4a9c",
            "icons": [{"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png"},
                      {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png"}]}
    return Response(json.dumps(data), media_type="application/manifest+json")


@router.get("/favicon.ico")
async def favicon():
    path = os.path.join(settings.web_dir, "static", "favicon.ico")
    if os.path.isfile(path):
        return FileResponse(path, media_type="image/x-icon")
    return Response(status_code=204)
