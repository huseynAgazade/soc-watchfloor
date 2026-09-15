"""Browser-facing protections for every response, as one ASGI middleware:

  * HTTPS: with `force_https`, plain HTTP is redirected (308) to HTTPS; HSTS is
    sent over HTTPS only when `hsts_enabled` (turn it on once the certificate is
    one browsers trust — HSTS removes the "proceed anyway" option);
  * security headers: CSP, frame, sniffing, referrer and permissions policies;
  * search engines: `X-Robots-Tag: noindex` unless `public_site`;
  * caching: pages and API answers are never cached (they hold customer data),
    static assets are cached for a week;
  * compression: gzip for everything except the assistant's event stream, which
    must reach the browser as it is written.
"""
from __future__ import annotations

from starlette.datastructures import Headers, MutableHeaders
from starlette.middleware.gzip import GZipMiddleware
from starlette.responses import RedirectResponse

from ..config import settings

CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; "
       "base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
_PUBLIC_FILES = ("/favicon.ico", "/robots.txt", "/sitemap.xml", "/site.webmanifest")


def _headers(path: str, https: bool) -> list[tuple[str, str]]:
    out = [
        ("Content-Security-Policy", CSP + ("; upgrade-insecure-requests" if settings.force_https else "")),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
    ]
    if not settings.public_site:
        out.append(("X-Robots-Tag", "noindex, nofollow"))
    if https and settings.hsts_enabled:
        out.append(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
    if path.startswith("/static/"):
        out.append(("Cache-Control", "public, max-age=604800"))
    elif path in _PUBLIC_FILES:
        out.append(("Cache-Control", "public, max-age=86400"))
    else:
        out.append(("Cache-Control", "no-store"))
    return out


class WebGuard:
    def __init__(self, app):
        self.app = app
        self.gzip = GZipMiddleware(app, minimum_size=1024)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        headers = Headers(scope=scope)
        scheme = scope.get("scheme", "http")
        if settings.trust_proxy_headers and headers.get("x-forwarded-proto"):
            scheme = headers["x-forwarded-proto"].split(",")[0].strip().lower()

        if settings.force_https and scheme != "https" and path != "/health":
            host = (headers.get("host") or "localhost").rsplit(":", 1)[0] if not (headers.get("host") or "").startswith("[") \
                else headers["host"].split("]")[0] + "]"
            port = "" if settings.https_port == 443 else f":{settings.https_port}"
            query = scope.get("query_string", b"").decode("latin-1")
            await RedirectResponse(f"https://{host}{port}{path}" + (f"?{query}" if query else ""),
                                   status_code=308)(scope, receive, send)
            return

        extra = _headers(path, scheme == "https")

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                h = MutableHeaders(scope=message)
                for k, v in extra:
                    if k not in h:
                        h[k] = v
            await send(message)

        target = self.app if path.endswith("/stream") else self.gzip
        await target(scope, receive, send_with_headers)
