"""The plain-HTTP listener: sends every request to the HTTPS core (308 keeps the
method and body), same host, path and query. /health answers directly so
monitoring does not need to follow redirects."""
from __future__ import annotations

import os

from starlette.datastructures import Headers
from starlette.responses import PlainTextResponse, RedirectResponse

HTTPS_PORT = int(os.environ.get("HTTPS_PORT", "443"))


async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    if scope.get("path") == "/health":
        await PlainTextResponse("ok")(scope, receive, send)
        return
    host = Headers(scope=scope).get("host") or "localhost"
    host = host.split("]")[0] + "]" if host.startswith("[") else host.rsplit(":", 1)[0]
    port = "" if HTTPS_PORT == 443 else f":{HTTPS_PORT}"
    query = scope.get("query_string", b"").decode("latin-1")
    url = f"https://{host}{port}{scope.get('path', '/')}" + (f"?{query}" if query else "")
    await RedirectResponse(url, status_code=308)(scope, receive, send)
