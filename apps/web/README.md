# apps/web — Next.js BFF

The browser-facing layer. Owns authentication, the session cookie (backed by
Redis), RBAC gating, and server-side rendering. It never computes SOC figures —
it proxies the FastAPI **core** (`/api/core/*`) which owns Postgres, the MCP
client and the agent loop.

The look and behaviour target is `../../prototype/portal.html`. Porting is
view-by-view: each `<section class="view">` in the prototype becomes a route
under `app/`.

## Dev
```bash
cp .env.example .env
npm install
npm run dev   # http://localhost:3000
```
