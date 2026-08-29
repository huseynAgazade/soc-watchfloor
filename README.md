# SOC Watchfloor

> **Public demo.** This is a sanitized, self-contained copy for demonstration.
> All customer names (Acme Corp, Initech, Umbrella Co, Hooli Media, Globex),
> people, emails, phone numbers, hostnames and IPs are **synthetic**. No real
> tenant data, credentials, or API tokens are included — secrets are read from
> git-ignored `.env` files you supply. The assistant drives a read-only Splunk
> SOAR MCP server — [**huseynAgazade/splunk-soar-mcp**](https://github.com/huseynAgazade/splunk-soar-mcp)
> — through a role- and tenant-scoped authorization proxy.

An executive-summary portal for SOC operations at an MSSP: dashboards for two
separate shift teams, SLA per customer, L1 performance, MITRE ATT&CK coverage,
detection-rule inventory, a scheduled AI performance briefing, and an LLM chat
assistant — all multi-tenant and driven by one shared tool layer.

> **Status:** scaffolding. The approved UI is the static prototype in
> [`prototype/portal.html`](prototype/portal.html); the services below are being
> grown into it. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full
> design and the reasoning behind it.

## Run it (Docker)

```bash
cp .env.example .env          # fill in SPLUNK_PASSWORD (or SPLUNK_TOKEN)
docker compose -f infra/docker-compose.yml up --build
```

Then open **http://localhost:8000/** and sign in with `admin` /
`SEED_ADMIN_PASSWORD` (from `.env`; change it at first login).

- **Postgres** persists in the named volume `pgdata` — your users/accounts
  survive `docker compose down` and restarts.
- **Auth + roles** are enforced by the core; the site is behind a login.
- **SLA and L1 pages fetch live** from Splunk via the `mcp-soar` connector; other
  pages still show their embedded snapshot until their connector lands.
- The UI is bind-mounted from `prototype/`, so edits show on refresh.

## Design in one paragraph

Dashboards and the chat assistant call the **same** deterministic tools. Those
tools compute every number; the model only narrates — it never does arithmetic.
Every tool call is scoped to a tenant **server-side**, over anything the model
asked for, enforced again at the database with row-level security. Swapping the
LLM is three lines of YAML in the LiteLLM gateway, not a code change.

## Layout

```
soc-watchfloor/
  prototype/          the approved static UI (open portal.html in a browser)
  docs/               ARCHITECTURE.md and design notes
  apps/web/           Next.js — the BFF: auth, session, RBAC, SSR
  services/core/      FastAPI "SOC Core": Postgres, MCP client, agent loop
  services/mcp-*/     the four MCP servers (roster, soar, detection, splunk)
  infra/              docker-compose, Postgres schema, LiteLLM config
```

## Data sources

| Module | Source |
| --- | --- |
| Analyst / engineer shifts | SOAR custom list (`monthly_shift_roster`) + on-call rotation |
| SLA per customer | SOAR container SLA-stage fields (MTTA / MTTT / MTTR / MTTTres / MTTCR) |
| L1 performance | SOAR case data, keyed by analyst |
| MITRE coverage + rules | `detection-attck-mapper` pipeline (Splunk + Falcon EDR export) |
| AI briefing | Splunk `agentic_soc_summary` dashboard / Grafana |
| SIEM metrics (volume, EPS) | Splunk SPL — editable from the admin query catalog |

## Quick start (dev)

```bash
cp .env.example .env          # fill in secrets — never commit .env
docker compose -f infra/docker-compose.yml up --build
# web  -> http://localhost:3000
# core -> http://localhost:8000/docs
```

## Security

Admin-provisioned accounts only (no self-signup), Argon2id passwords, optional
TOTP, Redis-backed sessions. Every query is tenant-scoped server-side. Admin-
edited SIEM queries are read-only, tokenized (`$index$/$earliest$/$latest$`),
validated, versioned and audited. Never commit secrets; they are injected at
runtime. See `docs/ARCHITECTURE.md` §4 and §11.

## Acknowledgements

The assistant's SOAR tool layer is provided by
[**huseynAgazade/splunk-soar-mcp**](https://github.com/huseynAgazade/splunk-soar-mcp) —
a read-only Model Context Protocol server for Splunk SOAR. This project wraps it
behind a role- and tenant-scoped authorization proxy so a language model can
query SOAR safely (the model proposes tools; the proxy enforces what actually runs).
