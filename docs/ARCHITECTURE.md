# SOC Ops Portal — Architecture & Design Specification

**Status:** Draft v1 — design only, no code yet
**Author:** drafted with Claude Code for socadmin@soc.example
**Date:** 2026-08-19
**Context:** MSSP SOC. Multiple customer tenants (Globex, Acme Corp, Hooli Stream,
Umbrella Co, Initech, Brandefense, …). Existing estate: Splunk SOAR (Phantom),
Splunk SIEM, CrowdStrike Falcon, Cortex XDR, Grafana, Mattermost.

---

## 0. How to read this

Sections 1–3 are the thesis; if you read nothing else, read §2 and §4.3.
Sections 4–9 are the buildable spec. Section 13 is the phase plan you'd actually execute.
Section 15 is the list of ways this project fails, and what stops each one.

Nothing here is code. Every decision is written so it can be argued with before it costs anything.

---

## 1. Context and constraints

### 1.1 What the portal is

An **executive summary portal for SOC operations**: one place where a SOC manager,
shift lead, or account manager can see how the SOC is actually performing — per customer,
per analyst, per detection — and ask follow-up questions in natural language.

Seven modules in scope:

| # | Module | System of record | Integration |
|---|---|---|---|
| 1 | Analysts + shifts | **This portal** | none (owned) |
| 2 | Engineers + shifts | **This portal** | none (owned) |
| 3 | SLA reports per customer | Splunk SOAR | `soar-mcp` |
| 4 | Performance summary for L1s | Splunk SOAR (+ QA) | `soar-mcp` |
| 5 | AI agent analysis of SOC performance | Grafana | `grafana-mcp` |
| 6 | MITRE mapping | Detection content store | `detection-mcp` |
| 7 | Enabled rules | SIEM + content store | `detection-mcp` |

"Not limited to" is taken seriously: §5 and §7 are written so an eighth module is an
additive change (one table group, one MCP server, one nav entry), not a refactor.

### 1.2 Hard constraints (from you)

- **Docker is mandatory.** Everything ships as containers; `docker compose up` is the
  install story. No "works on my laptop" steps.
- **Authentication is mandatory.** Real login, real roles, real per-tenant scoping.
- **Next.js UI + Python MCP layer.**
- **LLM likely runs locally.** Design must not assume a frontier hosted model.

### 1.3 Soft constraints worth naming now

- SOC operates in **UTC+4 (Asia/Dubai)**. Night shifts cross midnight. All timestamps
  stored UTC, rendered in a configurable org timezone. This is a bug factory if left implicit.
- This is an **MSSP**, so *every* schema, query, cache key, and tool call carries a
  `customer_id`. Multi-tenancy retrofitted later is a rewrite.
- Executive reports must be **reproducible**: February's SLA number, re-run in June,
  must return the same value. That forces snapshotting (§6.3).

---

## 2. The architectural thesis: one tool layer, two consumers

The tempting design is "a dashboard, plus a chatbot bolted on the side." That produces
two code paths to the same data, which drift, and eventually the chat tells the CISO 94.2%
while the dashboard shows 91.8%.

**The design here is the inverse.** There is exactly one data-access layer — the MCP tool
layer — and it has two consumers:

```
                   ┌──────────────────────────┐
                   │      MCP TOOL LAYER      │
                   │  (Python, per-domain)    │
                   └────────┬────────┬────────┘
                            │        │
          deterministic ────┘        └──── agentic
                            │        │
                   ┌────────▼──┐  ┌──▼─────────┐
                   │ Dashboard │  │  LLM chat  │
                   │  panels   │  │            │
                   └───────────┘  └────────────┘
```

Consequences, all of them good:

1. **The chat can never contradict the dashboard** — same function, same result.
2. **You test once.** A unit test on `get_sla_summary()` covers both surfaces.
3. **Adding a module means adding tools**, and the chat gets smarter for free.
4. **The LLM's capability is bounded by your tools**, which is exactly where you want
   the boundary for a security product — not bounded by how clever its prompt is.

### 2.1 The corollary: the LLM never computes a number

Deterministic code computes every figure that appears in an executive report — SLA
percentages, breach counts, roster coverage, rule counts, MITRE coverage ratios. The
LLM's job is **explanation, correlation, narration, and ad-hoc questions**. It receives
computed numbers and talks about them.

If the model is allowed to average, count, or divide, you will eventually publish a
confidently wrong number to a customer. Not "might" — will. The failure is silent and
the output looks perfect.

This single rule is what makes a **local model viable** (§10).

### 2.2 Fat tools, thin model

Directly downstream of §2.1. Design MCP tools to return *small, pre-aggregated, labelled*
results rather than raw API payloads.

```
BAD   search_soar(query: str) -> 500 container JSON blobs
      (model must filter, count, average — it will get it wrong)

GOOD  get_sla_summary(customer_id, period) -> {
        total_cases: 412, met: 389, breached: 23,
        compliance_pct: 94.42, worst_severity: "critical",
        mttr_minutes_p50: 41, mttr_minutes_p90: 186, ...
      }
      (model reads 12 labelled numbers and explains them)
```

Every tool in §7 is specified in the "GOOD" shape. This is the single highest-leverage
decision for reliability on constrained hardware.

---

## 3. System architecture

### 3.1 Containers

```
                              ┌────────────────────────────────────────┐
   browser ──── HTTPS ───────►│ edge (Caddy)  TLS, HSTS, rate limit    │
                              └───────────────┬────────────────────────┘
                                              │
                              ┌───────────────▼────────────────────────┐
                              │ web  —  Next.js (App Router, RSC)      │
                              │ • session cookie, CSRF                 │
                              │ • RBAC gate on every route             │
                              │ • SSR dashboards, streaming chat UI    │
                              │ • holds NO integration credentials     │
                              └───────────────┬────────────────────────┘
                                              │ internal HTTP (docker net, mTLS optional)
                              ┌───────────────▼────────────────────────┐
                              │ core  —  FastAPI  "SOC Core"           │
                              │ • /api/v1/*   deterministic endpoints  │
                              │ • /api/v1/chat  SSE agent loop         │
                              │ • MCP client + tool registry           │
                              │ • tenant-scope enforcement (§4.3)      │
                              └──┬────────┬───────────┬────────────┬───┘
                                 │        │           │            │
                    ┌────────────▼┐  ┌────▼─────┐  ┌──▼───────┐ ┌──▼──────────┐
                    │ postgres    │  │ redis    │  │ llm      │ │ MCP servers │
                    │ (SoR + snap)│  │cache/queue│ │(OpenAI-  │ │  (below)    │
                    └─────────────┘  └──────────┘  │ compat)  │ └─────────────┘
                                                   └──────────┘
                              ┌────────────────────────────────────────┐
                              │ worker  —  APScheduler / Celery beat   │
                              │ • roster horizon scan (15 min)         │
                              │ • SLA snapshot (hourly + nightly seal) │
                              │ • rule sync (hourly)                   │
                              │ • AI briefing generation (nightly)     │
                              └────────────────────────────────────────┘

   MCP servers — one container each, each holding ONLY its own credentials:
   ┌──────────────┬──────────────┬──────────────────┬───────────────┐
   │ mcp-roster   │ mcp-soar     │ mcp-detection    │ mcp-grafana   │
   │ portal DB    │ SOAR REST    │ SIEM + content   │ Grafana HTTP  │
   │ (read-only   │ (read-only   │ repo + ATT&CK    │ API (read)    │
   │  DB role)    │  API token)  │ STIX             │               │
   └──────────────┴──────────────┴──────────────────┴───────────────┘
```

### 3.2 Why a Python core *and* a Next.js server

Because credentials and correctness both want to live in one place:

- **Blast radius.** The SOAR API token, Grafana token, and SIEM credentials never enter
  the Node process. A compromised frontend dependency (the npm supply chain being what
  it is) cannot reach Splunk SOAR.
- **§2 requires it.** The deterministic dashboard endpoints and the agent's tools must be
  *the same functions*. Those functions are Python (matching your existing SOAR/Falcon
  tooling). So the dashboard API must be Python too.
- **The agent loop belongs next to the tools.** Retries, tool-result truncation, and scope
  injection are all easier in-process than across an HTTP hop.

Next.js is therefore a **BFF**: authentication, session, RBAC, rendering, and a streaming
proxy for chat. It is a genuinely thin server, and that is intentional.

### 3.3 Why MCP servers are separate containers, not in-process modules

MCP's stdio transport tempts you to spawn tool servers as subprocesses of `core`. Prefer
**separate containers speaking streamable HTTP** because:

- Each container gets **only its own secret** (Docker secrets, per-service env).
- A hung SOAR API call cannot block the roster tools.
- You can restart, version, and scale `mcp-soar` without touching the portal.
- Network policy can restrict `mcp-soar` to the SOAR host only, `mcp-grafana` to Grafana
  only — real egress control per integration.

The cost is four more containers. For a security product that is a bargain.

### 3.4 Request paths

**Dashboard panel (deterministic):**
```
browser → web (RSC, session check) → core /api/v1/sla/summary?customer=X&period=2026-07
        → core resolves user scope, asserts X ∈ scope
        → tool function get_sla_summary(X, period)  ← same fn the LLM calls
        → reads sla_facts snapshot in Postgres
        → JSON → rendered chart
```

**Chat message (agentic):**
```
browser → web /api/chat (session → user_id, allowed_customers)
        → core /api/v1/chat  (SSE)
            system prompt + tool schemas (filtered by role)
            LLM proposes tool call
            core INJECTS allowed_customers, ignoring any model-supplied tenant arg (§4.3)
            MCP call → result wrapped in untrusted-data envelope (§11.2)
            loop until final answer
            persist message + every tool call + evidence → chat_messages, audit_log
        → stream back tokens AND a visible tool transcript
```

The visible tool transcript is not a debug feature. It is how an analyst decides whether
to trust the answer, and it is the difference between a tool people use and a novelty.

---

## 4. Authentication, authorization, tenancy

> This answers your question directly: yes, this is about logging in to the web app —
> and, more importantly, about what you can see *after* you log in.

### 4.1 Authentication — admin-provisioned accounts only

**Decided:** there is no self-registration and no public sign-up. An **admin creates every
account**, sets its password, and assigns its role and tenant scope. This is the correct
model for an internal SOC tool — the user set is small, known, and changes only when
someone joins or leaves.

**Account lifecycle**
```
admin creates user (email, name, role, allowed customers, temp password)
        → user logs in with temp password
        → FORCED password change on first login (must_change_password flag)
        → optional: enrol TOTP (enforced per-role; recommended mandatory for admin + manager)
        → admin can: reset password, change role/scope, disable, delete
```

**Admin → Users screen** (its own module, build it in Phase 0):
list users with role, tenant scope, last login, MFA status, state; create/edit/disable;
force password reset; revoke all sessions for a user. Disable, never delete, when someone
leaves — `audit_log` rows must keep resolving to a real name.

**Mechanics**
- Argon2id password hashing (never bcrypt-with-defaults, never SHA-anything).
- Password policy: min 12 chars, breach-list check against a local HIBP-style hash set,
  no forced rotation (rotation drives password reuse — modern NIST guidance).
- Lockout / exponential backoff after repeated failures, per account *and* per source IP.
- **Sessions in Redis, not JWT-in-cookie.** You want instant revocation the hour an analyst
  leaves; a self-contained JWT stays valid until it expires. Cookie is `HttpOnly`, `Secure`,
  `SameSite=Lax`, with idle timeout (8h) and absolute timeout (12h — one shift).
- `core` trusts nothing from the browser. `web` mints a short-lived internal token carrying
  `user_id`, `roles`, `allowed_customer_ids`, signed with a shared key.
- Every auth event — login, failure, lockout, password reset, role change — to `audit_log`.

**OIDC stays as a seam, not a feature.** Keep the login path behind an `AuthProvider`
interface with one implementation (`LocalPasswordProvider`). If AD/Entra is approved later,
that is a second implementation and a role-mapping table — no change to sessions, RBAC, or
tenancy. Do not build it now; do not design it out either.

```
users(id, email, full_name, password_hash, role, allowed_customer_ids[],
      totp_secret_enc, mfa_enrolled, must_change_password,
      state /*active|disabled*/, failed_attempts, locked_until,
      last_login_at, created_by, created_at, disabled_at, disabled_by)
```

### 4.2 Roles (what may you do)

| Role | Sees | Notable rights |
|---|---|---|
| `l1_analyst` | own perf, own shifts, tenant dashboards in scope | cannot see peers' perf |
| `l2_analyst` | + team perf, all cases in scope | QA review |
| `soc_engineer` | + detection rules, MITRE, rule drift | propose rule changes |
| `shift_lead` | + full roster edit, notification ack | publish roster |
| `soc_manager` | everything, all tenants | approve customer-facing reports |
| `account_manager` | SLA + AI briefing for assigned tenants only | export customer report |
| `admin` | + user/role/integration config | secrets rotation |
| `customer_readonly` *(optional, later)* | one tenant, curated views only | no analyst names |

Two design notes that matter:

- **L1 performance data is personal data about employees.** Default it to
  self + management visibility, not a public leaderboard (see §6.4 and §15.4).
- `customer_readonly` is deliberately deferred. Exposing a portal to customers changes the
  threat model (untrusted users inside the app) and should be a separate hardening project.

### 4.3 Tenancy — **authorization is not a prompt**

The single most important security rule in this system:

> **The LLM must never be trusted to filter by customer.**

Never write "you may only access data for Hooli Stream" in a system prompt and consider the job
done. Case titles, alert names, and rule descriptions all contain attacker-controlled text;
a crafted alert name can and will try to talk your model into querying another tenant.

Enforcement is structural, at three layers:

1. **Session layer.** `allowed_customer_ids` is resolved from the database at login and
   carried in the server-side session. The browser never supplies it.
2. **Tool-invocation layer.** When the model emits a tool call, `core` **overwrites** the
   tenant parameter with the session's allowed set. A model-supplied `customer_id` outside
   scope is not an error to explain — it is silently replaced, and the attempt is logged as
   a security event.
3. **Data layer.** Postgres **row-level security** policies on every tenant-scoped table,
   keyed off a session GUC set per connection. Even a SQL-injection-shaped bug in a tool
   cannot cross tenants.

Three independent layers, because the first two are code you will change often.

### 4.4 Audit

Every request that touches customer data writes to `audit_log`: actor, role, tenant,
action, tool name, parameters (redacted), result row count, latency, trace ID. For an MSSP
this is contractual, not optional. Retention 400 days, append-only table, separate DB role
with `INSERT` only.

---

## 5. Data ownership and the data model

### 5.1 Ownership map — read this before designing any table

| Domain | Owner | Portal behaviour |
|---|---|---|
| People, shifts, roster, absences | **Portal** | full CRUD, source of truth |
| Notifications | **Portal** | generated + acknowledged here |
| Cases, SLA clocks | Splunk SOAR | **projection**: snapshot into `sla_facts` |
| L1 activity | Splunk SOAR (+ QA Analyzer) | projection into `analyst_facts` |
| Detection rules, enabled state | SIEM | projection + drift history |
| MITRE technique catalogue | MITRE ATT&CK STIX | versioned import |
| Rule→technique mapping | **Portal** (curated) | CRUD, this is your IP |
| SOC performance metrics | Grafana | read-through, cached |

**Shifts are the only domain where the portal is the system of record.** That is why
Phase 1 builds it first (§13) — zero integration risk, immediate standalone value.

**Rule→technique mapping is the second thing you own** and is genuinely valuable
institutional knowledge. It should be editable, reviewable, and versioned in the portal —
not scraped from rule names.

### 5.2 Core schema (abridged; every tenant table carries `customer_id` + RLS)

**People and roster**
```
people(id, full_name, email, phone, role, tier /*L1|L2|L3|ENG*/,
       employment_status, hired_at, left_at,
       mattermost_user_id, soar_username, siem_username, timezone)
       -- soar_username is the join key that makes §6.4 possible. Get it right.

teams(id, name, kind /*analyst|engineering*/, lead_person_id)
team_members(team_id, person_id, from_date, to_date)

shift_templates(id, team_id, name, start_local, end_local,
                crosses_midnight bool, days_of_week[], timezone, min_headcount)

roster_periods(id, team_id, starts_on, ends_on,
               status /*draft|published|archived*/, published_by, published_at)
       -- "3 days left" is measured against MAX(ends_on) of published periods

shift_assignments(id, roster_period_id, shift_template_id, person_id,
                  on_date, starts_at_utc, ends_at_utc,
                  role_in_shift /*lead|analyst|oncall|standby*/,
                  status /*planned|confirmed|swapped|absent*/, swapped_from_id)

absences(id, person_id, kind /*leave|sick|training|holiday*/, from_utc, to_utc, approved_by)
```

**Notifications**
```
coverage_policies(id, team_id|null, customer_id|null, kind, params jsonb,
                  severity_thresholds jsonb, enabled, channels[])

notifications(id, policy_id, dedup_key, subject_type, subject_id, customer_id|null,
              severity /*info|warn|critical*/, title, body, evidence jsonb,
              state /*open|acked|snoozed|resolved*/, first_seen_at, last_seen_at,
              acked_by, acked_at, snooze_until, resolved_at, resolved_reason)
              -- UNIQUE(dedup_key) WHERE state IN ('open','snoozed')
notification_deliveries(id, notification_id, channel, target, sent_at, status, error)
```

**Customers and SLA**
```
customers(id, name, code, tier, timezone, business_hours jsonb, contract_from, contract_to,
          soar_label /*e.g. initech*/, active)

sla_policies(id, customer_id, severity, metric /*ack|triage|notify|resolve*/,
             threshold_minutes, business_hours_only bool,
             pause_on_states[] /*e.g. awaiting_customer*/, effective_from, effective_to)
             -- effective_from/to means historic reports use the contract that was live then

sla_facts(case_id, customer_id, severity, opened_at, ack_at, triage_at, notify_at, resolve_at,
          paused_minutes, metric, elapsed_minutes, threshold_minutes, met bool,
          breach_minutes, closed_by_person_id, disposition, snapshot_at, sealed bool)
          -- one row per (case, metric). Immutable once sealed. This is the report source.
```

**Analyst performance**
```
analyst_facts(person_id, customer_id, period /*date or week*/,
              cases_handled, cases_closed, cases_escalated, escalations_confirmed_tp,
              mttt_minutes_p50, mttt_minutes_p90,
              qa_sampled, qa_passed, qa_score_avg,
              shift_minutes_scheduled, shift_minutes_active, snapshot_at)
```

**Detection content**
```
detection_rules(id, siem_rule_id, customer_id|null /*null = global*/, name, description,
                status /*enabled|disabled|draft*/, severity, risk_score,
                data_sources[], owner_person_id, created_at, last_modified_at,
                last_fired_at, alerts_30d, tp_30d, fp_30d, suppressed)

rule_state_history(id, rule_id, changed_at, field, old_value, new_value, changed_by, source)
              -- answers "why did detections drop in July"

attack_versions(id, version /*e.g. v17.1*/, imported_at, is_current)
attack_techniques(attack_version_id, technique_id, name, tactic_ids[], is_subtechnique,
                  parent_technique_id, platforms[], data_components[])

rule_technique_map(rule_id, technique_id, attack_version_id, confidence /*1-3*/,
                   mapped_by, mapped_at, validated_at, validation_method)

data_source_health(customer_id, data_source, status /*healthy|degraded|absent*/,
                   last_event_at, expected_eps, actual_eps, checked_at)
              -- WITHOUT this table your MITRE heatmap is fiction. See §6.6.
```

**Chat and AI**
```
chat_sessions(id, user_id, customer_scope[], title, model, created_at, archived)
chat_messages(id, session_id, role, content, tool_calls jsonb, evidence jsonb,
              input_tokens, output_tokens, latency_ms, created_at)
ai_briefings(id, kind /*daily|weekly|customer*/, customer_id|null, period_start, period_end,
             narrative_md, evidence jsonb, model, generated_at,
             status /*draft|approved|published*/, approved_by, approved_at)
             -- evidence is mandatory. See §8.3.
```

---

## 6. Module specifications

### 6.1 Analysts + shifts / 6.2 Engineers + shifts

Structurally one module with two team kinds. Do **not** build them twice.

**UI**
- Month/week roster grid: rows = people, columns = days, cells = shift chips.
- Coverage strip beneath the grid: per shift window, headcount vs `min_headcount`,
  red where under-staffed. This is the view a shift lead actually opens.
- Drag-to-assign, bulk pattern fill ("4 on / 4 off"), swap request flow.
- **Roster horizon bar** at the top: "Published through 2026-09-02 — 14 days remaining."
  Colour follows the same thresholds as the notifications.
- Import/export: CSV and Excel, because the roster currently lives in a spreadsheet and
  a migration path that refuses spreadsheets never completes.

**Rules to get right**
- Night shift crossing midnight: store `starts_at_utc`/`ends_at_utc` explicitly at assign
  time; never re-derive from local time at read time.
- DST: Azerbaijan does not currently observe DST, but the org timezone is configurable —
  compute UTC boundaries with a real tz library, always.
- An absence overlapping a published assignment is a **conflict**, surfaced as a
  notification, not a silent overwrite.

### 6.3 SLA reports per customer

**Where the numbers come from.** SOAR containers carry the SLA stage timestamps
(your `sla_stage_fast_forward.py` confirms stages already exist). `mcp-soar` reads them;
the worker materialises one `sla_facts` row per (case, metric).

**The snapshot rule.** Reports read `sla_facts`, never live SOAR. Reasons:

1. **Reproducibility.** A sealed month cannot change. If SOAR data is amended later, that
   is a new snapshot with an audit trail, not a silently different number in a PDF the
   customer already has.
2. **Policy versioning.** SLA thresholds change with contract renewals. `sla_facts` stores
   the threshold *that applied at the time*, so history stays honest.
3. **Speed.** Executive dashboards over a year of SOAR REST queries are unusable.

Sealing: hourly snapshot for the current period (mutable), nightly seal for closed days,
month-end seal that flips `sealed=true` and makes rows immutable.

**Clock semantics — decide these explicitly, they are the usual source of disputes:**
- Business-hours-only SLAs pause outside `customers.business_hours`.
- `pause_on_states` stops the clock while awaiting customer response.
- Reopened cases: does the clock resume or restart? *Recommendation:* new metric row with
  `reopen_seq`, so both "first response" and "total" are reportable.

**Report surface**
- Per customer: compliance % by severity, breach list with drill-through to the case,
  trend vs prior period, MTTA/MTTT/MTTR at p50/p90 (never mean alone — one 40-hour
  outlier destroys a mean and hides the typical experience).
- Cross-customer executive grid: one row per tenant, RAG status, sparkline.
- Export: PDF/XLSX with a generated-at stamp, snapshot ID, and the policy version used.

### 6.4 Performance summary for L1s

**Metrics** (per analyst, per period, from `analyst_facts`):

| Category | Metric |
|---|---|
| Throughput | cases handled, cases closed, cases per active hour |
| Speed | time-to-first-touch p50/p90, time-to-triage p50/p90 |
| Quality | escalation precision (escalations confirmed TP by L2), false-close rate from QA sampling, QA score |
| Discipline | shift adherence, unhandled queue time during their shift |

Your existing **QA Analyzer** project is the natural feed for the quality column — wire it
in rather than inventing a second scoring scheme.

**Design guardrail — and this one is not optional.** Never ship a raw leaderboard ranked by
case volume. It is the fastest known way to damage a SOC: analysts optimise for closes, and
false-negative rate rises silently while the dashboard turns green. Therefore:

- Every throughput metric is displayed **paired with a quality metric**. Volume alone is
  never sortable on its own screen.
- Individual figures default to **self + management** visibility.
- The framing in the UI is **coaching**, not ranking: "vs team median", "trend for this
  analyst", not "#4 of 11".

State this in the product, not just in the docs — put the pairing rule in the panel copy.

### 6.5 AI agent analysis for SOC performance (Grafana)

Grafana holds the operational metrics. `mcp-grafana` queries datasources and dashboard
panels; the worker runs a **scheduled briefing agent**, nightly and weekly.

**Pipeline**
```
1. worker assembles the metric pack for the period (deterministic tool calls)
2. compares vs prior period and vs 8-week baseline; flags deltas beyond a threshold
3. LLM receives ONLY the computed pack and writes a narrative
4. stored as ai_briefings with evidence = the exact tool calls + values it saw
5. status=draft → a human approves before anything customer-facing is published
```

**Why scheduled, not on page load:** cheaper, faster to open, reviewable, and the same
briefing text is what everyone discusses in the morning standup. A "Regenerate" button
covers ad-hoc needs.

**Provenance is mandatory.** Every claim in the narrative links to the number behind it.
An unattributed LLM paragraph in front of a CISO is a liability; the same paragraph with
click-through evidence is an asset. Enforce it in the prompt *and* validate it in code:
reject a briefing whose narrative cites figures absent from the evidence pack.

### 6.6 MITRE mapping

**Import** ATT&CK Enterprise STIX, **pinned to a version** (`attack_versions`). Technique IDs
get renamed and deprecated across releases; an unpinned import silently rewrites your
historical coverage.

**The coverage heatmap** — tactics as columns, techniques as cells — but coloured by a
composite score, not by rule count:

```
coverage(technique, customer) = f(
    enabled rules mapped to it,
    mapping confidence,
    data_source_health for the sources those rules need,
    validated_at recency  (has anything proven it fires?)
)
```

**This is the part everyone gets wrong.** A rule mapped to T1059.001 whose data source is
not onboarded for that tenant is **not coverage** — it is a green cell that lies. Because
tenants onboard different log sources, coverage is **per customer** and the heatmap must be
tenant-scoped by default. A "global" view is a management summary, not an operational one.

**Views to build**
- Per-customer heatmap with drill-through: cell → rules → data sources → last fired.
- Gap report: techniques with zero enabled coverage, ranked by threat relevance to that
  customer's sector.
- Coverage drift over time — did we get better or worse this quarter?
- Optional later: overlay a threat-actor's technique set (Navigator layer import) to answer
  "are we covered against this actor for this customer?"

### 6.7 Enabled rules

**Sync** from the SIEM hourly via `mcp-detection`. Every observed change writes
`rule_state_history` — this table is what answers the recurring executive question
*"why did our alert volume drop last month?"*

**Panels**
- Inventory: filter by customer, status, severity, data source, owner, MITRE technique.
- **Noise ranking:** top rules by alert volume, with TP rate beside it. High volume + low TP
  = tuning candidate.
- **Dead rules:** enabled, zero alerts in 90 days. Either the logic is broken, the data
  source died, or the threat is absent — all three are worth knowing, and only this panel
  surfaces them.
- **Drift feed:** who enabled/disabled what, when, and (where the SIEM reports it) why.
- **Unmapped rules:** enabled but no MITRE mapping — the work queue for §6.6.

### 6.8 The chat

- Streaming SSE, with a **visible tool transcript** (tool name, parameters, row counts,
  latency) that a user can expand.
- **Session-scoped tenancy:** the user picks the customer scope when starting a chat, and
  tools are bound to it for the session's life. Cross-tenant questions require a role that
  permits it and are explicitly labelled in the transcript.
- **Saved recipes:** "Monday SLA briefing for {customer}", "MITRE gaps for {customer}",
  "who is on shift tonight and what is unassigned". Most real usage is a handful of
  repeated questions — make them one click, and the free-text box the escape hatch.
- **Every message persisted** with tool calls, tokens, latency, and trace ID.
- **Explicit refusal to guess:** if a tool returns nothing, the model says so. Prompt it
  to prefer "no data for that period" over inference. Test this case deliberately.

---

## 7. The MCP layer

### 7.1 Conventions for all servers

- **Read-only in v1.** No tool mutates SOAR, the SIEM, or Grafana. Write actions arrive
  later, behind explicit human confirmation in the UI, never model-initiated.
- **Tenant argument is authoritative from the session** (§4.3), not from the model.
- **Bounded results.** Every list tool takes `limit` (default 50, hard cap 500) and returns
  `total_count` separately, so the model knows it saw a subset.
- **Aggregates over rows** (§2.2). If a tool can return a summary, it returns a summary.
- **Typed errors.** `{error: "upstream_unavailable", retryable: true}` — never a stack trace,
  never a silent empty list, because "no data" and "SOAR is down" must not look identical.
- **Deterministic period parsing.** Tools accept ISO periods (`2026-07`, `2026-07-01..2026-07-31`),
  not "last month" — relative dates are resolved by `core` against the org timezone before
  the tool is invoked.

### 7.2 `mcp-roster` — portal's own data

| Tool | Returns |
|---|---|
| `get_shift_coverage(team, date_range)` | per-window headcount vs minimum, gaps |
| `who_is_on_shift(at_time, team?)` | people currently/then on duty, with roles |
| `get_roster_horizon(team?)` | last published date, days remaining, status |
| `list_unassigned_shifts(date_range)` | shifts below minimum headcount |
| `get_absences(date_range, team?)` | approved absences overlapping the range |
| `get_person_schedule(person, date_range)` | one person's assignments |

### 7.3 `mcp-soar` — Splunk SOAR (read-only)

| Tool | Returns |
|---|---|
| `get_sla_summary(customer, period, severity?)` | compliance %, counts, percentiles |
| `list_sla_breaches(customer, period, limit)` | breached cases with elapsed vs threshold |
| `get_case_volume(customer, period, group_by)` | counts by severity/disposition/label |
| `get_analyst_summary(person?, period, customer?)` | the `analyst_facts` row set |
| `get_case_detail(case_id)` | one case, redacted, tenant-checked |
| `get_automation_rate(customer, period)` | Automated / Hybrid / Manual split — maps directly onto your `execution_mode` field |

That last tool is nearly free given your existing automation architecture, and
"what % of cases did automation fully handle for this customer" is exactly the kind of
number an executive portal exists to show.

### 7.4 `mcp-detection` — MITRE + rules

| Tool | Returns |
|---|---|
| `get_mitre_coverage(customer, tactic?)` | per-technique coverage score + inputs |
| `list_coverage_gaps(customer, min_severity?)` | techniques with no effective coverage |
| `list_rules(customer?, status?, data_source?, technique?, limit)` | rule inventory slice |
| `get_rule_detail(rule_id)` | rule + mappings + 30d stats + history |
| `get_rule_drift(period, customer?)` | enable/disable changes in the period |
| `list_noisy_rules(customer, period, limit)` | volume + TP rate ranking |
| `list_dead_rules(customer, days=90)` | enabled, never fired |
| `get_data_source_health(customer)` | per-source status and last event |

### 7.5 `mcp-grafana` — SOC performance metrics

| Tool | Returns |
|---|---|
| `list_dashboards(folder?)` | available dashboards |
| `query_metric(metric_key, period, customer?)` | a named, curated metric series |
| `get_soc_metric_pack(period, customer?)` | the full briefing pack (§6.5) |
| `compare_periods(metric_key, period_a, period_b)` | delta + significance |

Note `query_metric` takes a **metric key from a curated registry**, not a raw PromQL/SQL
string. Letting a model author datasource queries is both a reliability problem and an
injection surface. Curate perhaps 30 metrics; add more as they are actually asked for.

---

## 8. The agent service

### 8.1 Loop

Standard tool-calling loop with hard limits: max 8 tool calls per turn, max 60s wall clock,
max tool-result size 8 KB per call (truncate with an explicit `[truncated, N of M rows]`
marker so the model knows). Exceeding limits ends the turn with a partial answer plus a
statement of what was cut — never a silent truncation.

### 8.2 System prompt structure

1. Role and scope (SOC ops assistant for *these* tenants, this user's role)
2. **Hard rules:** never compute figures the tools did not return; never infer missing data;
   always name the period and tenant in the answer
3. Tool catalogue (filtered by role — an `l1_analyst` never sees peer-performance tools)
4. Org context: timezone, shift windows, customer list, current date
5. Output conventions: numbers with units and period, evidence references

### 8.3 Evidence records

Every assistant message stores an `evidence` object: the tool calls made, their parameters
after scope injection, result digests, and the snapshot IDs consulted. The UI renders it.
Executive output without provenance is not shippable — this is the mechanism.

---

## 9. Notification engine

Your requirement — *"if the analyst/engineer list is not updated, or close to the end
(3 days left), notify"* — generalised into a policy engine rather than a hardcoded check,
because there will be a fourth and fifth condition within a month.

### 9.1 Policy kinds (v1)

| Kind | Fires when | Default thresholds |
|---|---|---|
| `roster_horizon` | published roster ends soon | info 14d, **warn 7d, critical 3d** |
| `roster_stale` | no roster edit for N days while horizon shrinks | warn 10d |
| `shift_understaffed` | assigned headcount < `min_headcount` | critical, any future shift |
| `shift_unassigned` | a required shift has nobody | critical |
| `absence_conflict` | approved absence overlaps a published assignment | warn |
| `oncall_gap` | no on-call for a window | critical |
| `sla_at_risk` | live case past X% of its threshold | warn 80%, critical 95% |
| `data_source_down` | a source feeding enabled rules stops | critical |
| `rule_drift_unreviewed` | rules disabled without a linked change record | warn |

The first six ship in Phase 1 (portal-owned data only, no integration dependency). The last
three arrive with their modules.

### 9.2 Evaluation and lifecycle

Worker evaluates every 15 minutes. Each finding produces a stable `dedup_key`
(`policy_id : subject_id : severity_bucket`).

```
open ──ack──► acked ──(condition clears)──► resolved
  │                                             ▲
  └──snooze──► snoozed ──(snooze expires)───────┘ back to open
```

**Anti-fatigue rules, which decide whether anyone keeps the feature turned on:**
- Re-notify **only on severity escalation** (7d → 3d re-fires; 5d → 4d does not).
- Auto-resolve when the condition clears, with a resolution note.
- Digest mode per channel: Mattermost gets one grouped message per evaluation cycle, not
  one message per finding.
- Quiet hours per channel for `info`; `critical` always breaks through.

### 9.3 Channels

In-app bell (authoritative), **Mattermost webhook** (you already run it — this is where
people will actually see it), email for `critical`, and an optional webhook out for anything
else. Every attempt logged in `notification_deliveries`; a failed Mattermost post must not
lose the notification.

---

## 10. LLM strategy — the honest answer

You asked whether running locally matters. It does, and here is the shape of it.

### 10.1 What the workload actually demands

Not creative writing — **reliable multi-step tool use**: pick the right tool, fill arguments
correctly, chain two or three calls, and refuse to invent anything. That capability falls off
a cliff below roughly 30B parameters, and the failure mode is the dangerous kind: fluent,
confident, wrong.

### 10.2 Rough tiers

| Option | Tool-use quality | Data leaves network | Notes |
|---|---|---|---|
| Claude (API / Bedrock / Vertex) | excellent | yes (Bedrock/Vertex: your tenancy) | best answer quality, needs approval |
| Local 70B class (Llama 3.3 70B, Qwen 2.5/3 72B) | good | no | ~2×A100-80G or 4×L40S |
| Local 30–35B class (Qwen3-32B) | workable **with §2.2 tools** | no | 1×A100-80G / 2×L40S — realistic floor |
| Local 7–14B | not viable for agentic use | no | fine for summarising a pre-built pack |

### 10.3 The recommendation

**Build provider-agnostic and start local.** Every model call goes through one interface
speaking the OpenAI-compatible protocol; vLLM, Ollama, LiteLLM, Bedrock, and the Anthropic
API all sit behind it. Model choice becomes an env var, and you can benchmark honestly
instead of arguing.

Then make local work by design, not by hope:

1. **Fat tools** (§2.2) — every tool returns ≤ 20 labelled values. The model orchestrates;
   it never aggregates.
2. **Deterministic UI paths** — dashboards do not call the LLM at all. If the model is
   unavailable, the portal still works, minus chat. That is a real availability property.
3. **Templated briefings** — the nightly briefing is a filled template with LLM prose in
   defined slots, not a free composition. Small models do slot-filling well.
4. **Constrained decoding** for tool arguments where the runtime supports it.
5. **A regression suite of ~50 golden questions** with known-correct answers, run against
   any model before it is allowed to be the default. This is how you tell "the 32B is fine"
   from "the 32B looks fine."

That last item is the thing that turns the model choice from a debate into a measurement,
and it is cheap to build. Do it in Phase 1 with three questions and grow it.

### 10.4 Swapping models: exactly how much is config, and what is not

You asked whether changing the model is just a name + API key change, or a code change.
**Both, in different senses — and the architecture is what keeps the code half at zero.**

**The plumbing: config only, permanently.** Put a **model gateway container in the compose
file** (LiteLLM proxy, or an equivalent). `core` is then hardcoded to exactly one endpoint
it never changes:

```
core  ──── OpenAI-compatible HTTP ────►  litellm:4000  ───┬─► vllm / ollama    (local)
      (one base_url, forever)                          ├─► Anthropic API
                                                       ├─► Bedrock / Vertex
                                                       └─► anything else
```

Swapping the model is then editing one YAML block and restarting one container:

```yaml
model_list:
  - model_name: soc-default              # core only ever asks for this name
    litellm_params:
      model: openai/Qwen3-32B            # ← change this line
      api_base: http://vllm:8000/v1      # ← and this
      api_key: os.environ/LLM_API_KEY    # ← and this
```

`core` never learns which model it is talking to. No Python changes, no rebuild, no redeploy
of the portal. The gateway also gives you retries, timeouts, fallback chains
(*local → hosted on failure*), per-user rate limits, and token accounting for free — all
things you would otherwise write by hand.

**The behaviour: not free, and pretending otherwise is the trap.** The *interface* is
identical across models; the *competence* is not. Concretely, what can change with a swap:

| What may break on a model swap | Why | What absorbs it |
|---|---|---|
| Tool-argument accuracy | models format arguments differently | strict JSON schemas + a repair retry |
| Tool selection | weaker models pick the wrong tool | fat tools (§2.2), fewer of them, blunt names |
| Following "never invent numbers" | instruction adherence varies | evidence validation in code (§8.3) |
| Native tool-calling support | some models lack it | gateway can emulate; verify before adopting |
| Prompt length tolerance | small models degrade on long system prompts | role-filtered tool catalogue (§8.2) |

So the rule is: **swapping is a config change; *adopting* is a measurement.** Change the
YAML, run the golden-question suite (§10.3 item 5), compare pass rate. If it passes, it is
adopted. That takes minutes and replaces an unwinnable argument with a number.

Everything in this document is already built to make that true: the model does not compute,
does not authorize, and does not decide scope — so a weaker model produces a *less helpful*
portal, never a *wrong* one. That is the property worth protecting, and it is what makes
"just change the name and key" honest rather than wishful.

### 10.5 If a hosted model is ever approved

Nothing changes but an env var — and one policy decision about what may be sent. Keep an
outbound redaction layer in `core` (customer names → tenant codes, hostnames → tokens) as a
seam even if unused on day one; retrofitting it later is much harder.

---

## 11. Security model

### 11.1 Standard posture

TLS at the edge with HSTS; strict CSP; no third-party scripts (an SOC portal must not phone
out to a CDN); secrets via Docker secrets or a vault, never baked images; per-service DB
roles, read-only where possible; RLS on tenant tables; dependency and image scanning in CI;
containers non-root, read-only rootfs where feasible.

### 11.2 Prompt injection — the threat unique to this design

Case titles, alert names, filenames, and rule descriptions are **attacker-controlled text**
that flows into your model's context. Assume every tool result is hostile.

Mitigations:
- **Structural tenancy** (§4.3) — injection cannot widen scope, because scope is not in the
  prompt.
- **Read-only tools in v1** — the worst outcome of a successful injection is a wrong answer,
  not a changed case or a disabled rule.
- **Untrusted-data envelopes** — tool results are wrapped and explicitly labelled as data,
  never instructions, with the system prompt stating that content inside envelopes is never
  to be followed.
- **No egress from the model runtime** — a local model with no network cannot exfiltrate,
  which is a genuine argument in favour of local inference.
- **Human confirmation for any future write tool**, expressed in the UI with the exact
  action shown before it runs.

### 11.3 Data sensitivity

L1 performance data is **personal data about employees**. Access-control it (§4.2), decide a
retention period deliberately, and be able to answer "who looked at my numbers" from
`audit_log`. If any part of this portal is later exposed to customers, that is a separate
threat model and a separate review.

---

## 12. Observability and operations

- **OpenTelemetry** traces spanning `web → core → mcp-* → upstream`, so "the SLA page is
  slow" resolves to a specific SOAR call without guesswork.
- **Portal metrics into Grafana** — you already run it. Dashboard the portal's own health
  alongside the SOC's, including tool-call success rate and p95 latency per MCP tool.
- **Health endpoints** per container; `core` exposes upstream reachability so a degraded
  SOAR shows as a banner rather than as a blank chart.
- **Backups:** nightly `pg_dump` plus WAL archiving; restore tested quarterly. `sla_facts`
  and `audit_log` are the crown jewels — everything else is reconstructible from upstream.
- **Migrations:** Alembic, forward-only, run as an init container before `core` starts.

---

## 13. Delivery phases

Ordering principle: **start with the domain you own, and prove the full stack vertically
before going wide.** Chat arrives early but narrow, so the pattern is validated once and
reused, rather than being a big-bang integration at the end.

**Phase 0 — Foundation (1–2 weeks)**
Docker Compose skeleton, Postgres + Alembic, Next.js shell with nav, admin-provisioned
local auth + forced first-login password change + TOTP, **Admin → Users screen**, RBAC
middleware, customers table + tenant scoping + RLS, audit log, LiteLLM gateway container
wired to a local model, CI with lint/test/image scan. *Exit:* an admin can create three
users with different roles and tenant scopes, and each sees correctly different navigation.

**Phase 1 — Roster + notifications + first chat (2–3 weeks)**
People, teams, shift templates, roster periods, assignments, absences. Roster grid UI with
coverage strip and horizon bar. Worker + first six notification policies. Mattermost
delivery. `mcp-roster`. **Chat wired end-to-end over roster tools only.** Golden-question
suite v0. *Exit:* "who is on shift tonight and when does the roster run out" works in chat
and on screen, and the 3-day warning has fired for real.

**Phase 2 — Detection content (2–3 weeks)**
`mcp-detection`, SIEM rule sync, rule inventory, drift history, noisy/dead rule panels,
ATT&CK STIX import, mapping CRUD, `data_source_health`, coverage heatmap. *Exit:* a
per-customer heatmap whose green cells you would personally defend.

**Phase 3 — SLA + L1 performance (3–4 weeks)**
`mcp-soar`, `sla_policies`, snapshot worker, sealing, SLA report UI, exports, `analyst_facts`,
L1 panels with paired quality metrics, QA Analyzer feed. *Exit:* a customer-ready monthly
SLA report generated from a sealed snapshot, reproducible on demand.

**Phase 4 — Grafana + AI briefings (2 weeks)**
`mcp-grafana`, curated metric registry, metric pack, scheduled briefing agent, evidence
validation, approval workflow. *Exit:* a nightly briefing a manager reads before standup.

**Phase 5 — Executive layer + hardening (2 weeks)**
Cross-tenant executive overview, scheduled report delivery, saved chat recipes, full golden
suite, load test, pen-test pass, runbooks. *Exit:* handover-ready.

Roughly 12–16 weeks for one focused engineer; less with two, since Phase 2 and Phase 3 are
independent after Phase 1.

---

## 14. Open decisions (need your input before build)

1. **Local model and hardware.** Which GPU is actually available? This sets the model tier
   and therefore how "fat" the tools must be. If it is one 24 GB card, the chat becomes
   summarise-a-prepared-pack rather than agentic, and that is a legitimate v1.
2. ~~AD/Entra availability~~ — **decided:** admin-provisioned local accounts only (§4.1).
   Remaining sub-question: is TOTP MFA mandatory for all roles, or only admin/manager?
3. **SLA clock semantics.** Business hours or 24×7 per customer? Do reopened cases restart
   the clock? These are contract questions, and they must be answered before §6.3 is coded.
4. **QA sampling process.** Does a formal L1 QA review exist today with a rate and rubric?
   Without one, §6.4's quality column is empty and the throughput metrics stand alone —
   which §15.4 says is harmful.
5. **SIEM rule access.** Read API/credentials for Splunk saved searches — or is the rule
   inventory maintained somewhere else (Git content repo)?
6. **Customer-facing or internal only?** Big fork. Internal-only is assumed throughout.
7. **Roster today.** Which spreadsheet, and can I see a sample? It determines the import
   mapping and the real shift patterns.

---

## 15. Anti-patterns this design specifically prevents

**15.1 The LLM computes an executive number.**
*Failure:* a plausible, confidently wrong SLA percentage reaches a customer. Silent.
*Prevention:* §2.1 — deterministic compute, LLM narrates only; §8.3 evidence validation.

**15.2 Tenant leakage through the model.**
*Failure:* injected text in a case title persuades the model to query another customer.
*Prevention:* §4.3 — three structural layers, none of them a prompt.

**15.3 MITRE coverage theater.**
*Failure:* a green heatmap over data sources that are not onboarded; a real incident walks
through a "covered" technique.
*Prevention:* §6.6 — coverage scored on data-source health and validation recency, and
scoped per customer.

**15.4 The L1 leaderboard.**
*Failure:* analysts optimise for close volume; false-negative rate rises invisibly.
*Prevention:* §6.4 — paired quality metrics, restricted visibility, coaching framing.

**15.5 Live-queried reports.**
*Failure:* last month's report returns a different number this month; nobody can say why.
*Prevention:* §6.3 — immutable sealed snapshots with policy versions attached.

**15.6 Notification fatigue.**
*Failure:* the same "3 days left" every 15 minutes; within a week everyone mutes the channel
and the feature is dead.
*Prevention:* §9.2 — dedup keys, escalation-only re-fire, digests, quiet hours.

**15.7 Credential sprawl.**
*Failure:* one `.env` holds SOAR, SIEM, and Grafana tokens; one compromised container takes
the estate.
*Prevention:* §3.3 — per-MCP containers, per-service secrets, restricted egress.

**15.8 A chatbot bolted onto a dashboard.**
*Failure:* two code paths, drifting numbers, double maintenance.
*Prevention:* §2 — one tool layer, two consumers.
