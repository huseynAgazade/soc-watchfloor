# mcp-soar

**Source:** Splunk (running `restsoar` against Splunk SOAR) — the same path the
production *SOC Incident Overview* dashboard uses, so the numbers match it.

A read-only MCP server exposing SOAR/SLA tools. The core connects to it as a
tool provider; the assistant then calls these tools by name. Every tool returns
a small, labelled result set and is tenant-scoped.

## Tools

| Tool | Returns |
| --- | --- |
| `get_sla_by_customer(window, tenant)` | per-customer MTTA / MTTT / MTTR / MTTTres / MTTCR (mean seconds) + compliance % |
| `get_analyst_performance(window)` | per-analyst cases, triage p50, MTTA, MTTR, MTTTres, triage-SLA % |
| `get_status_mix(window)` | case-outcome distribution by SOAR status |
| `get_case_volume(window, tenant)` | case counts by customer and severity |

`window` ∈ `24h | 7d | 30d | 60d`. `tenant` is a customer id or `all`.

## SLA definitions (verbatim from the dashboard)

```
MTTA    = sla_assignment_primary_end  - sla_assignment_primary_start
MTTT    = sla_triage_primary_end      - sla_triage_primary_start
MTTR    = sla_remediation_primary_end - sla_remediation_primary_start
MTTTres = close_time - create_time            (full lifecycle, no threshold)
MTTCR   = close_time - sla_waiting_customer_start
```
Excludes automated / unassigned / out-of-scope cases. Compliance uses the
dashboard's severity thresholds (MTTA 5–10 min, MTTT 10 min, MTTR 30/45/60/90 min
by severity). `hooli_media` is labelled `hooli_stream` in Splunk; the tools
normalise it back to the customer id.

## Run

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env         # fill in SPLUNK_TOKEN (preferred) or SPLUNK_PASSWORD
python server.py             # MCP stdio server
```

## Test (live)

```bash
export $(grep -v '^#' .env | xargs)
python test_live.py          # authenticates, runs every tool, lists MCP tools
```

## Notes

- **Read-only.** No tool writes to SOAR or Splunk.
- **Auth:** prefer a Splunk token (`SPLUNK_TOKEN`). The password path uses the
  Splunk Web login + CSRF flow because the 8089 management port is closed from
  the app network.
- **Scope:** `tenant` is a parameter here; in production the core injects it from
  the session and never trusts a model-supplied value.
