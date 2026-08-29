"""SOAR/SLA tool functions — the deterministic layer.

Each tool runs a validated Splunk search and returns a small, labelled result.
`tenant` scopes the result server-side: in production the core injects it from
the session (never from the model). "all" means every in-scope customer.
The model orchestrates these; it never aggregates.
"""
from __future__ import annotations

from splunk_client import SplunkClient
import queries

# customer id <-> dashboard label (hooli_media is labelled hooli_stream there)
_LABEL_TO_ID = {"hooli_stream": "hooli_media"}
_ID_TO_LABEL = {v: k for k, v in _LABEL_TO_ID.items()}


def _norm_customer(row_label: str) -> str:
    return _LABEL_TO_ID.get(row_label, row_label)


def _scope(rows: list[dict], tenant: str, key: str = "customer") -> list[dict]:
    for r in rows:
        if key in r:
            r[key] = _norm_customer(r[key])
    if tenant and tenant != "all":
        rows = [r for r in rows if r.get(key) == tenant]
    return rows


def _num(rows: list[dict], fields: list[str]) -> list[dict]:
    for r in rows:
        for f in fields:
            if f in r and r[f] not in (None, ""):
                try:
                    r[f] = float(r[f]) if "." in str(r[f]) else int(r[f])
                except ValueError:
                    pass
    return rows


def get_sla_by_customer(client: SplunkClient, window: str = "7d", tenant: str = "all") -> list[dict]:
    """Per-customer SLA means (MTTA/MTTT/MTTR/MTTTres/MTTCR, seconds) + compliance %."""
    rows = client.oneshot(queries.sla_by_customer(window))
    rows = _num(rows, ["cases", "MTTA", "MTTT", "MTTR", "MTTTres", "MTTCR",
                       "compliance_MTTA", "compliance_MTTT", "compliance_MTTR", "compliance_MTTCR"])
    return _scope(rows, tenant, "customer")


def get_analyst_performance(client: SplunkClient, window: str = "30d") -> list[dict]:
    """Per-analyst throughput, triage p50, stage times (seconds) and triage-SLA %."""
    rows = client.oneshot(queries.analyst_performance(window))
    return _num(rows, ["cases", "triage_p50", "MTTA", "MTTR", "MTTTres", "triage_sla"])


def get_status_mix(client: SplunkClient, window: str = "7d") -> list[dict]:
    """Case-outcome distribution by SOAR status (count + percent)."""
    rows = client.oneshot(queries.status_mix(window))
    return _num(rows, ["count", "pct"])


def get_case_volume(client: SplunkClient, window: str = "7d", tenant: str = "all") -> list[dict]:
    """Case counts by customer and severity."""
    rows = client.oneshot(queries.case_volume(window))
    rows = _num(rows, ["cases"])
    return _scope(rows, tenant, "customer")
