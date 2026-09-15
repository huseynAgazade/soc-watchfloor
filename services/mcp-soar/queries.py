"""SPL query templates for the SOAR/SLA tools.

The SLA head (field extraction + the five stage-time evals) is lifted from the
production "SOC Incident Overview" dashboard so the numbers match it:
  MTTA    = sla_assignment_primary_end  - sla_assignment_primary_start
  MTTT    = sla_triage_primary_end      - sla_triage_primary_start
  MTTR    = sla_remediation_primary_end - sla_remediation_primary_start
  MTTTres = close_time - create_time            (full lifecycle, no threshold)
  MTTCR   = close_time - sla_waiting_customer_start
It excludes automated / unassigned / out-of-scope cases, as the dashboard does.

Fetching: the dashboard's query pulled the newest 3,000 containers and filtered
by date afterwards, so any window holding more than 3,000 containers (a busy week
on soc_soar) was silently cut short. Here SOAR applies the window itself
(create_time filter, no row cap), and the window is fetched in SLICE-sized pieces
stitched together with `append`, so no single restsoar call has to carry a whole
quarter of containers (~2.7 MB per thousand). All aggregation still happens in SPL.
"""
from __future__ import annotations

import os
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

_HEAD = open(os.path.join(os.path.dirname(__file__), "_sla_head.spl")).read()

SLICE = timedelta(days=14)          # measured fastest on soc_soar; see core app/datasources/spl.py
MAX_SPAN = timedelta(days=93)
ORG_TZ = ZoneInfo(os.environ.get("ORG_TIMEZONE", "Asia/Dubai"))
WINDOW_DAYS = {"7d": 7, "30d": 30, "60d": 60, "90d": 90}


def bounds_for_window(window: str, now: datetime | None = None) -> tuple[datetime, datetime]:
    """24h | 7d | 30d | 60d | 90d → (start, end) in UTC. Nd means from local
    midnight N days ago until now (Splunk's -Nd@d)."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if window == "24h":
        return now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=24), now
    if window not in WINDOW_DAYS:
        raise ValueError(f"unknown window: {window}")
    day = now.astimezone(ORG_TZ).date() - timedelta(days=WINDOW_DAYS[window])
    return datetime.combine(day, time.min, tzinfo=ORG_TZ).astimezone(timezone.utc), now


def check_bounds(start: datetime, end: datetime) -> None:
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("start and end must carry a timezone")
    if not start < end:
        raise ValueError("start must be before end")
    if end - start > MAX_SPAN:
        raise ValueError(f"window longer than {MAX_SPAN.days} days")


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _restsoar(start: datetime, end: datetime) -> str:
    return ('| restsoar soar_server="soc_soar" endpoint="/container?sort=id&order=asc&page_size=0'
            f'&_filter_create_time__gte=%22{_iso(start)}%22&_filter_create_time__lt=%22{_iso(end)}%22"')


def slices(start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    out, cur = [], start
    while cur < end:
        nxt = min(cur + SLICE, end)
        out.append((cur, nxt))
        cur = nxt
    return out


def _head(start: datetime, end: datetime) -> str:
    check_bounds(start, end)
    parts = slices(start, end)
    source = _restsoar(*parts[0]) + "".join(f"\n| append [{_restsoar(a, b)}]" for a, b in parts[1:])
    return _HEAD.replace("__SOURCE__", source)


def sla_by_customer(start: datetime, end: datetime) -> str:
    """Per-tenant means + compliance against the dashboard's severity thresholds."""
    return _head(start, end) + r"""
| eval MTTA_breach = case(severity IN ("critical","high") AND MTTA_sec>300,1, severity IN ("medium","low") AND MTTA_sec>600,1, 1=1,0)
| eval MTTT_breach = if(MTTT_sec>600,1,0)
| eval MTTR_breach = case(severity=="critical" AND MTTR_sec>1800,1, severity=="high" AND MTTR_sec>2700,1, severity=="medium" AND MTTR_sec>3600,1, severity=="low" AND MTTR_sec>5400,1, 1=1,0)
| eval MTTCR_breach = if(severity=="critical" AND MTTCR_sec>3600,1,0)
| stats avg(MTTA_sec) as MTTA avg(MTTT_sec) as MTTT avg(MTTR_sec) as MTTR avg(MTTRs_sec) as MTTTres avg(MTTCR_sec) as MTTCR
    sum(MTTA_breach) as bA sum(MTTT_breach) as bT sum(MTTR_breach) as bR sum(MTTCR_breach) as bCR count as cases by label
| eval MTTA=round(MTTA),MTTT=round(MTTT),MTTR=round(MTTR),MTTTres=round(MTTTres),MTTCR=round(MTTCR)
| eval compliance_MTTA=round(100-100*bA/cases,1), compliance_MTTT=round(100-100*bT/cases,1), compliance_MTTR=round(100-100*bR/cases,1), compliance_MTTCR=round(100-100*bCR/cases,1)
| rename label as customer
| table customer cases MTTA MTTT MTTR MTTTres MTTCR compliance_MTTA compliance_MTTT compliance_MTTR compliance_MTTCR
"""


def analyst_performance(start: datetime, end: datetime) -> str:
    """Per-analyst throughput + stage times + triage p50 + triage-SLA compliance."""
    return _head(start, end) + r"""
| eval MTTT_breach = if(MTTT_sec>600,1,0)
| stats count as cases avg(MTTA_sec) as MTTA avg(MTTT_sec) as MTTT perc50(MTTT_sec) as triage_p50
    avg(MTTR_sec) as MTTR avg(MTTRs_sec) as MTTTres sum(MTTT_breach) as tbreach by sla_owner_name
| eval triage_sla=round(100-100*tbreach/cases,1)
| eval MTTA=round(MTTA),MTTT=round(MTTT),triage_p50=round(triage_p50),MTTR=round(MTTR),MTTTres=round(MTTTres)
| search NOT sla_owner_name IN (soc.analyst, soc.ir, soc.tde)
| sort - cases
| rename sla_owner_name as analyst
| table analyst cases triage_p50 MTTA MTTR MTTTres triage_sla
"""


def status_mix(start: datetime, end: datetime) -> str:
    """Case counts by customer and SOAR status. Per customer so the caller can
    apply tenant scope before aggregating."""
    return _head(start, end) + r"""
| stats count by label status
| rename label as customer
| table customer status count
"""


def case_volume(start: datetime, end: datetime) -> str:
    """Case counts by customer and severity."""
    return _head(start, end) + r"""
| stats count as cases by label severity
| rename label as customer
| sort - cases
| table customer severity cases
"""
