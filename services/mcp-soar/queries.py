"""SPL query templates for the SOAR/SLA tools.

The SLA head (container fetch + field extraction + the five stage-time evals) is
lifted verbatim from the production "SOC Incident Overview" dashboard so the
numbers match it exactly:
  MTTA    = sla_assignment_primary_end  - sla_assignment_primary_start
  MTTT    = sla_triage_primary_end      - sla_triage_primary_start
  MTTR    = sla_remediation_primary_end - sla_remediation_primary_start
  MTTTres = close_time - create_time            (full lifecycle, no threshold)
  MTTCR   = close_time - sla_waiting_customer_start
It excludes automated / unassigned / out-of-scope cases, as the dashboard does.
"""
from __future__ import annotations

import os

_HEAD = open(os.path.join(os.path.dirname(__file__), "_sla_head.spl")).read()

# Splunk relative-time tokens by window name.
WINDOWS = {"24h": "-24h@h", "7d": "-7d@d", "30d": "-30d@d", "60d": "-60d@d"}


def _head(window: str) -> str:
    tok = WINDOWS.get(window, "-7d@d")
    return _HEAD.replace("__WIN__", tok)


def sla_by_customer(window: str = "7d") -> str:
    """Per-tenant means + compliance against the dashboard's severity thresholds."""
    return _head(window) + r"""
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


def analyst_performance(window: str = "30d") -> str:
    """Per-analyst throughput + stage times + triage p50 + triage-SLA compliance."""
    return _head(window) + r"""
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


def status_mix(window: str = "7d") -> str:
    """Case-outcome distribution by SOAR status."""
    return _head(window) + r"""
| stats count by status
| eventstats sum(count) as total
| eval pct=round(100*count/total,1)
| sort - count
| table status count pct
"""


def case_volume(window: str = "7d") -> str:
    """Case counts by customer and severity."""
    return _head(window) + r"""
| stats count as cases by label severity
| rename label as customer
| sort - cases
| table customer severity cases
"""
