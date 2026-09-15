"""Built-in catalog entries, seeded on first start. After seeding they live in the
database and are edited from Users & access → Data sources; editing never touches
this file, and "reset" restores the text below as a new version.

SOAR/SLA queries share two fragments (sla.head, sla.breaches) lifted from the
SOC Incident Overview dashboard. Agentic AI queries are the panels of the Splunk
dashboard initech_all_general/agentic_soc_summary, with a tenant filter added.
"""
from __future__ import annotations

from sqlalchemy import select

from ..db import SessionLocal
from ..models import DataQuery, DataQueryVersion

SLA_HEAD = r'''$soar_containers$
| rex max_match=0 field=_raw "(?<container_block>\{[^{}]*\"id\":\s?\d+.*?\})"
| mvexpand container_block
| rex field=container_block "\"create_time\":\s?\"(?<create_time_raw>[^\"]+)\""
| rex field=container_block "\"incident_category\":\s?\"(?<incident_category>[^\"]+)\""
| rex field=container_block "\"status\":\s?\"(?<status>[^\"]+)\""
| rex field=container_block "\"label\":\s?\"(?<label>[^\"]+)\""
| rex field=container_block "\"name\":\s?\"(?<name>[^\"]+)\""
| rex field=container_block "\"id\":\s?(?<id>\d+)"
| rex field=container_block "\"owner_name\":\s?\"(?<owner_name>[^\"]+)\""
| rex field=container_block "\"severity\":\s?\"(?<severity>[^\"]+)\""
| rex field=container_block "\"close_time\":\s?\"(?<close_time_raw>[^\"]+)\""
| spath input=container_block path=custom_fields output=custom_fields_json
| spath input=custom_fields_json
| fields - custom_fields_json
| fields id create_time_raw close_time_raw status label name owner_name severity sla_* active_sla_stage incident_category
| dedup id
| search NOT sla_owner_name IN ("", "unassigned") NOT status IN (new, "in progress", duplicate, testing) AND label!="" AND NOT label IN (events,test_label) AND label IN ($tenant_labels$)
| eval MTTA_sec=if(sla_assignment_primary_start!="" and sla_assignment_primary_end!="" and sla_assignment_primary_start < sla_assignment_primary_end, strptime(sla_assignment_primary_end, "%Y-%m-%d %H:%M:%S") - strptime(sla_assignment_primary_start, "%Y-%m-%d %H:%M:%S"), 0)
| eval MTTT_sec=if(sla_triage_primary_start!="" and sla_triage_primary_end!="" and sla_triage_primary_start < sla_triage_primary_end, strptime(sla_triage_primary_end, "%Y-%m-%d %H:%M:%S") - strptime(sla_triage_primary_start, "%Y-%m-%d %H:%M:%S"), 0)
| eval MTTR_sec=if(sla_remediation_primary_start!="" and sla_remediation_primary_end!="" and sla_remediation_primary_start < sla_remediation_primary_end, strptime(sla_remediation_primary_end, "%Y-%m-%d %H:%M:%S") - strptime(sla_remediation_primary_start, "%Y-%m-%d %H:%M:%S"), 0)
| eval MTTRs_sec = strptime(close_time_raw, "%Y-%m-%dT%H:%M:%S.%N%Z") - strptime(create_time_raw, "%Y-%m-%dT%H:%M:%S.%N%Z")
| eval MTTT_sec=if(MTTT_sec > MTTRs_sec, 0, MTTT_sec)
| eval MTTCR_sec = if(sla_waiting_customer_start!="" and close_time_raw!="", strptime(close_time_raw, "%Y-%m-%dT%H:%M:%S.%N%Z") - strptime(sla_waiting_customer_start, "%Y-%m-%d %H:%M:%S"), 0)
| eval MTTR_sec=if(MTTR_sec <= 0, MTTRs_sec-MTTT_sec-MTTA_sec-MTTCR_sec, MTTR_sec)
| eval MTTR_sec=if(MTTR_sec < 0, 0, MTTR_sec)'''

SLA_BREACHES = r'''| eval MTTA_breach = case(severity IN ("critical","high") AND MTTA_sec>300,1, severity IN ("medium","low") AND MTTA_sec>600,1, 1=1,0)
| eval MTTT_breach = if(MTTT_sec>600,1,0)
| eval MTTR_breach = case(severity=="critical" AND MTTR_sec>1800,1, severity=="high" AND MTTR_sec>2700,1, severity=="medium" AND MTTR_sec>3600,1, severity=="low" AND MTTR_sec>5400,1, 1=1,0)
| eval MTTCR_breach = if(severity=="critical" AND MTTCR_sec>3600,1,0)
| eval any_breach = if(MTTA_breach+MTTT_breach+MTTR_breach+MTTCR_breach>0,1,0)'''


def _q(id, name, category, spl, columns, *, description="", scope_mode="tenant_token", scope_field="",
       cache_seconds=300):
    return dict(id=id, name=name, category=category, spl=spl, columns=columns, description=description,
                scope_mode=scope_mode, scope_field=scope_field, cache_seconds=cache_seconds)


def _aisoc(event_type: str, rest: str, extra: str = "") -> str:
    return f"index=soc_aisoc sourcetype=aisoc:json tenant IN ($tenants$) event_type={event_type}{extra} {rest}"


_DUR = ('| eval d=round(secs,0), hh=floor(d/3600), mm=floor((d%3600)/60), ss=round(d%60,0), '
        'disp=case(hh>0,hh."h ".mm."m",mm>0,mm."m ".ss."s",1==1,ss."s") | fields disp secs')
_RANK = ('| eval sev_in=lower(severity_original), sev_out=lower(severity_adjusted) '
         '| eval rank_in=case(sev_in=="informational",0,sev_in=="info",0,sev_in=="low",1,sev_in=="medium",2,sev_in=="high",3,sev_in=="critical",4,1==1,-1), '
         'rank_out=case(sev_out=="informational",0,sev_out=="info",0,sev_out=="low",1,sev_out=="medium",2,sev_out=="high",3,sev_out=="critical",4,1==1,-1)')

SEED = [
    # ---- fragments ----
    _q("sla.head", "SOAR containers with SLA stage times", "fragment", SLA_HEAD, [],
       description="Containers created in the period (restsoar, sliced), filtered to assigned, resolved, in-scope "
                   "cases, with MTTA_sec/MTTT_sec/MTTR_sec/MTTRs_sec/MTTCR_sec. Include with $include:sla.head$.",
       scope_mode="tenant_token"),
    _q("sla.breaches", "SLA breach flags by severity", "fragment", SLA_BREACHES, [],
       description="MTTA/MTTT/MTTR/MTTCR breach flags against the dashboard's severity thresholds, plus any_breach. "
                   "Include after sla.head."),
    # ---- SLA ----
    _q("sla.by_customer", "SLA metrics by customer", "sla", r'''$include:sla.head$
$include:sla.breaches$
| stats avg(MTTA_sec) as MTTA avg(MTTT_sec) as MTTT avg(MTTR_sec) as MTTR avg(MTTRs_sec) as MTTTres avg(MTTCR_sec) as MTTCR sum(MTTA_breach) as bA sum(MTTT_breach) as bT sum(MTTR_breach) as bR sum(MTTCR_breach) as bCR sum(any_breach) as breached count as cases by label
| eval MTTA=round(MTTA),MTTT=round(MTTT),MTTR=round(MTTR),MTTTres=round(MTTTres),MTTCR=round(MTTCR)
| eval compliance_all=round(100-100*breached/cases,1), compliance_MTTA=round(100-100*bA/cases,1), compliance_MTTT=round(100-100*bT/cases,1), compliance_MTTR=round(100-100*bR/cases,1), compliance_MTTCR=round(100-100*bCR/cases,1)
| rename label as customer
| table customer cases breached MTTA MTTT MTTR MTTTres MTTCR compliance_all compliance_MTTA compliance_MTTT compliance_MTTR compliance_MTTCR''',
       ["customer", "cases", "breached", "MTTA", "MTTT", "MTTR", "MTTTres", "MTTCR", "compliance_all",
        "compliance_MTTA", "compliance_MTTT", "compliance_MTTR", "compliance_MTTCR"],
       description="Per-customer mean stage times (seconds), cases, breached cases and compliance %. "
                   "Feeds the SLA page and the Overview SLA tiles.", scope_field="customer"),
    _q("sla.daily", "SLA cases and breaches per day", "overview", r'''$include:sla.head$
$include:sla.breaches$
| eval day=strftime(strptime(create_time_raw, "%Y-%m-%dT%H:%M:%S.%N%Z"), "%Y-%m-%d")
| stats count as cases sum(any_breach) as breached by day label
| rename label as customer
| sort day
| table day customer cases breached''',
       ["day", "customer", "cases", "breached"],
       description="Daily case count and breached cases per customer — the Overview trend lines.",
       scope_field="customer"),
    _q("sla.status_mix", "Case outcomes by customer", "sla", r'''$include:sla.head$
| stats count by label status
| rename label as customer
| table customer status count''',
       ["customer", "status", "count"],
       description="Resolved cases per SOAR status and customer — the SLA page's case outcomes.",
       scope_field="customer"),
    _q("sla.case_volume", "Case volume by customer and severity", "sla", r'''$include:sla.head$
| stats count as cases by label severity
| rename label as customer
| sort - cases
| table customer severity cases''',
       ["customer", "severity", "cases"], description="Cases per customer and severity.", scope_field="customer"),
    _q("automation.split", "Automation outcome split by customer", "overview", r'''$soar_containers$
| rex max_match=0 field=_raw "(?<container_block>\{[^{}]*\"id\":\s?\d+.*?\})"
| mvexpand container_block
| rex field=container_block "\"id\":\s?(?<id>\d+)"
| rex field=container_block "\"label\":\s?\"(?<label>[^\"]+)\""
| rex field=container_block "\"status\":\s?\"(?<status>[^\"]+)\""
| spath input=container_block path=custom_fields.execution_mode output=execution_mode
| dedup id
| search label!="" NOT label IN (events,test_label) NOT status IN (new, "in progress", testing) AND label IN ($tenant_labels$)
| eval mode=case(execution_mode=="Automated","Automated", execution_mode=="Hybrid","Hybrid", execution_mode=="Manual","Manual", 1==1,"Not set")
| stats count by label mode
| rename label as customer
| table customer mode count''',
       ["customer", "mode", "count"],
       description="Cases created in the period and no longer open, per customer and SOAR execution_mode "
                   "(Automated, Hybrid, Manual, Not set) — the Overview automation outcome split.",
       scope_field="customer"),
    # ---- L1 ----
    _q("l1.by_analyst", "L1 performance by analyst", "l1", r'''$include:sla.head$
| eval MTTT_breach = if(MTTT_sec>600,1,0)
| stats count as cases avg(MTTA_sec) as MTTA avg(MTTT_sec) as MTTT perc50(MTTT_sec) as triage_p50 avg(MTTR_sec) as MTTR avg(MTTRs_sec) as MTTTres avg(MTTCR_sec) as MTTCR sum(MTTT_breach) as tbreach by sla_owner_name
| eval triage_sla=round(100-100*tbreach/cases,1)
| eval MTTA=round(MTTA),MTTT=round(MTTT),triage_p50=round(triage_p50),MTTR=round(MTTR),MTTTres=round(MTTTres),MTTCR=round(MTTCR)
| search NOT sla_owner_name IN (soc.analyst, soc.ir, soc.tde)
| sort - cases
| rename sla_owner_name as analyst
| table analyst cases triage_p50 MTTA MTTT MTTR MTTTres MTTCR triage_sla''',
       ["analyst", "cases", "triage_p50", "MTTA", "MTTT", "MTTR", "MTTTres", "MTTCR", "triage_sla"],
       description="Per-analyst cases owned, stage times (seconds), triage p50 and triage-SLA %, for the "
                   "selected tenant(s) only."),
    # ---- Agentic AI performance (initech_all_general/agentic_soc_summary) ----
    _q("agentic.incidents", "Incidents triaged", "agentic",
       _aisoc("triage_completed", "| stats dc(incident_id) as incidents"), ["incidents"], cache_seconds=120),
    _q("agentic.artifacts", "Artifacts analyzed", "agentic",
       _aisoc("triage_completed", "| stats count as events sum(artifact_count) as artifacts "
                                  "| eval artifacts=if(isnull(artifacts),0,artifacts) | fields artifacts"),
       ["artifacts"], cache_seconds=120),
    _q("agentic.actions", "Actions recommended", "agentic",
       _aisoc("remediation_completed", "| stats count as events sum(action_count) as actions "
                                       "| eval actions=if(isnull(actions),0,actions) | fields actions"),
       ["actions"], cache_seconds=120),
    _q("agentic.confidence", "Average triage confidence", "agentic",
       _aisoc("triage_completed", "| stats avg(confidence) as avg_confidence "
                                  "| eval avg_confidence=round(avg_confidence,2)"),
       ["avg_confidence"], cache_seconds=120),
    _q("agentic.cloud_pct", "Routed to cloud LLM", "agentic",
       _aisoc("anonymization_decision", '| stats dc(eval(if(status=="anonymized",incident_id,null()))) as cloud '
                                        'dc(incident_id) as total | eval pct=if(total>0,round(cloud*100/total,1),0) '
                                        '| fields pct'),
       ["pct"], description="Share of incidents anonymized and sent to the cloud LLM (%).", cache_seconds=120),
    _q("agentic.avg_triage", "Average triage time", "agentic",
       _aisoc("triage_completed", "| stats avg(duration) as secs " + _DUR), ["disp", "secs"], cache_seconds=120),
    _q("agentic.avg_remediation", "Average remediation time", "agentic",
       _aisoc("remediation_completed", "| stats avg(duration) as secs " + _DUR), ["disp", "secs"],
       cache_seconds=120),
    _q("agentic.time_saved", "Analyst time saved", "agentic",
       _aisoc("triage_completed", "| stats dc(incident_id) as incidents avg(duration) as avg_dur "
                                  "| eval secs=incidents*(600-avg_dur) | eval secs=if(secs<0,0,secs) " + _DUR),
       ["disp", "secs"], description="Incidents × (10 min manual baseline − AI triage time).", cache_seconds=120),
    _q("agentic.critical_high", "Critical and high incidents", "agentic",
       _aisoc("triage_completed", "| stats dc(incident_id) as incidents",
              " (severity_adjusted=critical OR severity_adjusted=high)"),
       ["incidents"], cache_seconds=120),
    _q("agentic.escalated", "Escalated by the matrix", "agentic",
       _aisoc("triage_completed", _RANK + " | eval esc=if(rank_in>=0 AND rank_out>=0 AND rank_out>rank_in,1,0) "
                                          "| stats sum(esc) as incidents"),
       ["incidents"], cache_seconds=120),
    _q("agentic.triage_latency", "Triage duration p50 / p95 (rolling 24h, seconds)", "agentic",
       _aisoc("triage_completed", "| timechart span=1h p50(duration) as p50 p95(duration) as p95 "
                                  "| streamstats window=24 avg(p50) as p50_24h avg(p95) as p95_24h "
                                  "| fields _time p50_24h p95_24h | eval p50_24h=round(p50_24h) "
                                  "| eval p95_24h=round(p95_24h)"),
       ["_time", "p50_24h", "p95_24h"], cache_seconds=120),
    _q("agentic.remediation_latency", "Remediation duration p50 / p95 (rolling 24h, minutes)", "agentic",
       _aisoc("remediation_completed", "| timechart span=1h p50(duration) as p50 p95(duration) as p95 "
                                       "| streamstats window=24 avg(p50) as p50_24h avg(p95) as p95_24h "
                                       "| fields _time p50_24h p95_24h | eval p50_24h=round(p50_24h/60,2) "
                                       "| eval p95_24h=round(p95_24h/60,2)"),
       ["_time", "p50_24h", "p95_24h"], cache_seconds=120),
    _q("agentic.hours_saved_daily", "Analyst hours saved per day", "agentic",
       _aisoc("triage_completed", '| timechart span=1d dc(incident_id) as incidents avg(duration) as avg_dur '
                                  '| eval hours_saved=round((incidents*(600-avg_dur))/3600,2) '
                                  '| eval hours_saved=if(hours_saved<0,0,hours_saved) | fields _time hours_saved '
                                  '| rename hours_saved as "Analyst hours saved"'),
       ["_time", "Analyst hours saved"], cache_seconds=120),
    _q("agentic.categories", "Top incident categories", "agentic",
       _aisoc("triage_completed", "| stats dc(incident_id) as incidents by category | sort - incidents | head 5"),
       ["category", "incidents"], cache_seconds=120),
    _q("agentic.severity_mix", "AI-adjusted severity mix", "agentic",
       _aisoc("triage_completed", "| stats dc(incident_id) as incidents by severity_adjusted | sort - incidents"),
       ["severity_adjusted", "incidents"], cache_seconds=120),
    _q("agentic.severity_matrix", "Severity matrix: SOAR severity in vs AI-adjusted out", "agentic",
       _aisoc("triage_completed", _RANK + ' | eval direction=case(rank_in<0 OR rank_out<0,"unknown",'
                                          'rank_out>rank_in,"escalated",rank_out<rank_in,"de-escalated",1==1,"unchanged") '
                                          '| stats count as incidents by sev_in sev_out direction | sort - incidents '
                                          '| rename sev_in as "SOAR severity" sev_out as "AI-adjusted" '
                                          'direction as "Direction" incidents as "Incidents"'),
       ["SOAR severity", "AI-adjusted", "Direction", "Incidents"],
       description="Every SOAR-severity → AI-adjusted-severity transition with its incident count (the full matrix).",
       cache_seconds=120),
]
SEED_BY_ID = {q["id"]: q for q in SEED}
_SYNCED = ("name", "description", "category", "spl", "columns", "scope_mode", "scope_field", "cache_seconds")


async def seed_data_queries() -> None:
    """Keep built-in entries in step with this file:
      * a missing built-in is inserted;
      * a built-in nobody has edited (still owned by "system") follows the shipped
        definition — a change here lands as a new version;
      * a built-in dropped from this file is removed if nobody edited it.
    Anything a person has edited, reset or rolled back is never touched."""
    async with SessionLocal() as db:
        rows = {q.id: q for q in (await db.execute(select(DataQuery))).scalars().all()}
        for q in SEED:
            cur = rows.get(q["id"])
            if cur is None:
                db.add(DataQuery(**q, builtin=True, version=1, updated_by="system"))
                db.add(DataQueryVersion(query_id=q["id"], version=1, spl=q["spl"], note="built-in", changed_by="system"))
            elif cur.builtin and cur.updated_by == "system" and any(getattr(cur, k) != q[k] for k in _SYNCED):
                for k in _SYNCED:
                    setattr(cur, k, q[k])
                cur.version += 1
                db.add(DataQueryVersion(query_id=cur.id, version=cur.version, spl=cur.spl,
                                        note="built-in updated", changed_by="system"))
        for qid, cur in rows.items():
            if cur.builtin and cur.updated_by == "system" and qid not in SEED_BY_ID:
                await db.delete(cur)
        await db.commit()
