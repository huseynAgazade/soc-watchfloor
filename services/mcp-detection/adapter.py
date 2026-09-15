"""Turn the pipeline's _all_rules_combined.json into the portal's detection dataset.

Coverage is counted at the TOP-LEVEL technique (T1078, not T1078.004) against
MITRE's per-tactic top-level totals, consistently. A technique mapped only by a
DISABLED rule is a phantom cell. Operational/health and TEST rules are separated
from real detections so they never inflate coverage.

A dataset can be built for a subset of tenants (a caller's scope): the rules, the
per-tenant breakdowns and the "all" roll-up are then computed over that subset
only, so a scoped caller never receives another customer's rule or figure.
"""
from __future__ import annotations

import json
import os
import re

_HERE = os.path.dirname(__file__)
_NAMES = json.load(open(os.path.join(_HERE, "pipeline", "mitre_technique_names.json")))

CANON = [
    ("reconnaissance", "Reconnaissance", "TA0043", 12), ("resource-development", "Resource Development", "TA0042", 9),
    ("initial-access", "Initial Access", "TA0001", 11), ("execution", "Execution", "TA0002", 20),
    ("persistence", "Persistence", "TA0003", 22), ("privilege-escalation", "Privilege Escalation", "TA0004", 13),
    ("stealth", "Defense Evasion", "TA0005", 30), ("credential-access", "Credential Access", "TA0006", 17),
    ("discovery", "Discovery", "TA0007", 34), ("lateral-movement", "Lateral Movement", "TA0008", 9),
    ("collection", "Collection", "TA0009", 17), ("command-and-control", "Command and Control", "TA0011", 18),
    ("exfiltration", "Exfiltration", "TA0010", 9), ("impact", "Impact", "TA0040", 15),
]
BYCODE = {c: (s, n, tot) for s, n, c, tot in CANON}
CUST = {"initech": "initech", "globex": "umbrella_co", "hooli": "hooli_media"}
TENANTS = ["umbrella_co", "initech", "hooli_media", "acme_corp", "globex_co"]
TOP_TOTAL = 211
OPS_KW = re.compile(r"log ingestion|license|heartbeat|sensor status|customer_response|baseline|"
                    r"not sending heartbeat|interval scheduled|tracker", re.I)


def _enabled(r):
    if "disabled" in r:
        return not r.get("disabled")
    if "status" in r:
        return str(r.get("status")).lower() == "active"
    return True


def _is_test(r):
    n = r.get("name") or ""
    return n.startswith("TEST-") or n.startswith("TEST ") or bool(re.search(r"\bTest\b.*Rule|for testing", n))


def _entries(r):
    e = r.get("mitre_attack") or []
    if e:
        return e
    if r.get("tactic") and r.get("technique"):
        return [f'{r["tactic"]}:{r["technique"]}']
    return []


def _flatten(combined):
    rules = []
    for cust, srcs in combined.items():
        for src, rl in srcs.items():
            for r in rl:
                en = _entries(r)
                mapped = bool([x for x in en if ":" in x])
                name = r.get("name") or r.get("id") or "Unnamed"
                test = _is_test(r)
                ops = (not mapped) and bool(OPS_KW.search(name))
                kind = "test" if test else ("operational" if ops else ("detection" if mapped else "unmapped"))
                rules.append({"tenant": CUST.get(cust, cust), "src": src, "name": name,
                              "enabled": _enabled(r), "sev": r.get("severity", r.get("alert_severity")),
                              "entries": en, "mapped": mapped, "kind": kind,
                              "sched": r.get("cron_schedule") or r.get("schedule_definition"),
                              "updated": r.get("updated")})
    return rules


def load(combined_path: str) -> list[dict]:
    with open(combined_path) as f:
        return _flatten(json.load(f))


def dataset(rules: list[dict], scope: list[str] | set[str] | None = None) -> dict:
    """scope None → every tenant; otherwise only the given tenant ids."""
    tenants = sorted(set(TENANTS) | {r["tenant"] for r in rules})
    if scope is not None:
        allowed = set(scope)
        rules = [r for r in rules if r["tenant"] in allowed]
        tenants = [t for t in tenants if t in allowed]

    def summarize(t):
        subset = [r for r in rules if t == "all" or r["tenant"] == t]
        det = [r for r in subset if r["kind"] == "detection"]
        covered, phantom, rulecnt = ({s: set() for s, _, _, _ in CANON} for _ in range(3))
        for r in det:
            for e in r["entries"]:
                if ":" not in e:
                    continue
                code, tech = e.split(":", 1)
                top = tech.split(".")[0].strip()
                if code not in BYCODE:
                    continue
                slug = BYCODE[code][0]
                rulecnt[slug].add(r["name"])
                (covered if r["enabled"] else phantom)[slug].add(top)
        tot_cov, tot_ph = set(), set()
        tactics = []
        for slug, name, code, tot in CANON:
            c = covered[slug]
            ph = phantom[slug] - c
            tactics.append({"slug": slug, "name": name, "code": code, "cov": len(c), "tot": tot,
                            "pct": round(len(c) / tot * 100) if tot else 0, "phantom": len(ph),
                            "rules": len(rulecnt[slug])})
            tot_cov |= {slug + ":" + x for x in c}
            tot_ph |= {slug + ":" + x for x in ph}
        return {"tactics": tactics, "topCovered": len(tot_cov), "topTotal": TOP_TOTAL, "phantom": len(tot_ph),
                "rules_total": len(subset), "rules_detection": len(det),
                "rules_enabled": len([r for r in det if r["enabled"]]),
                "rules_disabled": len([r for r in det if not r["enabled"]]),
                "rules_unmapped": len([r for r in subset if r["kind"] == "unmapped"]),
                "rules_ops": len([r for r in subset if r["kind"] == "operational"]),
                "rules_test": len([r for r in subset if r["kind"] == "test"])}

    def tech_detail(t):
        subset = [r for r in rules if (t == "all" or r["tenant"] == t) and r["kind"] == "detection"]
        byt = {s: {} for s, _, _, _ in CANON}
        for r in subset:
            for e in r["entries"]:
                if ":" not in e:
                    continue
                code, tech = e.split(":", 1)
                top = tech.split(".")[0].strip()
                if code not in BYCODE:
                    continue
                d = byt[BYCODE[code][0]].setdefault(top, {"rules": set(), "on": 0, "off": 0})
                d["rules"].add(r["name"])
                d["on" if r["enabled"] else "off"] += 1
        out = {}
        for slug, name, code, tot in CANON:
            techs = [{"id": top, "n": _NAMES.get(top, top), "c": len(d["rules"]),
                      "ph": 1 if (d["on"] == 0 and d["off"] > 0) else 0} for top, d in byt[slug].items()]
            techs.sort(key=lambda x: (-x["c"], x["n"]))
            out[slug] = techs
        return out

    rules_out = [{"tenant": r["tenant"], "src": r["src"], "n": r["name"], "on": r["enabled"], "sev": r["sev"],
                  "tech": ([e for e in r["entries"] if ":" in e][0].split(":", 1)[1] if r["mapped"] else None),
                  "kind": r["kind"], "sched": r["sched"]} for r in rules]

    data = {"summary": {}, "tactics": {}, "tech": {}, "rules": rules_out,
            "onboarded": sorted({r["tenant"] for r in rules})}
    for t in ["all"] + tenants:
        s = summarize(t)
        data["summary"][t] = {k: v for k, v in s.items() if k != "tactics"}
        data["tactics"][t] = s["tactics"]
        data["tech"][t] = tech_detail(t)
    return data


def build(combined_path: str, scope: list[str] | set[str] | None = None) -> dict:
    return dataset(load(combined_path), scope)


if __name__ == "__main__":
    import sys
    d = build(sys.argv[1] if len(sys.argv) > 1 else os.path.join(_HERE, "pipeline", "rules", "_all_rules_combined.json"))
    s = d["summary"]["all"]
    print(f"ALL: {s['topCovered']}/{s['topTotal']} top-level covered, {s['phantom']} phantom, "
          f"{s['rules_total']} rules ({s['rules_detection']} detection: {s['rules_enabled']} on/{s['rules_disabled']} off, "
          f"{s['rules_unmapped']} unmapped, {s['rules_ops']} ops, {s['rules_test']} test)")
    for t in ["umbrella_co", "initech", "hooli_media"]:
        st = d["summary"][t]
        print(f"  {t}: {st['topCovered']}/{st['topTotal']} covered, {st['rules_detection']} detections")
