#!/usr/bin/env python3
"""
generate_coverage_html.py

Reads the combined rules JSON produced by json_automatic_mapper.py
(shape: {customer: {source: [rule, ...]}}), maps every rule's
"mitre_attack" entries ("TA00XX:T1XXX" strings) onto the 14 canonical
MITRE ATT&CK Enterprise tactics, and produces a single self-contained
HTML report (based on the provided index.html template) with the data
embedded directly -- so it opens correctly with a plain double-click,
no local web server required.

Rule names are tagged with their customer/source, e.g.
"Threat - Rule Name [customer1/splunk]", so coverage stays
differentiated across customers/sources in one combined view.

Usage:
    python3 generate_coverage_html.py \
        --input  rules/_all_rules_combined.json \
        --template index.html \
        --output  rules/coverage_report.html

Expects mitre_technique_names.json (technique ID -> friendly name,
bundled alongside this script) to be present in the same directory.
"""

import argparse
import datetime
import json
import os

# Canonical MITRE ATT&CK Enterprise tactics, in kill-chain order.
# Slug ids and the "stealth" id for Defense Evasion match the reference
# template's CANON_TACTICS exactly -- don't rename these, the template's
# CSS/JS scroll targets (#tac-<id>) depend on them.
CANON_TACTICS = [
    ("reconnaissance", "Reconnaissance", "TA0043"),
    ("resource-development", "Resource Development", "TA0042"),
    ("initial-access", "Initial Access", "TA0001"),
    ("execution", "Execution", "TA0002"),
    ("persistence", "Persistence", "TA0003"),
    ("privilege-escalation", "Privilege Escalation", "TA0004"),
    ("stealth", "Defense Evasion", "TA0005"),
    ("credential-access", "Credential Access", "TA0006"),
    ("discovery", "Discovery", "TA0007"),
    ("lateral-movement", "Lateral Movement", "TA0008"),
    ("collection", "Collection", "TA0009"),
    ("command-and-control", "Command And Control", "TA0011"),
    ("exfiltration", "Exfiltration", "TA0010"),
    ("impact", "Impact", "TA0040"),
]

GRADIENT = {"colors": ["#dceefb", "#7ab8e8", "#2e75b6", "#0d2f5e"], "minValue": 1, "maxValue": 3}

# Total *top-level* (non-sub-technique) active techniques per tactic, from the
# official MITRE ATT&CK Enterprise STIX bundle (github.com/mitre/cti), pulled
# 2026-07-22 (content last modified 2026-05-12). Revoked/deprecated techniques
# are excluded. Used to compute "N of TOTAL techniques covered" per tactic.
#
# NOTE: MITRE has renamed TA0005 from "Defense Evasion" to "Stealth" and split
# out a new tactic, "Defense Impairment" (TA0112, 18 top-level techniques),
# which isn't in CANON_TACTICS below. This script keeps the existing
# "stealth" slug / "Defense Evasion" label and its TA0005 total (30) so
# existing rule mappings and this report stay consistent; add TA0112 here (and
# to the template's CANON_TACTICS) later if you want to track it separately.
#
# These totals will drift as MITRE updates the matrix -- regenerate them from
# a fresh enterprise-attack.json if the counts start looking stale.
TACTIC_TECHNIQUE_TOTALS = {
    "reconnaissance": 12,
    "resource-development": 9,
    "initial-access": 11,
    "execution": 20,
    "persistence": 22,
    "privilege-escalation": 13,
    "stealth": 30,
    "credential-access": 17,
    "discovery": 34,
    "lateral-movement": 9,
    "collection": 17,
    "command-and-control": 18,
    "exfiltration": 9,
    "impact": 15,
}


def score_color(count):
    if count <= 0:
        return None
    if count <= 2:
        return GRADIENT["colors"][0]
    if count <= 5:
        return GRADIENT["colors"][1]
    if count <= 8:
        return GRADIENT["colors"][2]
    return GRADIENT["colors"][3]


def load_technique_names(script_dir):
    path = os.path.join(script_dir, "mitre_technique_names.json")
    if not os.path.isfile(path):
        print(f"WARNING: {path} not found -- technique names will fall back to bare IDs")
        return {}
    with open(path, "r") as f:
        return json.load(f)


def flatten_rules(combined):
    """
    Yields (display_name, customer, source, rule) for every rule across
    every customer/source in the combined JSON. `rule` is the raw rule
    dict as found in the input JSON -- callers pull whatever fields
    they need out of it (mitre_attack, search/search_filter, severity,
    schedule, etc.) rather than this function pre-selecting fields.
    """
    for customer, sources in combined.items():
        for source, rules in sources.items():
            for rule in rules:
                name = rule.get("name") or rule.get("id") or "Unnamed rule"
                display_name = f"{name} [{customer}/{source}]"
                yield display_name, customer, source, rule


def _rule_detail(display_name, customer, source, rule):
    """
    Builds the enriched rule record embedded in the report: the full
    original rule object (so the UI can render every field it finds --
    search/search_filter as a code block, schedule, severity, owner,
    actions, etc.) plus a few underscore-prefixed bookkeeping fields
    the UI relies on for de-duplication, sorting, and the
    customer/source pill. Underscore prefixes avoid colliding with any
    real field name from Splunk, Falcon, or future sources.
    """
    detail = dict(rule)
    detail["_displayName"] = display_name
    detail["_customer"] = customer
    detail["_source"] = source
    return detail


def _resolve_mitre_entries(rule):
    """
    Returns the list of "TA00XX:T1XXX" entries to map this rule with.
    Normally that's just rule["mitre_attack"]. Some sources (seen in
    Falcon-style rules) instead populate top-level singular `tactic`/
    `technique` fields and leave `mitre_attack` empty -- if so, fall
    back to reconstructing a single "tactic:technique" entry from
    those so the rule isn't dropped as unmapped just because the info
    lives in a different field.
    """
    entries = rule.get("mitre_attack") or []
    if entries:
        return entries
    tactic = rule.get("tactic")
    technique = rule.get("technique")
    if tactic and technique:
        return [f"{tactic}:{technique}"]
    return []


def build_tactics_data(combined, technique_names):
    tactic_by_code = {code: (slug, name) for slug, name, code in CANON_TACTICS}
    # slug -> techniqueId -> {display_name: rule_detail}
    buckets = {slug: {} for slug, _, _ in CANON_TACTICS}

    unmapped_rules = []
    unknown_tactic_codes = set()

    for display_name, customer, source, rule in flatten_rules(combined):
        mitre_entries = _resolve_mitre_entries(rule)
        detail = _rule_detail(display_name, customer, source, rule)
        if not mitre_entries:
            unmapped_rules.append(detail)
            continue
        mapped_any = False
        for entry in mitre_entries:
            if ":" not in entry:
                continue
            tactic_code, technique_id = entry.split(":", 1)
            if tactic_code not in tactic_by_code:
                unknown_tactic_codes.add(tactic_code)
                continue
            slug, _ = tactic_by_code[tactic_code]
            buckets[slug].setdefault(technique_id, {})[display_name] = detail
            mapped_any = True
        if not mapped_any:
            unmapped_rules.append(detail)

    tactics = []
    for slug, name, code in CANON_TACTICS:
        techniques = []
        for technique_id, rule_map in buckets[slug].items():
            rules = sorted(rule_map.values(), key=lambda r: r["_displayName"])
            techniques.append(
                {
                    "techniqueId": technique_id,
                    "name": technique_names.get(technique_id, technique_id),
                    "score": len(rules),
                    "color": score_color(len(rules)) or GRADIENT["colors"][0],
                    "rules": rules,
                }
            )
        techniques.sort(key=lambda t: (-len(t["rules"]), t["name"]))

        all_rules_in_tactic = set()
        for t in techniques:
            all_rules_in_tactic.update(r["_displayName"] for r in t["rules"])

        tactics.append(
            {
                "id": slug,
                "name": name,
                "tacticId": code,
                "techniques": techniques,
                "ruleCount": len(all_rules_in_tactic),
                "techniqueCount": len(techniques),
                "techniquesTotal": TACTIC_TECHNIQUE_TOTALS.get(slug),
            }
        )

    return tactics, unmapped_rules, unknown_tactic_codes


def build_dataset(combined, technique_names, source_name):
    tactics, unmapped_rules, unknown_tactic_codes = build_tactics_data(combined, technique_names)

    all_rule_names = set()
    all_technique_ids = set()
    for tac in tactics:
        for t in tac["techniques"]:
            all_technique_ids.add(t["techniqueId"])
            all_rule_names.update(r["_displayName"] for r in t["rules"])

    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    tactics_covered = sum(1 for t in tactics if t["techniqueCount"] > 0)
    unmapped_sorted = sorted(unmapped_rules, key=lambda r: r["_displayName"])

    dataset = {
        "generatedAt": f"Generated {generated_at} | {len(all_rule_names)} rules | {len(all_technique_ids)} techniques",
        "sourceName": source_name,
        "tactics": tactics,
        "unmappedRules": unmapped_sorted,
        "stats": {
            "uniqueTechniques": len(all_technique_ids),
            "uniqueRules": len(all_rule_names),
            "tacticsCovered": tactics_covered,
            "tacticsTotal": len(tactics),
            "unmappedCount": len(unmapped_sorted),
        },
        "gradient": GRADIENT,
    }
    return dataset, unmapped_rules, unknown_tactic_codes


def inject_into_template(template_text, dataset):
    """
    Replaces the single-line `const EMBEDDED_DATA = {...};` assignment in
    the template with the generated dataset, so the report is a fully
    self-contained HTML file (works via plain double-click / file://,
    no local web server required to fetch a separate data.json).
    """
    lines = template_text.splitlines()
    marker = "const EMBEDDED_DATA = "
    for i, line in enumerate(lines):
        if line.strip().startswith(marker):
            lines[i] = marker + json.dumps(dataset) + ";"
            return "\n".join(lines)
    raise RuntimeError("Could not find 'const EMBEDDED_DATA = ' line in template -- template format may have changed")


def main():
    parser = argparse.ArgumentParser(description="Generate a self-contained MITRE ATT&CK coverage HTML report.")
    parser.add_argument("--input", required=True, help="Path to the combined rules JSON")
    parser.add_argument("--template", required=True, help="Path to the index.html template")
    parser.add_argument("--output", required=True, help="Path to write the generated HTML report")
    parser.add_argument(
        "--source-name",
        default="Combined Detection Rules Coverage (Splunk + Falcon EDR)",
        help="Label shown under the report title",
    )
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    technique_names = load_technique_names(script_dir)

    with open(args.input, "r") as f:
        combined = json.load(f)

    with open(args.template, "r") as f:
        template_text = f.read()

    dataset, unmapped_rules, unknown_tactic_codes = build_dataset(combined, technique_names, args.source_name)

    output_html = inject_into_template(template_text, dataset)
    with open(args.output, "w") as f:
        f.write(output_html)

    # Also write the plain data.json alongside it, matching what the
    # page's own "Export data.json" button would produce.
    data_json_path = os.path.join(os.path.dirname(args.output), "data.json")
    with open(data_json_path, "w") as f:
        json.dump(dataset, f, indent=2)

    print(dataset["generatedAt"])
    print(f"written report -> {args.output}")
    print(f"written data   -> {data_json_path}")

    if unmapped_rules:
        names = sorted(r["_displayName"] for r in unmapped_rules)
        unmapped_path = os.path.join(os.path.dirname(args.output), "unmapped_rules.txt")
        with open(unmapped_path, "w") as f:
            f.write("\n".join(names))
        print(f"NOTE: {len(unmapped_rules)} rule(s) had no usable mitre_attack mapping")
        print(f"      they're shown in the report's 'Unmapped Rules' section; full list also written -> {unmapped_path}")
        for name in names[:5]:
            print(f"    {name}")
    if unknown_tactic_codes:
        print(f"NOTE: unrecognized tactic code(s) seen and skipped: {sorted(unknown_tactic_codes)}")


if __name__ == "__main__":
    main()