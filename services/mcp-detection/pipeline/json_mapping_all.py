#!/usr/bin/env python3
"""
map_mitre_rules.py

Reads the per-rule JSON files produced by splunk_export_rules.py, pulls
the "mitre_attack" field (entries like "TA0009:T1560"), and builds a
Tactic -> Technique -> [rule names] mapping.

Usage:
    python3 map_mitre_rules.py --rules-dir rules/splunk/customer1 \
                                --output   rules/splunk/customer1/_mitre_map.json
"""

import argparse
import json
import os

# Enterprise ATT&CK tactic IDs -> names. Static list, doesn't change often;
# update here if MITRE adds/renames a tactic.
TACTIC_ID_TO_NAME = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}


def load_rules(rules_dir):
    rules = []
    for fname in os.listdir(rules_dir):
        if not fname.endswith(".json") or fname == "_index.json" or fname.startswith("_mitre_map"):
            continue
        fpath = os.path.join(rules_dir, fname)
        with open(fpath, "r") as f:
            try:
                rules.append(json.load(f))
            except json.JSONDecodeError:
                print(f"WARNING: skipping unparsable file {fpath}")
    return rules


def build_mapping(rules):
    mapping = {}
    for rule in rules:
        rule_name = rule.get("name", "UNKNOWN")
        for entry in rule.get("mitre_attack", []):
            if ":" not in entry:
                print(f"WARNING: unexpected mitre_attack entry {entry!r} on rule {rule_name!r}")
                continue
            tactic_id, technique_id = entry.split(":", 1)
            tactic_name = TACTIC_ID_TO_NAME.get(tactic_id, tactic_id)

            tactic_bucket = mapping.setdefault(tactic_name, {})
            technique_bucket = tactic_bucket.setdefault(technique_id, [])
            if rule_name not in technique_bucket:
                technique_bucket.append(rule_name)

    return mapping

def build_mapping(rules):
    mapping = {}
    for rule in rules:
        rule_name = rule.get("name", "UNKNOWN")
        for entry in rule.get("mitre_attack", []):
            if ":" in entry:
                tactic_id, technique_id = entry.split(":", 1)
            else:
                tactic_id, technique_id = entry, "UNSPECIFIED"

            tactic_name = TACTIC_ID_TO_NAME.get(tactic_id, tactic_id)

            tactic_bucket = mapping.setdefault(tactic_name, {})
            technique_bucket = tactic_bucket.setdefault(technique_id, [])
            if rule_name not in technique_bucket:
                technique_bucket.append(rule_name)

    return mapping


def main():
    parser = argparse.ArgumentParser(description="Map exported Splunk rules by MITRE Tactic/Technique.")
    parser.add_argument("--rules-dir", required=True, help="Folder containing the exported rule JSON files")
    parser.add_argument("--output", required=True, help="Path to write the resulting mapping JSON")
    args = parser.parse_args()

    rules = load_rules(args.rules_dir)
    mapping = build_mapping(rules)

    with open(args.output, "w") as f:
        json.dump(mapping, f, indent=2, sort_keys=True)

    tactic_count = len(mapping)
    technique_count = sum(len(techniques) for techniques in mapping.values())
    print(f"mapped {len(rules)} rule file(s) -> {tactic_count} tactic(s), {technique_count} technique(s)")
    print(f"written to {args.output}")


if __name__ == "__main__":
    main()