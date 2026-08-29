#!/usr/bin/env python3
"""
json_mapping_all.py

Reads customers.yaml, discovers every customer configured under
"customers" (Splunk) and/or "ngsiem_customers" (Falcon EDR), loads all
previously-exported rule JSON files from each customer's own output_dir,
and writes one combined JSON file grouping everything by customer and
source. Nothing about which customers exist is hardcoded here -- add a
new customer block to customers.yaml and it's picked up automatically.

Usage:
    python3 json_mapping_all.py --config customers.yaml \
        --output rules/_all_rules_combined.json
"""

import argparse
import json
import os

import yaml

# Generated/meta files that live alongside rule files but aren't rules
# themselves -- skip these when reading a customer's output_dir.
SKIP_PREFIXES = ("_index", "_mitre_map", "_rules_updated", "_all_rules_combined")


def load_rules_from_dir(directory):
    rules = []
    if not os.path.isdir(directory):
        print(f"WARNING: directory not found, skipping: {directory}")
        return rules

    for fname in os.listdir(directory):
        if not fname.endswith(".json"):
            continue
        if any(fname.startswith(p) for p in SKIP_PREFIXES):
            continue
        fpath = os.path.join(directory, fname)
        with open(fpath, "r") as f:
            try:
                rules.append(json.load(f))
            except json.JSONDecodeError:
                print(f"WARNING: skipping unparsable file {fpath}")
    return rules


def build_combined(config):
    splunk_customers = config.get("customers", {}) or {}
    ngsiem_customers = config.get("ngsiem_customers", {}) or {}

    all_customer_names = sorted(set(splunk_customers) | set(ngsiem_customers))

    combined = {}
    for name in all_customer_names:
        combined[name] = {}

        splunk_cfg = splunk_customers.get(name)
        if splunk_cfg:
            combined[name]["splunk"] = load_rules_from_dir(splunk_cfg["output_dir"])

        falcon_cfg = ngsiem_customers.get(name)
        if falcon_cfg:
            combined[name]["falcon_edr"] = load_rules_from_dir(falcon_cfg["output_dir"])

    return combined


def main():
    parser = argparse.ArgumentParser(
        description="Combine all exported rule JSON files, grouped by customer and source."
    )
    parser.add_argument("--config", default="customers.yaml", help="Path to customers.yaml")
    parser.add_argument("--output", required=True, help="Path to write the combined JSON")
    args = parser.parse_args()

    with open(args.config, "r") as f:
        config = yaml.safe_load(f)

    combined = build_combined(config)

    with open(args.output, "w") as f:
        json.dump(combined, f, indent=2, sort_keys=True)

    print(f"combined rules for {len(combined)} customer(s):")
    for name, sources in combined.items():
        parts = ", ".join(f"{src}={len(rules)}" for src, rules in sources.items())
        print(f"  {name}: {parts if parts else 'no sources configured'}")
    print(f"written to {args.output}")


if __name__ == "__main__":
    main()