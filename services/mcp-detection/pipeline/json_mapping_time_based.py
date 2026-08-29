#!/usr/bin/env python3
"""
time_based_rules_filter.py

Filters the per-rule JSON files produced by splunk_export_rules.py down to
the ones whose "updated" timestamp falls within a date range you enter
interactively (format DD.MM.YYYY, e.g. 01.01.26).

Usage:
    python3 time_based_rules_filter.py --rules-dir rules/splunk/customer1 \
                                        --output    rules/splunk/customer1/_rules_updated_in_range.json

The script will then prompt:
    Start date (DD.MM.YYYY): 01.01.26
    End date   (DD.MM.YYYY): 31.05.26
"""

import argparse
import datetime
import json
import os


def load_rules(rules_dir):
    rules = []
    for fname in os.listdir(rules_dir):
        if not fname.endswith(".json"):
            continue
        if fname == "_index.json" or fname.startswith("_mitre_map") or fname.startswith("_rules_updated"):
            continue
        fpath = os.path.join(rules_dir, fname)
        with open(fpath, "r") as f:
            try:
                rules.append(json.load(f))
            except json.JSONDecodeError:
                print(f"WARNING: skipping unparsable file {fpath}")
    return rules


def prompt_date(label):
    while True:
        raw = input(f"{label} (DD.MM.YYYY): ").strip()
        try:
            return datetime.datetime.strptime(raw, "%d.%m.%Y").date()
        except ValueError:
            print(f"  '{raw}' isn't a valid DD.MM.YYYY date, try again.")


def parse_updated(value):
    # e.g. "2026-05-26T10:36:46+04:00"
    return datetime.datetime.fromisoformat(value).date()


def filter_rules(rules, start_date, end_date):
    matched = []
    for rule in rules:
        updated_raw = rule.get("updated")
        if not updated_raw:
            print(f"WARNING: rule {rule.get('name', 'UNKNOWN')!r} has no 'updated' field, skipping")
            continue
        try:
            updated_date = parse_updated(updated_raw)
        except ValueError:
            print(f"WARNING: rule {rule.get('name', 'UNKNOWN')!r} has unparsable 'updated' value {updated_raw!r}, skipping")
            continue

        if start_date <= updated_date <= end_date:
            matched.append(rule)
    return matched


def main():
    parser = argparse.ArgumentParser(description="Filter exported Splunk rules by their 'updated' date range.")
    parser.add_argument("--rules-dir", required=True, help="Folder containing the exported rule JSON files")
    parser.add_argument("--output", required=True, help="Path to write the matching rules JSON")
    args = parser.parse_args()

    start_date = prompt_date("Start date")
    end_date = prompt_date("End date")
    if start_date > end_date:
        print("Start date is after end date -- swapping them.")
        start_date, end_date = end_date, start_date

    rules = load_rules(args.rules_dir)
    matched = filter_rules(rules, start_date, end_date)

    with open(args.output, "w") as f:
        json.dump(matched, f, indent=2, sort_keys=True)

    print(f"matched {len(matched)} of {len(rules)} rule(s) updated between {start_date} and {end_date}")
    print(f"written to {args.output}")


if __name__ == "__main__":
    main()