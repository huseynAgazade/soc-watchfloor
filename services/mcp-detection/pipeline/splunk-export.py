#!/usr/bin/env python3
"""
splunk-export.py

Pulls "detection rules" (saved searches / ES correlation searches) from one
or more Splunk instances via the REST API, keeps only the active (enabled)
ones, optionally scopes/filters them by app, and writes one JSON file per
rule plus an index file to disk.

Multi-customer support:
    Each Splunk instance (customer) gets its own block in customers.yaml
    (base_url, credentials, app, output_dir). Nothing about the customers
    is hardcoded in the script itself -- you just add / edit YAML entries.
    See customers.example.yaml for the format.

Usage:
    python3 splunk-export.py --config customers.yaml --customer customer1
    python3 splunk-export.py --config customers.yaml --customer all
    python3 splunk-export.py --config customers.yaml --customer customer1 --correlation-only

Dependencies:
    pip install requests pyyaml
"""

import argparse
import datetime
import getpass
import json
import os
import re
import stat
import sys

import requests
import yaml

# Splunk instances are often self-signed internally; if you hit SSL errors
# and have set verify_ssl: false in the config, this keeps urllib3 quiet.
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def load_config(path):
    with open(path, "r") as f:
        cfg = yaml.safe_load(f)
    if not cfg or "customers" not in cfg:
        raise ValueError(f"'{path}' has no top-level 'customers' key")
    return cfg["customers"]


def _read_secret_file(path):
    """
    Reads a single secret from a file and refuses to use it if the file's
    permissions allow anyone other than the owner to read it. Keeps this
    file OUTSIDE any shared/synced folder (like /mnt/hgfs/...) -- a shared
    VM folder is visible to the host OS and defeats the point of this check.
    """
    if not os.path.isfile(path):
        raise RuntimeError(f"secrets file not found: {path}")

    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise RuntimeError(
            f"refusing to read '{path}': permissions {oct(mode)} allow "
            f"group/other access. Fix with: chmod 600 {path}"
        )

    with open(path, "r") as f:
        return f.read().strip()


def _resolve_secret(customer_name, label, cfg, env_key, file_key, prompt):
    """
    Resolution order for a single secret (token, username, or password):
      1. <file_key> in config  -> read from a 600-permission file
      2. <env_key> in config   -> read from that env var (fallback, for
                                   automation/CI where a file isn't practical)
      3. neither configured    -> prompt interactively, input hidden,
                                   nothing written to disk or history
    """
    file_path = cfg.get(file_key)
    if file_path:
        return _read_secret_file(file_path)

    env_name = cfg.get(env_key)
    if env_name:
        value = os.environ.get(env_name)
        if value:
            return value
        raise RuntimeError(
            f"[{customer_name}] {env_key} is set to '{env_name}' but that "
            f"env var is empty/unset"
        )

    return getpass.getpass(f"[{customer_name}] {prompt}: ")


def get_auth(customer_name, cfg):
    """
    Returns (headers, requests_auth_tuple). Only one of the two will be
    populated depending on auth type. No secret value is ever read from
    the YAML config itself -- only pointers to where the secret lives
    (a restricted file, an env var name) or, absent both, an interactive
    hidden prompt.
    """
    auth_cfg = cfg.get("auth", {})
    auth_type = auth_cfg.get("type")

    if auth_type == "token":
        token = _resolve_secret(
            customer_name, "token", auth_cfg, "token_env", "token_file", "Splunk token"
        )
        return {"Authorization": f"Bearer {token}"}, None

    if auth_type == "basic":
        user = _resolve_secret(
            customer_name, "username", auth_cfg, "username_env", "username_file", "Splunk username"
        )
        pw = _resolve_secret(
            customer_name, "password", auth_cfg, "password_env", "password_file", "Splunk password"
        )
        return {}, (user, pw)

    raise RuntimeError(f"[{customer_name}] unsupported auth.type: {auth_type!r}")


def fetch_saved_searches(base_url, app, headers, auth, verify_ssl):
    """
    Hits /servicesNS/-/<app>/saved/searches, which scopes results to the
    given app namespace -- this is the "filter by app itself" the REST API
    offers, equivalent to what Content Management shows when you filter by
    app in the UI. count=0 means "return everything, no pagination cap".
    """
    url = f"{base_url.rstrip('/')}/servicesNS/-/{app}/saved/searches"
    params = {"output_mode": "json", "count": 0}
    resp = requests.get(
        url, headers=headers, auth=auth, params=params, verify=verify_ssl, timeout=30
    )
    resp.raise_for_status()
    return resp.json().get("entry", [])


def is_active(entry):
    disabled = entry.get("content", {}).get("disabled")
    return disabled in (False, "0", 0)


def is_correlation_search(entry):
    # ES-specific flag; only present when the saved search is wired up
    # as a correlation search (i.e. an actual "detection rule" in ES
    # terms, vs. an arbitrary scheduled report/alert).
    return str(entry.get("content", {}).get("action.correlationsearch.enabled")) == "1"


def extract_rule_data(entry):
    content = entry.get("content", {})
    acl = entry.get("acl", {})
    return {
        "name": entry.get("name"),
        "app": acl.get("app"),
        "owner": acl.get("owner"),
        "sharing": acl.get("sharing"),
        "search": content.get("search"),
        "description": content.get("description"),
        "disabled": content.get("disabled"),
        "cron_schedule": content.get("cron_schedule"),
        "alert_type": content.get("alert_type"),
        "alert_comparator": content.get("alert_comparator"),
        "alert_threshold": content.get("alert_threshold"),
        "alert_severity": content.get("alert.severity"),
        "is_correlation_search": content.get("action.correlationsearch.enabled"),
        "correlation_search_label": content.get("action.correlationsearch.label"),
        "actions": content.get("actions"),
        "updated": entry.get("updated"),
    }


def sanitize_filename(name):
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
    return cleaned or "unnamed_rule"


def save_rules(rules, output_dir, customer_name):
    os.makedirs(output_dir, exist_ok=True)
    index = []
    for rule in rules:
        fname = sanitize_filename(rule["name"]) + ".json"
        fpath = os.path.join(output_dir, fname)
        with open(fpath, "w") as f:
            json.dump(rule, f, indent=2)
        index.append({"name": rule["name"], "file": fname})

    index_path = os.path.join(output_dir, "_index.json")
    with open(index_path, "w") as f:
        json.dump(
            {
                "customer": customer_name,
                "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "rule_count": len(rules),
                "rules": index,
            },
            f,
            indent=2,
        )


def process_customer(name, cfg, correlation_only_override=None):
    headers, auth = get_auth(name, cfg)
    verify_ssl = cfg.get("verify_ssl", True)

    entries = fetch_saved_searches(cfg["base_url"], cfg["app"], headers, auth, verify_ssl)
    entries = [e for e in entries if e.get("acl", {}).get("app") == cfg["app"]]
    print(f"[{name}] DEBUG configured app = {cfg['app']!r}, owned count = {len(entries)}")
    active_entries = [e for e in entries if is_active(e)]

    correlation_only = (
        cfg.get("correlation_only", False)
        if correlation_only_override is None
        else correlation_only_override
    )
    if correlation_only:
        active_entries = [e for e in active_entries if is_correlation_search(e)]

    rules = [extract_rule_data(e) for e in active_entries]
    save_rules(rules, cfg["output_dir"], name)
    print(f"[{name}] exported {len(rules)} active rule(s) -> {cfg['output_dir']}")

def extract_rule_data(entry):
    content = entry.get("content", {})
    acl = entry.get("acl", {})

    annotations_raw = content.get("action.correlationsearch.annotations")
    try:
        annotations = json.loads(annotations_raw) if annotations_raw else {}
    except (TypeError, ValueError):
        annotations = {"raw": annotations_raw}

    return {
        "name": entry.get("name"),
        "app": acl.get("app"),
        "owner": acl.get("owner"),
        "sharing": acl.get("sharing"),
        "search": content.get("search"),
        "description": content.get("description"),
        "disabled": content.get("disabled"),
        "cron_schedule": content.get("cron_schedule"),
        "alert_type": content.get("alert_type"),
        "alert_comparator": content.get("alert_comparator"),
        "alert_threshold": content.get("alert_threshold"),
        "alert_severity": content.get("alert.severity"),
        "is_correlation_search": content.get("action.correlationsearch.enabled"),
        "correlation_search_label": content.get("action.correlationsearch.label"),
        "mitre_attack": annotations.get("mitre_attack", []),
        "kill_chain_phases": annotations.get("kill_chain_phases", []),
        "cis": annotations.get("cis", []),
        "nist": annotations.get("nist", []),
        "confidence": annotations.get("confidence"),
        "actions": content.get("actions"),
        "updated": entry.get("updated"),
    }

def main():
    parser = argparse.ArgumentParser(description="Export active Splunk detection rules per customer.")
    parser.add_argument("--config", default="customers.yaml", help="Path to customers.yaml")
    parser.add_argument("--customer", default="all", help="Customer key from config, or 'all'")
    parser.add_argument(
        "--correlation-only",
        dest="correlation_only",
        action="store_true",
        default=None,
        help="Only keep ES correlation searches, overriding the config's per-customer setting",
    )
    args = parser.parse_args()

    customers = load_config(args.config)

    if args.customer == "all":
        targets = list(customers.items())
    else:
        if args.customer not in customers:
            print(f"Unknown customer '{args.customer}'. Known: {list(customers)}", file=sys.stderr)
            sys.exit(1)
        targets = [(args.customer, customers[args.customer])]

    exit_code = 0
    for name, cfg in targets:
        try:
            process_customer(name, cfg, args.correlation_only)
        except Exception as e:
            print(f"[{name}] ERROR: {e}", file=sys.stderr)
            exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()