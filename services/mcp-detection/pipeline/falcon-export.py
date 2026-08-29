#!/usr/bin/env python3
"""
falcon-export.py

Pulls NG-SIEM Correlation Rules from CrowdStrike Falcon's Correlation
Rules API (/correlation-rules/...) for one or more CIDs, optionally
filtered to rules authored by a specific user (user_uuid or user_id).
If the filtered request fails, falls back to fetching all rules
unfiltered rather than erroring out.

mitre_attack is written out as "TA00XX:T1XXX" strings, same shape as
splunk_export_rules.py produces -- so map_mitre_rules.py works unchanged
against either source.

Multi-CID support:
    Each tenant gets its own block under "ngsiem_customers" in
    customers.yaml (base_url, client_id/secret, optional author filter,
    output_dir) -- same pattern as falcon_customers / customers.

Usage:
    python3 falcon-export.py --config customers.yaml --customer customer1
    python3 falcon-export.py --config customers.yaml --customer all

Falcon API client needs the "Correlation Rules: READ" scope.

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

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def load_config(path):
    with open(path, "r") as f:
        cfg = yaml.safe_load(f)
    if not cfg or "ngsiem_customers" not in cfg:
        raise ValueError(f"'{path}' has no top-level 'ngsiem_customers' key")
    return cfg["ngsiem_customers"]


def _read_secret_file(path):
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


def _resolve_secret(customer_name, cfg, env_key, file_key, prompt):
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


def get_oauth_token(customer_name, cfg):
    client_id = _resolve_secret(customer_name, cfg, "client_id_env", "client_id_file", "Falcon client ID")
    client_secret = _resolve_secret(
        customer_name, cfg, "client_secret_env", "client_secret_file", "Falcon client secret"
    )
    verify_ssl = cfg.get("verify_ssl", True)

    url = f"{cfg['base_url'].rstrip('/')}/oauth2/token"
    resp = requests.post(
        url,
        data={"client_id": client_id, "client_secret": client_secret},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        verify=verify_ssl,
        timeout=30,
    )
    resp.raise_for_status()
    token = resp.json().get("access_token")
    if not token:
        raise RuntimeError(f"[{customer_name}] OAuth token request succeeded but no access_token in response")
    return token


def build_author_filter(cfg):
    """
    Returns an FQL filter string scoped to the rule author, or None if no
    author filter is configured. user_uuid takes priority over user_id if
    both are set.
    """
    user_uuid = cfg.get("author_user_uuid")
    if user_uuid:
        return f"user_uuid:'{user_uuid}'"

    user_id = cfg.get("author_user_id")
    if user_id:
        return f"user_id:'{user_id}'"

    return None


def fetch_combined_rules(base_url, token, filter_str, verify_ssl):
    rules = []
    offset = 0
    limit = 500
    headers = {"Authorization": f"Bearer {token}"}

    while True:
        params = {"offset": offset, "limit": limit}
        if filter_str:
            params["filter"] = filter_str

        url = f"{base_url.rstrip('/')}/correlation-rules/combined/rules/v2"
        resp = requests.get(url, headers=headers, params=params, verify=verify_ssl, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        batch = data.get("resources", [])
        rules.extend(batch)

        total = data.get("meta", {}).get("pagination", {}).get("total", len(rules))
        offset += len(batch)
        if not batch or offset >= total:
            break

    return rules


def extract_rule_data(rule):
    mitre_raw = rule.get("mitre_attack") or []
    mitre_combined = []
    for entry in mitre_raw:
        tactic_id = entry.get("tactic_id")
        technique_id = entry.get("technique_id")
        if tactic_id and technique_id:
            mitre_combined.append(f"{tactic_id}:{technique_id}")
        elif tactic_id:
            mitre_combined.append(tactic_id)

    search = rule.get("search") or {}
    operation = rule.get("operation") or {}
    schedule = operation.get("schedule") or {}

    return {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "description": rule.get("description"),
        "status": rule.get("status"),
        "severity": rule.get("severity"),
        "tactic": rule.get("tactic"),
        "technique": rule.get("technique"),
        "mitre_attack": mitre_combined,
        "search_filter": search.get("filter"),
        "search_lookback": search.get("lookback"),
        "search_outcome": search.get("outcome"),
        "search_trigger_mode": search.get("trigger_mode"),
        "schedule_definition": schedule.get("definition"),
        "start_on": operation.get("start_on"),
        "stop_on": operation.get("stop_on"),
        "customer_id": rule.get("customer_id"),
        "user_id": rule.get("user_id"),
        "user_uuid": rule.get("user_uuid"),
        "created_on": rule.get("created_on"),
        "updated": rule.get("last_updated_on"),
        "comment": rule.get("comment"),
    }


def sanitize_filename(name):
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
    return cleaned or "unnamed_rule"


def save_rules(rules, output_dir, customer_name):
    os.makedirs(output_dir, exist_ok=True)
    index = []
    for rule in rules:
        label = rule.get("name") or rule.get("name") or "unknown"
        fname = sanitize_filename(label) + ".json"
        fpath = os.path.join(output_dir, fname)
        with open(fpath, "w") as f:
            json.dump(rule, f, indent=2)
        index.append({"id": rule.get("id"), "name": rule.get("name"), "file": fname})

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


def process_customer(name, cfg):
    verify_ssl = cfg.get("verify_ssl", True)
    token = get_oauth_token(name, cfg)

    filter_str = build_author_filter(cfg)

    if filter_str:
        try:
            raw_rules = fetch_combined_rules(cfg["base_url"], token, filter_str, verify_ssl)
        except requests.exceptions.RequestException as e:
            print(f"[{name}] WARNING: author-filtered request failed ({e}); falling back to all rules, unfiltered")
            raw_rules = fetch_combined_rules(cfg["base_url"], token, None, verify_ssl)
    else:
        raw_rules = fetch_combined_rules(cfg["base_url"], token, None, verify_ssl)

    rules = [extract_rule_data(r) for r in raw_rules]
    save_rules(rules, cfg["output_dir"], name)
    print(f"[{name}] exported {len(rules)} rule(s) -> {cfg['output_dir']}")


def main():
    parser = argparse.ArgumentParser(description="Export NG-SIEM Correlation Rules per CID/customer.")
    parser.add_argument("--config", default="customers.yaml", help="Path to customers.yaml")
    parser.add_argument("--customer", default="all", help="Customer key from ngsiem_customers, or 'all'")
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
            process_customer(name, cfg)
        except Exception as e:
            print(f"[{name}] ERROR: {e}", file=sys.stderr)
            exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()