#!/usr/bin/env python3
"""
automatic.py

Runs every export script against every customer defined in
customers.yaml (via each script's own --customer all), then combines
all the resulting rule JSON files into one file via json_automatic_mapper.py.
New customers added to customers.yaml are picked up automatically --
nothing here is hardcoded per customer.

Usage:
    python3 automatic.py --config customers.yaml \
        --combined-output rules/_all_rules_combined.json

Expects splunk-export.py, falcon-export.py, and json_automatic_mapper.py to
live in the same directory as this script.
"""

import argparse
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Add more export scripts here if needed (e.g. "ngsiem-rules-export.py")
# -- each just needs to support --config / --customer the same way.
EXPORT_SCRIPTS = [
    "splunk-export.py",
    "falcon-export.py",
]


def run_script(script_name, config_path):
    script_path = os.path.join(SCRIPT_DIR, script_name)
    if not os.path.isfile(script_path):
        print(f"WARNING: {script_path} not found, skipping")
        return True

    print(f"--- running {script_name} --customer all ---")
    result = subprocess.run([sys.executable, script_path, "--config", config_path, "--customer", "all"])
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(description="Run all export scripts for all customers, then combine results.")
    parser.add_argument("--config", default="customers.yaml", help="Path to customers.yaml")
    parser.add_argument(
        "--combined-output",
        default="rules/_all_rules_combined.json",
        help="Path to write the combined JSON produced by json_automatic_mapper.py",
    )
    args = parser.parse_args()

    config_path = os.path.abspath(args.config)

    all_ok = True
    for script_name in EXPORT_SCRIPTS:
        ok = run_script(script_name, config_path)
        all_ok = all_ok and ok

    print("--- combining all exported rules ---")
    mapping_script = os.path.join(SCRIPT_DIR, "json_automatic_mapper.py")
    result = subprocess.run([sys.executable, mapping_script, "--config", config_path, "--output", args.combined_output])
    all_ok = all_ok and (result.returncode == 0)

    if not all_ok:
        print("automatic.py finished with at least one error above -- check the output for which step failed", file=sys.stderr)
        sys.exit(1)

    print("automatic.py finished successfully")


if __name__ == "__main__":
    main()