"""Offline tests for refresher.py — a fake export stands in for Splunk/Falcon.

    python test_refresh.py
"""
import datetime as dt
import json
import os
import tempfile
import threading

from refresher import Refresher

passed = failed = 0


def check(name, cond, extra=""):
    global passed, failed
    passed += bool(cond); failed += (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else f"  <<< {extra}"))


FAKE = r'''
import argparse, json, os, sys, time
p = argparse.ArgumentParser(); p.add_argument("--config"); p.add_argument("--combined-output"); a = p.parse_args()
mode = open("mode").read().strip()
if mode == "fail":
    print("[globex] 401 unauthorized with token " + os.environ.get("Splunk_TOKEN_GLOBEX", "")); sys.exit(1)
if mode == "empty":
    json.dump({}, open(a.combined_output, "w")); sys.exit(0)
if mode == "slow":
    time.sleep(1.5)
json.dump({"globex": {"splunk": [{"name": "r1"}, {"name": "r2"}], "falcon_edr": [{"name": "f"}]}}, open(a.combined_output, "w"))
'''

with tempfile.TemporaryDirectory() as tmp:
    pipe = os.path.join(tmp, "pipeline"); os.makedirs(os.path.join(pipe, "rules"))
    open(os.path.join(pipe, "automatic.py"), "w").write(FAKE)
    open(os.path.join(pipe, "customers.yaml"), "w").write("customers: {}\n")
    secrets = os.path.join(tmp, "secrets.env")
    open(secrets, "w").write("# comment\nSplunk_TOKEN_GLOBEX=super-secret-token-123\nEMPTY=\n")
    combined = os.path.join(pipe, "rules", "_all_rules_combined.json")
    json.dump({"old": {"splunk": [{"name": "old"}]}}, open(combined, "w"))
    mode = lambda m: open(os.path.join(pipe, "mode"), "w").write(m)
    r = Refresher(pipe, combined, secrets_file=secrets, at="06:00", tz="Asia/Dubai")

    mode("ok")
    s = r.run("manual:test")
    check("a successful export replaces the live rules file", "globex" in json.load(open(combined)), s)
    check("the previous rules file is kept", "old" in json.load(open(os.path.join(pipe, "rules", "_all_rules_combined.prev.json"))))
    check("status records success, trigger and rule counts",
          s["ok"] is True and s["last_attempt_trigger"] == "manual:test" and s["last_success_at"]
          and s["rules"] == {"globex": {"splunk": 2, "falcon_edr": 1}} and not s["running"], s)
    first_success = s["last_success_at"]

    mode("fail")
    s = r.run("schedule")
    check("a failed export leaves the live rules untouched", "globex" in json.load(open(combined)))
    check("a failure is reported with the export's last output", s["ok"] is False and "401 unauthorized" in (s["error"] or ""), s)
    check("secret values are masked in the error", "super-secret-token-123" not in (s["error"] or "") and "****" in s["error"], s["error"])
    check("secret values are masked in the run log",
          "super-secret-token-123" not in open(os.path.join(pipe, "rules", "_refresh_last.log")).read())
    check("the last success time survives a failure", s["last_success_at"] == first_success and s["rules"], s)
    check("no staging file is left behind", not os.path.exists(os.path.join(pipe, "rules", "_all_rules_combined.next.json")))

    mode("empty")
    s = r.run("manual:test")
    check("an export with no rules is treated as a failure", s["ok"] is False and "globex" in json.load(open(combined)), s)

    mode("slow")
    check("a background run starts", r.start("manual:a") == "started")
    check("a second run while one is going is refused", r.start("manual:b") == "already-running")
    check("status shows the run in progress with its trigger",
          r.status()["running"] and r.status()["running_trigger"] == "manual:a")
    for _ in range(50):
        if not r.status()["running"]:
            break
        threading.Event().wait(0.1)
    check("the background run finishes and records success", not r.status()["running"] and r.status()["ok"] is True)

    dubai = dt.timezone(dt.timedelta(hours=4))
    n = r.next_run(dt.datetime(2026, 9, 15, 5, 0, tzinfo=dubai))
    check("before 06:00 Dubai the next run is today", n == dt.datetime(2026, 9, 15, 2, 0, tzinfo=dt.timezone.utc), n)
    n = r.next_run(dt.datetime(2026, 9, 15, 6, 0, tzinfo=dubai))
    check("at or after 06:00 Dubai the next run is tomorrow", n == dt.datetime(2026, 9, 16, 2, 0, tzinfo=dt.timezone.utc), n)
    os.utime(combined, (0, 0))
    check("a rules file older than a day is stale", r.is_stale())
    os.utime(combined, None)
    check("a fresh rules file is not stale", not r.is_stale())

print(f">>> RESULT: {passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
