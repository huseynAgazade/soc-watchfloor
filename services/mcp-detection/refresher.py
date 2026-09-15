"""Re-runs the detection export (pipeline/automatic.py): every day at a set time,
once at start-up when the data is more than a day old, and on demand.

The export polls Splunk saved searches and CrowdStrike Falcon rules with the
keys in secrets.env — no LLM is involved. It writes to a staging file first; the
live `_all_rules_combined.json` is replaced only when the export succeeds and its
output parses, so a failed run never empties the MITRE page. The previous file is
kept as `_all_rules_combined.prev.json`.

Status (last attempt, last success, error, rule counts) is kept next to the data
in `_refresh_status.json`; the output of the last run in `_refresh_last.log`.
Secret values are masked in both.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import threading
import time
from zoneinfo import ZoneInfo

UTC = dt.timezone.utc


def _now() -> dt.datetime:
    return dt.datetime.now(UTC)


def _iso(t: dt.datetime | None) -> str | None:
    return t.astimezone(UTC).isoformat() if t else None


def _parse(s: str | None) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(s) if s else None
    except ValueError:
        return None


def read_env_file(path: str | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path or not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


class Refresher:
    def __init__(self, pipeline_dir: str, combined_path: str, *, secrets_file: str | None = None,
                 at: str = "06:00", tz: str = "Asia/Dubai", timeout: int = 900,
                 stale_hours: float = 26, python: str = sys.executable):
        self.pipeline_dir = pipeline_dir
        self.combined = os.path.abspath(combined_path)
        base = os.path.dirname(self.combined)
        self.staging = os.path.join(base, "_all_rules_combined.next.json")
        self.previous = os.path.join(base, "_all_rules_combined.prev.json")
        self.status_path = os.path.join(base, "_refresh_status.json")
        self.log_path = os.path.join(base, "_refresh_last.log")
        self.secrets_file = secrets_file
        self.hour, self.minute = (int(x) for x in at.split(":"))
        self.tz = ZoneInfo(tz)
        self.timeout = timeout
        self.stale_hours = stale_hours
        self.python = python
        self._lock = threading.Lock()
        self._running_since: dt.datetime | None = None
        self._trigger: str | None = None
        self._scheduler: threading.Thread | None = None

    # ---- schedule
    def next_run(self, now: dt.datetime | None = None) -> dt.datetime:
        local = (now or _now()).astimezone(self.tz)
        target = local.replace(hour=self.hour, minute=self.minute, second=0, microsecond=0)
        if target <= local:
            target += dt.timedelta(days=1)
        return target.astimezone(UTC)

    def synced_at(self) -> dt.datetime | None:
        try:
            return dt.datetime.fromtimestamp(os.path.getmtime(self.combined), UTC)
        except OSError:
            return None

    def is_stale(self, now: dt.datetime | None = None) -> bool:
        s = self.synced_at()
        return s is None or (now or _now()) - s > dt.timedelta(hours=self.stale_hours)

    # ---- status
    def _load(self) -> dict:
        try:
            with open(self.status_path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict) -> None:
        tmp = self.status_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.status_path)

    def status(self) -> dict:
        s = self._load()
        return {
            "synced_at": _iso(self.synced_at()),
            "running": self._lock.locked(),
            "running_since": _iso(self._running_since) if self._lock.locked() else None,
            "running_trigger": self._trigger if self._lock.locked() else None,
            "last_attempt_at": s.get("last_attempt_at"),
            "last_attempt_trigger": s.get("last_attempt_trigger"),
            "last_success_at": s.get("last_success_at"),
            "ok": s.get("ok"),
            "error": s.get("error"),
            "duration_s": s.get("duration_s"),
            "rules": s.get("rules"),
            "next_run_at": _iso(self.next_run()),
            "schedule": f"daily {self.hour:02d}:{self.minute:02d} {self.tz.key}",
        }

    # ---- running
    def _mask(self, text: str, secrets: list[str]) -> str:
        for v in secrets:
            text = text.replace(v, "****")
        return text

    def start(self, trigger: str) -> str:
        """Run in the background. Returns "started" or "already-running"."""
        if not self._lock.acquire(blocking=False):
            return "already-running"
        threading.Thread(target=self._run_locked, args=(trigger,), daemon=True).start()
        return "started"

    def run(self, trigger: str) -> dict:
        """Run in this thread (tests, CLI). Returns the status after the run."""
        if not self._lock.acquire(blocking=False):
            return {**self.status(), "error": "already running"}
        self._run_locked(trigger)
        return self.status()

    def _run_locked(self, trigger: str) -> None:
        try:
            self._running_since, self._trigger = _now(), trigger
            self._execute(trigger)
        finally:
            self._running_since = self._trigger = None
            self._lock.release()

    def _execute(self, trigger: str) -> None:
        started = _now()
        secrets = read_env_file(self.secrets_file)
        env = {**os.environ, **secrets}
        masked = [v for v in secrets.values() if len(v) >= 6]
        prev = self._load()
        out, rc = "", -1
        try:
            if os.path.exists(self.staging):
                os.remove(self.staging)
            p = subprocess.run([self.python, "automatic.py", "--config", "customers.yaml",
                                "--combined-output", self.staging],
                               cwd=self.pipeline_dir, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=self.timeout)
            out, rc = p.stdout or "", p.returncode
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or "") if isinstance(e.stdout, str) else ""
            out += f"\nexport timed out after {self.timeout} s"
        except OSError as e:
            out = f"could not start the export: {e}"
        out = self._mask(out, masked)

        data, error = None, None
        if rc == 0:
            try:
                with open(self.staging, encoding="utf-8") as f:
                    data = json.load(f)
                if not isinstance(data, dict) or not data:
                    data, error = None, "the export produced no rules"
            except (OSError, ValueError) as e:
                error = f"the export output could not be read: {type(e).__name__}"
        else:
            tail = [ln for ln in out.splitlines() if ln.strip()][-6:]
            error = "\n".join(tail) or f"export exited with code {rc}"

        status = {"last_attempt_at": _iso(started), "last_attempt_trigger": trigger,
                  "duration_s": round((_now() - started).total_seconds(), 1),
                  "last_success_at": prev.get("last_success_at"), "rules": prev.get("rules")}
        if data is not None:
            if os.path.exists(self.combined):
                os.replace(self.combined, self.previous)
            os.replace(self.staging, self.combined)
            status.update(ok=True, error=None, last_success_at=_iso(_now()),
                          rules={c: {s: len(r) for s, r in (srcs or {}).items()} for c, srcs in data.items()})
        else:
            if os.path.exists(self.staging):
                os.remove(self.staging)
            status.update(ok=False, error=self._mask(error or "export failed", masked)[:2000])
        self._save(status)
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(f"{_iso(started)} trigger={trigger} rc={rc}\n{out}")

    # ---- scheduler
    def start_scheduler(self, catch_up_delay: float = 60) -> None:
        if self._scheduler is not None:
            return

        def loop():
            if self.is_stale():
                time.sleep(catch_up_delay)
                if self.is_stale():
                    self.start("catch-up")
            while True:
                target = self.next_run()
                while _now() < target:
                    time.sleep(min(30.0, max(1.0, (target - _now()).total_seconds())))
                self.start("schedule")
                time.sleep(61)

        self._scheduler = threading.Thread(target=loop, daemon=True, name="detection-refresh")
        self._scheduler.start()
