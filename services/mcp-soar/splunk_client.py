"""Minimal read-only Splunk client for the SOAR/SLA connector.

Authenticates against Splunk Web (443) with CSRF handling and runs oneshot
searches through the web proxy. The management port (8089) is closed from the
app network, so this uses the same path the browser does. In production, prefer
a Splunk auth *token* (set SPLUNK_TOKEN) over a password.

Config (environment):
  SPLUNK_BASE_URL   e.g. https://siem.example
  SPLUNK_USERNAME   e.g. socadmin
  SPLUNK_PASSWORD   the account password (or use SPLUNK_TOKEN)
  SPLUNK_APP        search-app context for dispatch (default: search)
  SPLUNK_VERIFY_SSL "true"/"false" (default false for self-signed)
"""
from __future__ import annotations

import os
import re

import httpx


class SplunkError(RuntimeError):
    pass


class SplunkClient:
    def __init__(self) -> None:
        self.base = os.environ.get("SPLUNK_BASE_URL", "https://siem.example").rstrip("/")
        self.user = os.environ.get("SPLUNK_USERNAME", "socadmin")
        self.password = os.environ.get("SPLUNK_PASSWORD", "")
        self.token = os.environ.get("SPLUNK_TOKEN", "")
        self.app = os.environ.get("SPLUNK_APP", "search")
        verify = os.environ.get("SPLUNK_VERIFY_SSL", "false").lower() == "true"
        self._c = httpx.Client(verify=verify, timeout=180.0, follow_redirects=False)
        self._form_key: str | None = None
        self._authed = False

    # ---- auth ----
    def login(self) -> None:
        if self.token:
            self._authed = True
            return
        # 1. fetch login page for the cval CSRF value
        r = self._c.get(f"{self.base}/en-US/account/login", params={"return_to": "/en-US/"})
        cval = self._c.cookies.get("cval") or (re.search(r'"cval":(\d+)', r.text) or [None, ""])[1]
        if not cval:
            raise SplunkError("could not obtain login CSRF (cval)")
        # 2. post credentials
        r = self._c.post(
            f"{self.base}/en-US/account/login",
            data={"cval": cval, "username": self.user, "password": self.password, "return_to": "/en-US/"},
        )
        if r.status_code != 200 or "splunkd_8000" not in self._c.cookies:
            raise SplunkError(f"login failed (HTTP {r.status_code})")
        # 3. capture the form key used for subsequent POSTs
        self._form_key = self._c.cookies.get("splunkweb_csrf_token_8000")
        if not self._form_key:
            # touch an authed page to set it
            self._c.get(f"{self.base}/en-US/app/{self.app}/search")
            self._form_key = self._c.cookies.get("splunkweb_csrf_token_8000")
        self._authed = True

    def _headers(self) -> dict:
        h = {"X-Requested-With": "XMLHttpRequest"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        elif self._form_key:
            h["X-Splunk-Form-Key"] = self._form_key
        return h

    # ---- search ----
    def oneshot(self, spl: str, earliest: float | None = None, latest: float | None = None,
                count: int = 0) -> list[dict]:
        """Run a blocking search and return the result rows as dicts. earliest /
        latest (epoch seconds) bound the search job; count caps the rows (0 = all).

        With a token (preferred), go straight to the REST API on :8089 with a
        Bearer header — robust, no session to expire. Without one, fall back to
        the Splunk Web proxy + CSRF (password login)."""
        if not self._authed:
            self.login()
        if self.token:
            url = f"{self.base}/services/search/jobs"
        else:
            url = f"{self.base}/en-US/splunkd/__raw/servicesNS/{self.user}/{self.app}/search/jobs"
        data = {"search": spl, "exec_mode": "oneshot", "output_mode": "json", "count": str(count)}
        if earliest is not None:
            data["earliest_time"] = f"{earliest:.0f}"
        if latest is not None:
            data["latest_time"] = f"{latest:.0f}"
        r = self._c.post(url, headers=self._headers(), data=data)
        if r.status_code != 200:
            raise SplunkError(f"search HTTP {r.status_code}: {r.text[:200]}")
        data = r.json()
        if "results" not in data:
            raise SplunkError(f"search error: {data.get('messages')}")
        return data["results"]

    def close(self) -> None:
        self._c.close()
