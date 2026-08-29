"""Minimal read-only Splunk SOAR REST client for the roster connector.

The analyst roster lives in a SOAR custom list (monthly_shift_roster). This
reads it over the SOAR REST API with a token. Read-only.

Config (environment):
  SPLUNK_SOAR_URL   e.g. https://10.0.0.12:8443
  SPLUNK_SOAR_API   a SOAR automation token (ph-auth-token)
  SOAR_VERIFY_SSL   "true"/"false" (default false for self-signed)
"""
from __future__ import annotations

import os

import httpx


class SoarError(RuntimeError):
    pass


class SoarClient:
    def __init__(self) -> None:
        self.base = os.environ.get("SPLUNK_SOAR_URL", "").rstrip("/")
        self.token = os.environ.get("SPLUNK_SOAR_API", "")
        verify = os.environ.get("SOAR_VERIFY_SSL", "false").lower() == "true"
        if not self.base or not self.token:
            raise SoarError("SPLUNK_SOAR_URL / SPLUNK_SOAR_API not set")
        self._c = httpx.Client(verify=verify, timeout=30.0,
                               headers={"ph-auth-token": self.token})

    def get(self, path: str) -> dict:
        r = self._c.get(f"{self.base}/rest/{path.lstrip('/')}")
        if r.status_code != 200:
            raise SoarError(f"HTTP {r.status_code} on /rest/{path}: {r.text[:160]}")
        return r.json()

    def decided_list(self, list_id: int | str) -> list[list]:
        return self.get(f"decided_list/{list_id}").get("content", [])

    def close(self) -> None:
        self._c.close()
