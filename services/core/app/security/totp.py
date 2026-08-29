"""Optional TOTP (RFC 6238). Offline, no vendor — suits an on-prem deployment.
The secret is generated here and stored per-user; enrolment verifies one code
before the account is locked to it."""
from __future__ import annotations

import pyotp


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str, issuer: str = "SOC Watchfloor") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)
