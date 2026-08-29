"""Opaque session tokens. The token is random; all state lives server-side in the
sessions table (Redis in production). Only a hash of the token is stored, so a
DB leak does not hand over live sessions."""
from __future__ import annotations

import hashlib
import secrets


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
