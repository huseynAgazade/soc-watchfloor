"""Password policy, shared by every path that sets a password: an admin creating
an account, an admin resetting one, and a user changing their own."""
from __future__ import annotations

from ..config import settings

# Passwords that have appeared in this repository's code or history. They are
# public, so no account may use them.
SHARED_TEMP_PASSWORDS = frozenset({"changeme-temp"})
COMMITTED_ADMIN_PASSWORDS = frozenset({"changeme-admin", "changeme-admin-1234"})
KNOWN_LEAKED = SHARED_TEMP_PASSWORDS | COMMITTED_ADMIN_PASSWORDS


def password_problem(password: str, username: str = "") -> str | None:
    """Why `password` is not acceptable, or None when it is."""
    if len(password) < settings.password_min_length:
        return f"password must be at least {settings.password_min_length} characters"
    if password in KNOWN_LEAKED:
        return "that password is publicly known and cannot be used"
    if username and password.lower() == username.lower():
        return "password must not be the username"
    return None
