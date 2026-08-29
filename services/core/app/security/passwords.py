"""Argon2id password hashing. Never store or log a plaintext password."""
from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# Argon2id defaults are sensible; tuned for an on-prem server, not a phone.
_ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4)


def hash_password(plaintext: str) -> str:
    return _ph.hash(plaintext)


def verify_password(stored_hash: str, plaintext: str) -> bool:
    try:
        return _ph.verify(stored_hash, plaintext)
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _ph.check_needs_rehash(stored_hash)
    except Exception:
        return False
