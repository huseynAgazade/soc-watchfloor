"""Sign-in throttling per client address — protection against form spam and
password spraying.

The per-account lockout in auth.py stops guessing one account's password; this
stops one address trying many accounts. Only failures count, so people who sign
in normally are never slowed down. State is in process memory, like the
assistant limiter: right for the single core worker; a multi-worker deployment
would move it to Redis.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import Request

from ..config import settings

_MAX_KEYS = 10000


class FailureThrottle:
    def __init__(self) -> None:
        self._fails: dict[str, deque[float]] = defaultdict(deque)

    def _trim(self, key: str, window: float, now: float) -> deque[float]:
        q = self._fails[key]
        while q and now - q[0] >= window:
            q.popleft()
        return q

    def retry_after(self, key: str, limit: int, window: float) -> int:
        """Seconds until this address may try again, or 0 when it may now."""
        now = time.monotonic()
        q = self._trim(key, window, now)
        if len(q) < limit:
            if not q:
                self._fails.pop(key, None)
            return 0
        return max(1, int(window - (now - q[len(q) - limit])) + 1)

    def fail(self, key: str, window: float) -> int:
        """Record a failure; returns the failures from this address in the window."""
        now = time.monotonic()
        if len(self._fails) > _MAX_KEYS:
            for k in list(self._fails):
                if not self._trim(k, window, now):
                    self._fails.pop(k, None)
        q = self._trim(key, window, now)
        q.append(now)
        return len(q)

    def reset(self) -> None:
        self._fails.clear()


login_throttle = FailureThrottle()


def client_ip(request: Request) -> str:
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]
