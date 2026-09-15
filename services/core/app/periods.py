"""Reporting periods, resolved server-side in the organisation's timezone.

The browser sends a period key (or a custom date range); this turns it into an
exact UTC [start, end) interval. Relative words never reach a connector — every
connector receives absolute bounds, so two pages asking for "last 30 days" at the
same moment get the same numbers.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from .config import settings

LABELS = {
    "24h": "Last 24 hours", "d7": "Last 7 days", "d30": "Last 30 days", "d60": "Last 60 days",
    "d90": "Last 90 days", "mtd": "Month to date", "prev": "Previous month", "custom": "Custom range",
}
_DAYS = {"d7": 7, "d30": 30, "d60": 60, "d90": 90}
# the older ?window= spelling, still accepted
_WINDOWS = {"24h": "24h", "7d": "d7", "30d": "d30", "60d": "d60", "90d": "d90"}


class PeriodError(ValueError):
    pass


@dataclass(frozen=True)
class Period:
    key: str
    start: datetime   # UTC, inclusive
    end: datetime     # UTC, exclusive

    def as_dict(self) -> dict:
        tz = ZoneInfo(settings.org_timezone)
        last = (self.end - timedelta(microseconds=1)).astimezone(tz)
        return {"key": self.key, "label": LABELS[self.key],
                "start": _iso(self.start), "end": _iso(self.end),
                "from": self.start.astimezone(tz).date().isoformat(), "to": last.date().isoformat(),
                "timezone": settings.org_timezone}


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _midnight(d: date, tz: ZoneInfo) -> datetime:
    return datetime.combine(d, time.min, tzinfo=tz).astimezone(timezone.utc)


def resolve(period: str | None = None, date_from: str | None = None, date_to: str | None = None,
            window: str | None = None, default: str = "d30", now: datetime | None = None) -> Period:
    tz = ZoneInfo(settings.org_timezone)
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    today = now.astimezone(tz).date()

    if period:
        key = period
    elif window:
        if window not in _WINDOWS:
            raise PeriodError(f"unknown window: {window}")
        key = _WINDOWS[window]
    else:
        key = default

    if key == "24h":
        start, end = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=24), now
    elif key in _DAYS:
        start, end = _midnight(today - timedelta(days=_DAYS[key]), tz), now
    elif key == "mtd":
        start, end = _midnight(today.replace(day=1), tz), now
    elif key == "prev":
        first = today.replace(day=1)
        start, end = _midnight((first - timedelta(days=1)).replace(day=1), tz), _midnight(first, tz)
    elif key == "custom":
        try:
            d0, d1 = date.fromisoformat(date_from or ""), date.fromisoformat(date_to or "")
        except ValueError:
            raise PeriodError("a custom range needs from and to as YYYY-MM-DD")
        if d1 < d0:
            raise PeriodError("the range ends before it starts")
        if d0 > today:
            raise PeriodError("the range starts in the future")
        start, end = _midnight(d0, tz), min(_midnight(d1 + timedelta(days=1), tz), now)
    else:
        raise PeriodError(f"unknown period: {key}")

    if end - start > timedelta(days=settings.max_period_days + 1):
        raise PeriodError(f"periods are limited to {settings.max_period_days} days")
    return Period(key=key, start=start, end=end)
