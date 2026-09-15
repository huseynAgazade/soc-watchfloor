"""Parse the SOAR monthly_shift_roster list into the roster the portal renders.

List shape (monthly_shift_roster): row 0 is the header of day labels ("", "8/1/2026", ...,
""); each later row is [username, code, code, ...] for that month. Codes:
  00:00-08:00 -> N (night)   08:00-16:00 -> M (morning)   16:00-00:00 -> E (evening)
  ist.        -> O (day off) leave        -> L (leave)      ''  -> '' (unassigned)
"""
from __future__ import annotations

import datetime

_CODE = {
    "00:00-08:00": "N", "08:00-16:00": "M", "16:00-00:00": "E",
    "ist.": "O", "leave": "L", "": "",
}
_WD = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
# which shift code is "on" for a given hour-of-day
_WINDOW_FOR_HOUR = lambda h: "N" if h < 8 else ("M" if h < 16 else "E")  # noqa: E731


def _parse_header(hdr: list[str]) -> list[dict]:
    days = []
    for col, cell in enumerate(hdr):
        cell = (cell or "").strip()
        if not cell:
            continue
        try:
            m, d, y = cell.split("/")
            dt = datetime.date(int(y), int(m), int(d))
        except ValueError:
            continue
        days.append({"d": dt.day, "w": _WD[dt.weekday()], "we": 1 if dt.weekday() >= 5 else 0,
                     "iso": dt.isoformat(), "col": col})
    return days


def parse(content: list[list]) -> dict:
    if not content:
        return {"days": [], "people": [], "month": ""}
    days = _parse_header(content[0])
    # A day's codes sit in the same column as its date in the header row; column 0
    # is the username (its header cell is empty). Reading by that column index
    # keeps every code under its own date.
    cols = [d.pop("col") for d in days]
    people = []
    for row in content[1:]:
        if not row or not (row[0] or "").strip():
            continue
        codes = [_CODE.get((row[c] or "").strip(), "") if c < len(row) else "" for c in cols]
        people.append({"u": row[0].strip(), "s": codes})
    month = ""
    if days:
        try:
            month = datetime.date.fromisoformat(days[0]["iso"]).strftime("%B %Y")
        except ValueError:
            month = ""
    return {"days": days, "people": people, "month": month}


def on_shift(roster: dict, when: datetime.datetime) -> dict:
    """Who is on each window on the given day/time. `when` must already be in the
    org timezone; the day is matched by full date, so a roster for another month
    reports nobody rather than the same day-of-month."""
    iso = when.date().isoformat()
    idx = next((i for i, d in enumerate(roster["days"]) if d.get("iso") == iso), None)
    windows = {"M": [], "E": [], "N": []}
    if idx is None:
        return {"date": iso, "current": _WINDOW_FOR_HOUR(when.hour), "windows": windows,
                "covered": False}
    for p in roster["people"]:
        code = p["s"][idx] if idx < len(p["s"]) else ""
        if code in windows:
            windows[code].append(p["u"])
    return {"date": iso, "current": _WINDOW_FOR_HOUR(when.hour), "windows": windows, "covered": True}
