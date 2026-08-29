"""Parse the SOAR monthly_shift_roster list into the roster the portal renders.

List shape (list 43): row 0 is the header of day labels ("", "8/1/2026", ...,
""); each later row is [username, code, code, ...] for that month. Codes:
  00:00-08:00 -> N (night)   08:00-16:00 -> M (morning)   16:00-00:00 -> E (evening)
  off        -> O (day off) leave        -> L (leave)      ''  -> '' (unassigned)
"""
from __future__ import annotations

import datetime

_CODE = {
    "00:00-08:00": "N", "08:00-16:00": "M", "16:00-00:00": "E",
    "off": "O", "leave": "L", "": "",
}
_WD = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
# which shift code is "on" for a given hour-of-day
_WINDOW_FOR_HOUR = lambda h: "N" if h < 8 else ("M" if h < 16 else "E")  # noqa: E731


def _parse_header(hdr: list[str]) -> list[dict]:
    days = []
    for cell in hdr:
        cell = (cell or "").strip()
        if not cell:
            continue
        try:
            m, d, y = cell.split("/")
            dt = datetime.date(int(y), int(m), int(d))
        except ValueError:
            continue
        days.append({"d": dt.day, "w": _WD[dt.weekday()], "we": 1 if dt.weekday() >= 5 else 0,
                     "iso": dt.isoformat()})
    return days


def parse(content: list[list]) -> dict:
    if not content:
        return {"days": [], "people": [], "month": ""}
    header = content[0]
    days = _parse_header(header)
    # index in each data row where the day cells start (skip the username at [0],
    # and any leading empty header cell already dropped by _parse_header)
    lead_empty = 1 if header and (header[0] or "").strip() == "" else 0
    n = len(days)
    people = []
    for row in content[1:]:
        if not row or not (row[0] or "").strip():
            continue
        user = row[0].strip()
        cells = row[1 + lead_empty: 1 + lead_empty + n]
        codes = [_CODE.get((c or "").strip(), "") for c in cells]
        while len(codes) < n:
            codes.append("")
        people.append({"u": user, "s": codes})
    month = ""
    if days:
        try:
            month = datetime.date.fromisoformat(days[0]["iso"]).strftime("%B %Y")
        except ValueError:
            month = ""
    return {"days": days, "people": people, "month": month}


def on_shift(roster: dict, when: datetime.datetime) -> dict:
    """Who is on each window on the given day/time."""
    day = when.day
    idx = next((i for i, d in enumerate(roster["days"]) if d["d"] == day), None)
    windows = {"M": [], "E": [], "N": []}
    if idx is None:
        return {"date": when.date().isoformat(), "current": _WINDOW_FOR_HOUR(when.hour), "windows": windows}
    for p in roster["people"]:
        code = p["s"][idx] if idx < len(p["s"]) else ""
        if code in windows:
            windows[code].append(p["u"])
    return {"date": when.date().isoformat(), "current": _WINDOW_FOR_HOUR(when.hour), "windows": windows}
