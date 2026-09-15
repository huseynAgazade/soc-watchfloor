"""SPL for the query catalog: validation and token rendering.

Catalog queries never contain a literal time range or tenant. They carry tokens
the server fills on every run from the resolved period and the caller's scope:

  $earliest$ / $latest$           window bounds, epoch seconds
  $earliest_iso$ / $latest_iso$   window bounds, ISO-8601 UTC
  $tenants$                       "id1","id2" — tenant ids in scope   (e.g. tenant IN ($tenants$))
  $tenant_labels$                 "label1",…  — their SOAR labels     (e.g. label IN ($tenant_labels$))
  $soar_containers$               the SOAR containers created in the window, via restsoar,
                                  fetched in slices so a long window is never cut short
  $include:<fragment id>$         the SPL of a catalog fragment (shared building blocks)

Every run also bounds the search job itself to the window (earliest_time /
latest_time), so plain index searches need no time tokens at all.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

BLOCKED_COMMANDS = ("delete", "collect", "outputlookup", "outputcsv", "outputtext", "tscollect",
                    "sendemail", "sendalert", "sendresults", "script", "run", "runshellscript",
                    "mcollect", "meventcollect", "dbxoutput")
_BLOCKED = re.compile(r"(?:\A|\|)\s*(" + "|".join(BLOCKED_COMMANDS) + r")\b", re.I)
TOKENS = frozenset({"earliest", "latest", "earliest_iso", "latest_iso", "tenants", "tenant_labels",
                    "soar_containers"})
TENANT_TOKENS = frozenset({"tenants", "tenant_labels"})
SCOPE_MODES = ("tenant_token", "global")
_TOKEN = re.compile(r"\$([a-z_]+)\$")
_INCLUDE = re.compile(r"\$include:([A-Za-z0-9_.\-]+)\$")
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9_.:\-]+$")
MAX_LENGTH = 20000
MAX_INCLUDE_DEPTH = 4
# restsoar slice. Measured on soc_soar (Sep 2026, ~430 containers/day): a 30-day
# window took 21 s in 3-day slices, 9.5 s in 7-day and 6.6 s in 14-day, same rows.
SLICE = timedelta(days=14)


class SplError(ValueError):
    pass


def expand(spl: str, fragments: dict[str, str], _seen: tuple = ()) -> str:
    """Replace $include:id$ with the fragment's SPL, recursively."""
    def sub(m: re.Match) -> str:
        fid = m.group(1)
        if fid in _seen:
            raise SplError(f"fragment {fid} includes itself")
        if fid not in fragments:
            raise SplError(f"unknown fragment: {fid}")
        if len(_seen) >= MAX_INCLUDE_DEPTH:
            raise SplError("fragments are nested too deeply")
        return expand(fragments[fid], fragments, _seen + (fid,))
    return _INCLUDE.sub(sub, spl)


def includes(spl: str) -> set[str]:
    return set(_INCLUDE.findall(spl or ""))


def tokens_used(spl: str) -> set[str]:
    return set(_TOKEN.findall(spl))


def problems(spl: str, fragments: dict[str, str], scope_mode: str | None = "tenant_token") -> list[str]:
    """Why this SPL cannot be saved or run — empty when it is fine. scope_mode None
    checks a fragment (no tenant filter required)."""
    if not (spl or "").strip():
        return ["the query is empty"]
    out = []
    if len(spl) > MAX_LENGTH:
        out.append(f"the query is longer than {MAX_LENGTH} characters")
    try:
        full = expand(spl, fragments)
    except SplError as e:
        return out + [str(e)]
    bad = sorted({m.group(1).lower() for m in _BLOCKED.finditer(full)})
    if bad:
        out.append("writing commands are not allowed: " + ", ".join(bad))
    used = tokens_used(full)
    unknown = used - TOKENS
    if unknown:
        out.append("unknown tokens: " + ", ".join(f"${t}$" for t in sorted(unknown)))
    if scope_mode is not None:
        if scope_mode not in SCOPE_MODES:
            out.append("scope mode must be tenant_token or global")
        elif scope_mode == "tenant_token" and not used & TENANT_TOKENS:
            out.append("a tenant-scoped query must filter with $tenants$ or $tenant_labels$")
    return out


def quoted(values: list[str]) -> str:
    return ",".join(f'"{v}"' for v in values if _SAFE_VALUE.match(v or ""))


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def soar_containers(start: datetime, end: datetime, server: str) -> str:
    """restsoar over [start, end), one slice per SLICE, stitched with append. SOAR
    applies the window itself (create_time filter) and returns every row."""
    def one(a: datetime, b: datetime) -> str:
        return (f'| restsoar soar_server="{server}" endpoint="/container?sort=id&order=asc&page_size=0'
                f'&_filter_create_time__gte=%22{_iso(a)}%22&_filter_create_time__lt=%22{_iso(b)}%22"')
    parts, cur = [], start
    while cur < end:
        nxt = min(cur + SLICE, end)
        parts.append(one(cur, nxt))
        cur = nxt
    if not parts:
        raise SplError("empty window")
    return parts[0] + "".join(f"\n| append [{p}]" for p in parts[1:])


def render(spl: str, fragments: dict[str, str], *, start: datetime, end: datetime,
           tenant_ids: list[str], tenant_labels: list[str], soar_server: str) -> str:
    full = expand(spl, fragments)
    used = tokens_used(full)
    values = {
        "earliest": str(int(start.timestamp())), "latest": str(int(end.timestamp())),
        "earliest_iso": _iso(start), "latest_iso": _iso(end),
        "tenants": quoted(tenant_ids), "tenant_labels": quoted(tenant_labels),
    }
    if "soar_containers" in used:
        values["soar_containers"] = soar_containers(start, end, soar_server)
    return _TOKEN.sub(lambda m: values.get(m.group(1), m.group(0)), full)
