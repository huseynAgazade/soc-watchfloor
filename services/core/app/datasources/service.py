"""Running catalog queries for a user: scope, rendering, execution and caching.

Dashboards (api/metrics.py, api/data.py) and the assistant's Watchfloor tools all
come through here, so a panel and a chat answer read the same rows under the same
scope rules:
  * tenant_token queries filter inside the SPL with the caller's tenants (and,
    when the query names a scope_field, the rows are filtered again after);
  * global queries (no tenant filter possible) run only for all-tenants accounts
    with the tenant selector on "all";
  * ad-hoc SPL needs the run_adhoc_queries capability and an all-tenants account.
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass

from sqlalchemy import select

from ..config import settings
from ..connectors import splunk
from ..db import SessionLocal
from ..deps import all_tenants, user_capabilities
from ..models import DataQuery, Tenant, User
from ..periods import Period
from ..rbac import Capability
from . import spl as spl_mod

MAX_ROWS = 5000
_NUMERIC = re.compile(r"^-?\d+(\.\d+)?$")
_cache: dict = {}


class ScopeDenied(Exception):
    pass


class QueryError(Exception):
    pass


class QueryNotFound(QueryError):
    pass


@dataclass
class Scope:
    tenant: str                  # "all" or one tenant id
    ids: list[str]
    labels: list[str]
    label_to_id: dict[str, str]
    all_tenants: bool


async def tenants_in_scope(user: User) -> list[Tenant]:
    async with SessionLocal() as db:
        rows = (await db.execute(select(Tenant).order_by(Tenant.name))).scalars().all()
    rows = [t for t in rows if t.state != "archived"]
    if all_tenants(user):
        return rows
    allowed = set(user.allowed_customer_ids or [])
    return [t for t in rows if t.id in allowed]


async def resolve_scope(user: User, tenant: str | None) -> Scope:
    rows = await tenants_in_scope(user)
    if tenant and tenant != "all":
        rows = [t for t in rows if t.id == tenant]
        if not rows:
            raise ScopeDenied("that tenant is outside your scope")
    return Scope(tenant=tenant or "all", ids=sorted(t.id for t in rows),
                 labels=sorted({t.label or t.id for t in rows}),
                 label_to_id={(t.label or t.id): t.id for t in rows}, all_tenants=all_tenants(user))


async def catalog() -> dict[str, DataQuery]:
    async with SessionLocal() as db:
        return {q.id: q for q in (await db.execute(select(DataQuery))).scalars().all()}


def fragments_of(cat: dict[str, DataQuery]) -> dict[str, str]:
    return {q.id: q.spl for q in cat.values() if q.category == "fragment"}


def _typed(rows: list[dict]) -> list[dict]:
    for r in rows:
        for k, v in list(r.items()):
            if isinstance(v, str) and _NUMERIC.match(v):
                r[k] = float(v) if "." in v else int(v)
    return rows


async def _execute(rendered: str, period: Period, max_rows: int, cache_seconds: int) -> tuple[list[dict], bool, bool]:
    key = (hashlib.sha256(rendered.encode()).hexdigest(), int(period.start.timestamp()),
           int(period.end.timestamp()) // max(cache_seconds, 1), max_rows)
    now = time.monotonic()
    if cache_seconds > 0:
        hit = _cache.get(key)
        if hit and now - hit[0] < cache_seconds:
            return [dict(r) for r in hit[1]], hit[2], True
    rows, truncated = await splunk.search(rendered, period.start, period.end, max_rows)
    rows = _typed(rows)
    if cache_seconds > 0:
        for k in [k for k, v in _cache.items() if now - v[0] >= 3600]:
            del _cache[k]
        _cache[key] = (now, [dict(r) for r in rows], truncated)
    return rows, truncated, False


async def _run_spl(spl_text: str, *, scope_mode: str, scope_field: str, cache_seconds: int, period: Period,
                   scope: Scope, max_rows: int, fragments: dict[str, str]) -> dict:
    issues = spl_mod.problems(spl_text, fragments, scope_mode)
    if issues:
        raise QueryError("; ".join(issues))
    if scope_mode == "global" and not (scope.all_tenants and scope.tenant == "all"):
        raise ScopeDenied("this query is not tenant-scoped, so it needs an all-tenants account "
                          "with the tenant set to all")
    started = time.monotonic()
    if scope_mode == "tenant_token" and not scope.ids:
        return {"rows": [], "row_count": 0, "truncated": False, "cached": False, "ms": 0}
    rendered = spl_mod.render(spl_text, fragments, start=period.start, end=period.end, tenant_ids=scope.ids,
                              tenant_labels=scope.labels, soar_server=settings.soar_splunk_server)
    rows, truncated, cached = await _execute(rendered, period, max_rows, cache_seconds)
    if scope_field:
        kept = []
        for r in rows:
            tid = scope.label_to_id.get(str(r.get(scope_field, "")), r.get(scope_field))
            if tid in scope.ids:
                r[scope_field] = tid
                kept.append(r)
        rows = kept
    return {"rows": rows, "row_count": len(rows), "truncated": truncated, "cached": cached,
            "ms": int((time.monotonic() - started) * 1000)}


async def list_queries(category: str | None = None, include_fragments: bool = False) -> list[DataQuery]:
    rows = sorted((await catalog()).values(), key=lambda q: (q.category, q.id))
    return [q for q in rows if (include_fragments or q.category != "fragment")
            and (not category or q.category == category)]


async def run_query(user: User, query_id: str, period: Period, tenant: str | None = "all",
                    max_rows: int = MAX_ROWS) -> dict:
    cat = await catalog()
    q = cat.get(query_id)
    if q is None:
        raise QueryNotFound(f"no such query: {query_id}")
    if q.category == "fragment":
        raise QueryError("fragments are building blocks and cannot run on their own")
    scope = await resolve_scope(user, tenant)
    res = await _run_spl(q.spl, scope_mode=q.scope_mode, scope_field=q.scope_field,
                         cache_seconds=q.cache_seconds, period=period, scope=scope,
                         max_rows=max(1, min(max_rows, MAX_ROWS)), fragments=fragments_of(cat))
    return {**res, "query": q.id, "version": q.version, "columns": q.columns, "tenant": scope.tenant,
            "period": period.as_dict()}


def can_run_adhoc(user: User) -> bool:
    return Capability.run_adhoc_queries in user_capabilities(user) and all_tenants(user)


async def run_adhoc(user: User, spl_text: str, period: Period, tenant: str | None = "all",
                    max_rows: int = 200) -> dict:
    """SPL written by a person (query console) or by the assistant. Never cached."""
    if not can_run_adhoc(user):
        raise ScopeDenied("ad-hoc queries need the run_adhoc_queries capability and an all-tenants account")
    cat = await catalog()
    fragments = fragments_of(cat)
    try:
        uses_tenant = bool(spl_mod.tokens_used(spl_mod.expand(spl_text or "", fragments)) & spl_mod.TENANT_TOKENS)
    except spl_mod.SplError as e:
        raise QueryError(str(e))
    # Without a tenant token the SPL names its own filter; the caller already sees
    # every tenant, so the selector does not restrict it.
    scope = await resolve_scope(user, tenant if uses_tenant else "all")
    res = await _run_spl(spl_text, scope_mode="tenant_token" if uses_tenant else "global", scope_field="",
                         cache_seconds=0, period=period, scope=scope, max_rows=max(1, min(max_rows, 1000)),
                         fragments=fragments)
    columns = list(res["rows"][0].keys()) if res["rows"] else []
    return {**res, "columns": columns, "tenant": scope.tenant, "period": period.as_dict()}


async def test_query(user: User, spl_text: str, scope_mode: str, scope_field: str, period: Period,
                     tenant: str | None, expected: list[str]) -> dict:
    """Run unsaved SPL for the data-source editor, uncached, and check its columns."""
    cat = await catalog()
    scope = await resolve_scope(user, tenant)
    res = await _run_spl(spl_text, scope_mode=scope_mode, scope_field=scope_field, cache_seconds=0,
                         period=period, scope=scope, max_rows=500, fragments=fragments_of(cat))
    found = list(res["rows"][0].keys()) if res["rows"] else []
    missing = [c for c in (expected or []) if res["rows"] and c not in found]
    return {**res, "rows": res["rows"][:50], "columns_found": found, "missing_columns": missing,
            "period": period.as_dict(), "tenant": scope.tenant}
