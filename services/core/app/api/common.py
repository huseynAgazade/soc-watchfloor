"""Shared request helpers for data endpoints: period parameters and mapping query
errors onto HTTP status codes."""
from __future__ import annotations

from fastapi import HTTPException, Query

from .. import periods
from ..connectors import splunk
from ..datasources import service


def resolve_period(period: str | None, date_from: str | None = None, date_to: str | None = None,
                   window: str | None = None, default: str = "d7") -> periods.Period:
    try:
        return periods.resolve(period, date_from, date_to, window, default=default)
    except periods.PeriodError as e:
        raise HTTPException(422, str(e))


def period_param(default: str):
    """Dependency resolving period / from / to (or the older window) — 422 when invalid."""
    def _dep(period: str | None = Query(None), date_from: str | None = Query(None, alias="from"),
             date_to: str | None = Query(None, alias="to"), window: str | None = Query(None)) -> periods.Period:
        return resolve_period(period, date_from, date_to, window, default)
    return _dep


async def guard(awaitable):
    try:
        return await awaitable
    except service.ScopeDenied as e:
        raise HTTPException(403, str(e))
    except service.QueryNotFound as e:
        raise HTTPException(404, str(e))
    except service.QueryError as e:
        raise HTTPException(422, str(e))
    except splunk.ConnectorError as e:
        raise HTTPException(503, str(e))
