"""Generic data endpoints over the query catalog.

  GET  /api/data/queries           the catalog (SPL visible to data-source editors)
  GET  /api/data/run/{id}          run one query for a period + tenant
  POST /api/data/run-batch         run several (one page load)
  POST /api/data/adhoc             run SPL you wrote (query console) — run_adhoc_queries
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .. import audit, periods
from ..connectors import splunk
from ..datasources import service
from ..deps import active_user, require_capability, user_capabilities
from ..models import User
from ..rbac import Capability
from .common import guard, period_param, resolve_period

router = APIRouter()
_viewer = require_capability(Capability.view_dashboards)
_BATCH_CONCURRENCY = 4


def query_out(q, with_spl: bool) -> dict:
    out = {"id": q.id, "name": q.name, "description": q.description, "category": q.category,
           "source": q.source, "columns": q.columns or [], "scope_mode": q.scope_mode,
           "scope_field": q.scope_field, "cache_seconds": q.cache_seconds, "builtin": q.builtin,
           "version": q.version, "updated_by": q.updated_by,
           "updated_at": q.updated_at.isoformat() if q.updated_at else None}
    if with_spl:
        out["spl"] = q.spl
    return out


@router.get("/queries")
async def queries(user: User = Depends(_viewer), category: str | None = None) -> list[dict]:
    editor = Capability.edit_data_sources in user_capabilities(user) or service.can_run_adhoc(user)
    return [query_out(q, editor) for q in await service.list_queries(category)]


@router.get("/run/{query_id}")
async def run(query_id: str, user: User = Depends(_viewer), p: periods.Period = Depends(period_param("d7")),
              tenant: str = Query("all"), max_rows: int = Query(service.MAX_ROWS, ge=1, le=service.MAX_ROWS)):
    return await guard(service.run_query(user, query_id, p, tenant, max_rows))


class BatchIn(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=40)
    period: str | None = None
    date_from: str | None = Field(None, alias="from")
    date_to: str | None = Field(None, alias="to")
    tenant: str = "all"


@router.post("/run-batch")
async def run_batch(body: BatchIn, user: User = Depends(_viewer)) -> dict:
    p = resolve_period(body.period, body.date_from, body.date_to)
    sem = asyncio.Semaphore(_BATCH_CONCURRENCY)

    async def one(qid: str):
        async with sem:
            try:
                return qid, await service.run_query(user, qid, p, body.tenant)
            except service.ScopeDenied as e:
                return qid, {"error": str(e), "status": 403}
            except service.QueryNotFound as e:
                return qid, {"error": str(e), "status": 404}
            except service.QueryError as e:
                return qid, {"error": str(e), "status": 422}
            except splunk.ConnectorError as e:
                return qid, {"error": str(e), "status": 503}

    results = dict(await asyncio.gather(*(one(q) for q in dict.fromkeys(body.ids))))
    return {"period": p.as_dict(), "tenant": body.tenant, "results": results}


class AdhocIn(BaseModel):
    spl: str = Field(min_length=1, max_length=20000)
    period: str | None = None
    date_from: str | None = Field(None, alias="from")
    date_to: str | None = Field(None, alias="to")
    tenant: str = "all"
    max_rows: int = Field(200, ge=1, le=1000)


@router.post("/adhoc")
async def adhoc(body: AdhocIn, user: User = Depends(active_user)) -> dict:
    if not service.can_run_adhoc(user):
        raise HTTPException(403, "ad-hoc queries need the run_adhoc_queries capability and an all-tenants account")
    p = resolve_period(body.period, body.date_from, body.date_to)
    await audit.record("data.adhoc_query", f"{p.key} · {body.tenant} · {body.spl[:400]}", user.username)
    return await guard(service.run_adhoc(user, body.spl, p, body.tenant, body.max_rows))
