"""Thin execution bridge to the splunk-soar-mcp server.

The core's authorization proxy is the security boundary — it authenticates the
portal user, decides which tools their role may use and forces tenant scope.
This bridge only *executes* an already-authorized call against the MCP server,
and is bound to a private interface. It exposes the MCP tool catalogue (names +
schemas) and a /call passthrough. It never makes an authorization decision.
"""
from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from pydantic import BaseModel

MCP_URL = os.environ.get("SOAR_MCP_HTTP_URL", "http://127.0.0.1:9010/mcp")
app = FastAPI(title="mcp-soar-chat bridge", version="0.1.0")


async def _session():
    streams = await streamable_http_client(MCP_URL).__aenter__()
    return streams


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "mcp_url": MCP_URL}


@app.get("/tools")
async def tools() -> dict:
    async with streamable_http_client(MCP_URL) as streams:
        async with ClientSession(streams[0], streams[1]) as s:
            await s.initialize()
            out = []
            for t in (await s.list_tools()).tools:
                out.append({"name": t.name, "description": (t.description or "").strip(),
                            "input_schema": t.input_schema or {"type": "object", "properties": {}}})
            return {"tools": out}


class CallIn(BaseModel):
    name: str
    arguments: dict = {}


@app.post("/call")
async def call(body: CallIn) -> dict:
    try:
        async with streamable_http_client(MCP_URL) as streams:
            async with ClientSession(streams[0], streams[1]) as s:
                await s.initialize()
                res = await s.call_tool(body.name, body.arguments or {})
                text = "\n".join(c.text for c in res.content if getattr(c, "text", None))
                return {"ok": not res.is_error, "is_error": bool(res.is_error), "text": text}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"mcp call failed: {e}")
