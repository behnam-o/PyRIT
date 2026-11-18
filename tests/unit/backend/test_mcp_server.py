# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
from collections.abc import AsyncGenerator, Iterator
from contextlib import asynccontextmanager
from unittest.mock import patch

import httpx2
import pytest
from fastapi import FastAPI, Request
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client
from starlette.applications import Starlette
from starlette.routing import Route

from pyrit.backend.mcp_server import MCPEndpoint
from pyrit.backend.rest_tools import RestToolset

BASE_URL = "http://testserver"


@pytest.fixture
def endpoint() -> Iterator[MCPEndpoint]:
    app = FastAPI()
    app.state.compatibility_id = "0.0.0+g" + "a" * 40

    @app.get("/api/whoami")
    async def whoami_async(request: Request) -> dict[str, str | None]:
        """Report the caller's credentials."""
        return {"authorization": request.headers.get("authorization")}

    with patch.object(RestToolset, "OPERATIONS", ("whoami",)):
        yield MCPEndpoint(toolset=RestToolset(app=app))


def _app(endpoint: MCPEndpoint) -> Starlette:
    return Starlette(routes=[Route(MCPEndpoint.PATH, endpoint=endpoint)])


@asynccontextmanager
async def _session_async(
    endpoint: MCPEndpoint, *, headers: dict[str, str] | None = None
) -> AsyncGenerator[ClientSession, None]:
    async with (
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=_app(endpoint)), base_url=BASE_URL, headers=headers
        ) as http_client,
        streamable_http_client(f"{BASE_URL}{MCPEndpoint.PATH}", http_client=http_client) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        yield session


async def test_mcp_tools_are_rest_operations_called_with_the_callers_credentials(endpoint: MCPEndpoint) -> None:
    async with endpoint.run_async(), _session_async(endpoint, headers={"Authorization": "Bearer t"}) as session:
        tools = await session.list_tools()
        result = await session.call_tool(name="whoami", arguments={})

    assert [tool.name for tool in tools.tools] == ["whoami"]
    assert result.is_error is False
    (content,) = result.content
    assert isinstance(content, types.TextContent)
    assert json.loads(content.text) == {"authorization": "Bearer t"}


async def test_mcp_endpoint_serves_only_while_an_app_lifespan_runs(endpoint: MCPEndpoint) -> None:
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=_app(endpoint)), base_url=BASE_URL) as client:
        assert (await client.post(MCPEndpoint.PATH, json={})).status_code == 503
        for _ in range(2):
            async with endpoint.run_async(), _session_async(endpoint) as session:
                assert [tool.name for tool in (await session.list_tools()).tools] == ["whoami"]
        assert (await client.post(MCPEndpoint.PATH, json={})).status_code == 503
