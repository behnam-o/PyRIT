# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""MCP adapter for the PyRIT FastAPI application."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.types import Receive, Scope, Send

MCP_MOUNT_PATH = "/mcp"


class _ReloadableMCPApp:
    """Create a fresh single-use FastMCP transport for each backend lifespan."""

    def __init__(self, server: FastMCP) -> None:
        self._server = server
        self._app = self._create_app()

    def _create_app(self) -> Starlette:
        return self._server.http_app(path="/", stateless_http=True)

    @asynccontextmanager
    async def lifespan(self) -> AsyncGenerator[None, None]:
        """Run a fresh MCP transport lifespan."""
        self._app = self._create_app()
        async with self._app.lifespan(self._app):
            yield

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Delegate ASGI requests to the current transport app."""
        await self._app(scope, receive, send)


def mount_mcp_server(app: FastAPI) -> tuple[FastMCP, _ReloadableMCPApp]:
    """
    Create and mount an MCP server from the app's existing OpenAPI schema.

    Returns:
        tuple[FastMCP, _ReloadableMCPApp]: The MCP server and its mounted ASGI adapter.
    """
    server = FastMCP.from_fastapi(app=app, name="PyRIT MCP")
    mcp_app = _ReloadableMCPApp(server)
    app.mount(MCP_MOUNT_PATH, mcp_app, name="mcp")
    return server, mcp_app
