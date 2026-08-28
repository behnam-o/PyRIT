# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Tests for the backend MCP adapter."""

from fastmcp import Client

from pyrit.backend.main import app, mcp_server
from pyrit.backend.mcp_server import MCP_MOUNT_PATH


async def test_mcp_tools_match_rest_operations() -> None:
    """Verify every REST operation is exposed as an MCP tool."""
    operation_ids = {
        operation["operationId"]
        for path_item in app.openapi()["paths"].values()
        for operation in path_item.values()
        if isinstance(operation, dict) and "operationId" in operation
    }

    tools = await mcp_server.get_tools()

    assert len(tools) == len(operation_ids)
    assert "attack_result_id" in tools["get_attack_api_attacks"].parameters["required"]


def test_mcp_transport_is_mounted() -> None:
    """Verify the MCP Streamable HTTP transport is mounted on the backend app."""
    assert any(
        getattr(route, "path", None) == MCP_MOUNT_PATH and getattr(route, "name", None) == "mcp" for route in app.routes
    )


async def test_mcp_tool_calls_existing_rest_handler() -> None:
    """Verify an MCP tool delegates to its unchanged REST operation."""
    async with Client(mcp_server) as client:
        result = await client.call_tool("health_check_async_api_health_get")

    assert result.data["status"] == "healthy"
    assert result.data["service"] == "pyrit-backend"
