# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import json
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException, Request

from pyrit import _compatibility
from pyrit.backend.main import app as backend_app
from pyrit.backend.rest_tools import RestToolset
from pyrit.prompt_target import OpenAIResponseTarget
from pyrit.registry import TargetRegistry

COMPATIBILITY_ID = "0.0.0+g" + "a" * 40


@pytest.fixture
def toolset() -> Iterator[RestToolset]:
    app = FastAPI()
    app.state.compatibility_id = COMPATIBILITY_ID

    @app.get("/api/things/{thing_id}")
    async def get_thing_async(thing_id: str, request: Request) -> dict[str, object]:
        """Get one thing."""
        if thing_id == "missing":
            raise HTTPException(status_code=404, detail="Thing 'missing' not found")
        return {
            "id": thing_id,
            "authorization": request.headers.get("authorization"),
            "compatibility_id": request.headers.get(_compatibility.COMPATIBILITY_HEADER),
            "identifier": {"class_name": "Thing", "hash": "abc", "model_name": "m", "children": {"x": {}}},
            "note": None,
        }

    @app.get("/api/things")
    async def list_things(limit: int = 50) -> dict[str, object]:
        """List things."""
        return {
            "items": [{"name": f"thing-{index}", "text": "x" * 50} for index in range(limit)],
            "pagination": {"has_more": True},
        }

    with patch.object(RestToolset, "OPERATIONS", ("get_thing", "list_things")):
        yield RestToolset(app=app)


def test_tools_are_rest_operations_named_after_their_route_functions(toolset: RestToolset) -> None:
    tools = {tool.name: tool for tool in toolset.create_tools(authorization=None)}

    assert list(tools) == ["get_thing", "list_things"]
    assert tools["get_thing"].description.startswith("GET /api/things/{thing_id}\n\nGet one thing.")
    assert tools["get_thing"].parameters["required"] == ["thing_id"]
    assert set(tools["list_things"].parameters["properties"]) == {"limit", RestToolset.RESPONSE_FIELDS}


async def test_call_forwards_credentials_and_compacts_identifiers(toolset: RestToolset) -> None:
    text, failed = await toolset.call_async(name="get_thing", arguments={"thing_id": "a?b"}, authorization="Bearer t")

    assert failed is False
    assert json.loads(text) == {
        "id": "a?b",
        "authorization": "Bearer t",
        "compatibility_id": COMPATIBILITY_ID,
        "identifier": {"class_name": "Thing", "model_name": "m"},
    }


async def test_error_response_is_returned_whole_as_a_failed_result(toolset: RestToolset) -> None:
    text, failed = await toolset.call_async(
        name="get_thing", arguments={"thing_id": "missing", RestToolset.RESPONSE_FIELDS: ["id"]}, authorization=None
    )

    assert failed is True
    assert json.loads(text) == {"status": 404, "error": {"detail": "Thing 'missing' not found"}}


async def test_large_list_keeps_leading_items_and_pagination(toolset: RestToolset) -> None:
    with patch.object(RestToolset, "MAX_RESPONSE_CHARS", 1_000):
        text, _ = await toolset.call_async(name="list_things", arguments={"limit": 100}, authorization=None)

    result = json.loads(text)
    assert len(text) <= 1_000
    assert result["pagination"] == {"has_more": True}
    assert result["items"][0]["name"] == "thing-0"
    assert result["items_omitted"] == 100 - len(result["items"])


async def test_response_fields_keep_matches_and_name_alternatives_for_misses(toolset: RestToolset) -> None:
    text, _ = await toolset.call_async(
        name="list_things",
        arguments={"limit": 2, RestToolset.RESPONSE_FIELDS: ["items.name", "items.title"]},
        authorization=None,
    )

    assert json.loads(text) == {
        "items": [{"name": "thing-0"}, {"name": "thing-1"}],
        "unmatched_response_fields": {"items.title": {"available_fields": ["name", "text"]}},
    }


def test_missing_offered_operation_is_reported(toolset: RestToolset) -> None:
    with (
        patch.object(RestToolset, "OPERATIONS", ("get_thing", "no_such_route")),
        pytest.raises(ValueError, match="no_such_route"),
    ):
        toolset.create_tools(authorization=None)


async def test_backend_operations_resolve_and_call_the_real_api(patch_central_database: MagicMock) -> None:
    TargetRegistry.reset_registry_singleton()
    TargetRegistry.get_registry_singleton().instances.register(
        OpenAIResponseTarget(model_name="gpt-4", endpoint="https://example.invalid", api_key="not-a-key"), name="agent"
    )
    try:
        toolset = RestToolset(app=backend_app)
        assert [operation.name for operation in toolset.operations] == list(RestToolset.OPERATIONS)
        text, failed = await toolset.call_async(name="list_targets", arguments={}, authorization=None)
    finally:
        TargetRegistry.reset_registry_singleton()

    assert failed is False
    (target,) = json.loads(text)["items"]
    assert target["target_registry_name"] == "agent"
    assert target["identifier"] == {
        "class_name": "OpenAIResponseTarget",
        "endpoint": "https://example.invalid",
        "model_name": "gpt-4",
    }
