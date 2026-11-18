# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import asyncio
import json
from collections.abc import Iterator
from contextlib import AbstractContextManager
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import httpx
import pytest
from fastapi.testclient import TestClient

from pyrit.backend.main import app
from pyrit.models import Message, MessagePiece
from pyrit.prompt_target import OpenAIResponseTarget, TextTarget
from pyrit.registry import TargetRegistry

MISSING_ID = UUID(int=404)


@pytest.fixture(autouse=True)
def registered_targets(patch_central_database: MagicMock) -> Iterator[None]:
    TargetRegistry.reset_registry_singleton()
    registry = TargetRegistry.get_registry_singleton()
    registry.instances.register(
        OpenAIResponseTarget(model_name="gpt-4", endpoint="https://example.invalid", api_key="not-a-key"),
        name="agent",
    )
    registry.instances.register(TextTarget(), name="text")
    yield
    TargetRegistry.reset_registry_singleton()


@pytest.fixture
def client(compatibility_headers: dict[str, str]) -> TestClient:
    return TestClient(app, headers=compatibility_headers)


def _model_replies(*replies: Message | Exception) -> AbstractContextManager[AsyncMock]:
    return patch.object(
        OpenAIResponseTarget, "_handle_openai_request_async", new_callable=AsyncMock, side_effect=replies
    )


def _tool_call(name: str) -> Message:
    return MessagePiece(
        role="assistant",
        original_value=json.dumps({"type": "function_call", "call_id": "call-1", "name": name, "arguments": "{}"}),
        original_value_data_type="function_call",
    ).to_message()


def _reply(text: str) -> Message:
    return Message.from_prompt(prompt=text, role="assistant")


def _create(client: TestClient, *, title: str = "Session", target: str = "agent") -> dict:
    response = client.post("/api/agent/sessions", json={"title": title, "target_registry_name": target})
    assert response.status_code == 201, response.text
    return response.json()


def _send(client: TestClient, session_id: str, text: str) -> dict:
    response = client.post(
        f"/api/agent/sessions/{session_id}/messages", json={"target_registry_name": "agent", "text": text}
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_first_send_saves_the_system_prompt_tool_calls_and_reply(client: TestClient) -> None:
    session = _create(client, title=" Which targets\n do I have? ")
    with _model_replies(_tool_call("list_targets"), _reply("You have two targets.")):
        body = _send(client, session["id"], "Which targets do I have?")

    messages = body["messages"]
    assert session["title"] == "Which targets do I have?"
    assert [message["role"] for message in messages] == ["system", "user", "assistant", "tool", "assistant"]
    assert messages[0]["message_pieces"][0]["converted_value"].startswith("You are the agent built into CoPyRIT")
    tool_result = json.loads(json.loads(messages[3]["message_pieces"][0]["converted_value"])["output"])
    assert {target["target_registry_name"] for target in tool_result["items"]} == {"agent", "text"}
    assert messages[4]["message_pieces"][0]["converted_value"] == "You have two targets."
    assert client.get("/api/agent/sessions").json()["items"] == [body["session"]]
    assert client.get("/api/attacks").json()["items"] == []


def test_send_continues_the_session_and_moves_it_to_the_top(client: TestClient) -> None:
    older, newer = _create(client), _create(client)
    with _model_replies(_reply("first"), _reply("second"), _reply("third")):
        _send(client, older["id"], "one")
        _send(client, newer["id"], "two")
        body = _send(client, older["id"], "again")

    turns = [(message["role"], message["message_pieces"][0]["converted_value"]) for message in body["messages"][1:]]
    assert turns == [("user", "one"), ("assistant", "first"), ("user", "again"), ("assistant", "third")]
    assert [session["id"] for session in client.get("/api/agent/sessions").json()["items"]] == [
        older["id"],
        newer["id"],
    ]
    assert client.get(f"/api/agent/sessions/{older['id']}/messages").json() == body


async def test_busy_session_rejects_another_send_while_other_sessions_answer(
    compatibility_headers: dict[str, str],
) -> None:
    answering, release = asyncio.Event(), asyncio.Event()
    calls = 0

    async def reply_async(**_: object) -> Message:
        nonlocal calls
        calls += 1
        reply = _reply(f"answer {calls}")
        if calls == 1:
            answering.set()
            await release.wait()
        return reply

    message = {"target_registry_name": "agent", "text": "hello"}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers=compatibility_headers) as client:
        busy, other = [
            (await client.post("/api/agent/sessions", json={"title": title, "target_registry_name": "agent"})).json()
            for title in ("busy", "other")
        ]
        with patch.object(
            OpenAIResponseTarget, "_handle_openai_request_async", new_callable=AsyncMock, side_effect=reply_async
        ):
            first = asyncio.create_task(client.post(f"/api/agent/sessions/{busy['id']}/messages", json=message))
            await answering.wait()
            second = await client.post(f"/api/agent/sessions/{busy['id']}/messages", json=message)
            elsewhere = await client.post(f"/api/agent/sessions/{other['id']}/messages", json=message)
            release.set()
            first_response = await first

    assert second.status_code == 409
    assert second.json()["detail"] == "The agent is still answering the previous message in this session."
    assert elsewhere.status_code == 200
    assert elsewhere.json()["messages"][-1]["message_pieces"][0]["converted_value"] == "answer 2"
    assert first_response.status_code == 200
    assert first_response.json()["messages"][-1]["message_pieces"][0]["converted_value"] == "answer 1"


def test_rename_changes_only_the_title(client: TestClient) -> None:
    session = _create(client, title="hello")

    response = client.patch(f"/api/agent/sessions/{session['id']}", json={"title": "  Jailbreak\n checks "})

    assert response.status_code == 200, response.text
    assert response.json() == {**session, "title": "Jailbreak checks"}
    assert client.get("/api/agent/sessions").json()["items"] == [response.json()]


@pytest.mark.parametrize("title", [" \n ", "x" * 101])
def test_blank_or_long_title_is_rejected(client: TestClient, title: str) -> None:
    session = _create(client)

    assert client.post("/api/agent/sessions", json={"title": title, "target_registry_name": "agent"}).status_code == 422
    assert client.patch(f"/api/agent/sessions/{session['id']}", json={"title": title}).status_code == 422


def test_failed_model_call_is_kept_in_the_conversation(client: TestClient) -> None:
    session = _create(client)
    with _model_replies(RuntimeError("model unavailable")):
        body = _send(client, session["id"], "hello")

    error = body["messages"][-1]["message_pieces"][0]
    assert error["response_error"] == "processing"
    assert "model unavailable" in error["converted_value"]


def test_target_that_cannot_run_tools_is_rejected_without_a_session(client: TestClient) -> None:
    response = client.post("/api/agent/sessions", json={"title": "hello", "target_registry_name": "text"})

    assert response.status_code == 400
    assert "OpenAIResponseTarget" in response.json()["detail"]
    assert client.get("/api/agent/sessions").json()["items"] == []


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("post", "/api/agent/sessions", {"title": "hello", "target_registry_name": "missing"}),
        ("post", f"/api/agent/sessions/{MISSING_ID}/messages", {"target_registry_name": "agent", "text": "hello"}),
        ("get", f"/api/agent/sessions/{MISSING_ID}/messages", None),
        ("patch", f"/api/agent/sessions/{MISSING_ID}", {"title": "hello"}),
    ],
)
def test_unknown_target_or_session_returns_404(client: TestClient, method: str, path: str, body: dict | None) -> None:
    assert client.request(method, path, json=body).status_code == 404
