# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Agent session routes."""

from collections.abc import Awaitable
from typing import TypeVar
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status

from pyrit.backend.models import ProblemDetail
from pyrit.backend.models.agent_sessions import (
    AgentMessageRequest,
    AgentSessionCreateRequest,
    AgentSessionListResponse,
    AgentSessionMessagesResponse,
    AgentSessionRenameRequest,
)
from pyrit.backend.rest_tools import RestToolset
from pyrit.backend.services.agent_session_service import AgentSessionService
from pyrit.backend.services.manual_send_scheduler import ManualSendConflictError, ManualSendQueueFullError
from pyrit.models import AgentSession

router = APIRouter(prefix="/agent/sessions", tags=["agent"])

_Result = TypeVar("_Result")

_TARGET_CANNOT_RUN_TOOLS: dict[int | str, dict[str, object]] = {
    400: {"model": ProblemDetail, "description": "The target cannot run agent tools"},
}
_SESSION_NOT_FOUND: dict[int | str, dict[str, object]] = {
    404: {"model": ProblemDetail, "description": "Session not found"},
}
_SEND_RESPONSES: dict[int | str, dict[str, object]] = {
    **_TARGET_CANNOT_RUN_TOOLS,
    404: {"model": ProblemDetail, "description": "Session or target not found"},
    409: {"model": ProblemDetail, "description": "The session is still answering another message"},
    429: {"model": ProblemDetail, "description": "Manual-message admission unavailable"},
}


@router.get("", response_model=AgentSessionListResponse)
async def list_agent_sessions_async(http_request: Request) -> AgentSessionListResponse:
    """
    List saved agent sessions.

    Returns:
        AgentSessionListResponse: Sessions, most recently used first.
    """
    return AgentSessionListResponse(items=await _service(http_request).list_sessions_async())


@router.post(
    "",
    response_model=AgentSession,
    status_code=status.HTTP_201_CREATED,
    responses={**_TARGET_CANNOT_RUN_TOOLS, 404: {"model": ProblemDetail, "description": "Target not found"}},
)
async def create_agent_session_async(*, request: AgentSessionCreateRequest, http_request: Request) -> AgentSession:
    """
    Create an empty session. Send its first message with POST /api/agent/sessions/{session_id}/messages.

    Returns:
        AgentSession: The new session.
    """
    return await _map_errors_async(_service(http_request).create_session_async(request=request))


@router.patch("/{session_id}", response_model=AgentSession, responses=_SESSION_NOT_FOUND)
async def rename_agent_session_async(
    *, session_id: UUID, request: AgentSessionRenameRequest, http_request: Request
) -> AgentSession:
    """
    Rename a session. Its place in the session list does not change.

    Returns:
        AgentSession: The renamed session.
    """
    return await _map_errors_async(_service(http_request).rename_session_async(session_id=session_id, request=request))


@router.get("/{session_id}/messages", response_model=AgentSessionMessagesResponse, responses=_SESSION_NOT_FOUND)
async def get_agent_session_messages_async(*, session_id: UUID, http_request: Request) -> AgentSessionMessagesResponse:
    """
    Read a session and its messages.

    Returns:
        AgentSessionMessagesResponse: The session and its messages.
    """
    return await _map_errors_async(_service(http_request).get_session_messages_async(session_id=session_id))


@router.post("/{session_id}/messages", response_model=AgentSessionMessagesResponse, responses=_SEND_RESPONSES)
async def send_agent_message_async(
    *, session_id: UUID, request: AgentMessageRequest, http_request: Request
) -> AgentSessionMessagesResponse:
    """
    Send a message and wait for the agent's reply, including any tool calls.

    A session answers one message at a time; other sessions are not affected.

    Returns:
        AgentSessionMessagesResponse: The session and its messages.
    """
    return await _map_errors_async(_service(http_request).send_message_async(session_id=session_id, request=request))


def _service(http_request: Request) -> AgentSessionService:
    # The agent's tool calls are REST requests to this app, made with the caller's credentials.
    return AgentSessionService(
        toolset=RestToolset(app=http_request.app), authorization=http_request.headers.get("authorization")
    )


async def _map_errors_async(operation: Awaitable[_Result]) -> _Result:
    try:
        return await operation
    except ManualSendConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The agent is still answering the previous message in this session.",
        ) from exc
    except ManualSendQueueFullError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
