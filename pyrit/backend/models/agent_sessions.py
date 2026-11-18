# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Requests and responses for agent sessions."""

from pydantic import BaseModel, ConfigDict, Field

from pyrit.backend.models.attacks import MessageView
from pyrit.backend.models.common import IdentifierStr, TextStr
from pyrit.models import AgentSession
from pyrit.models.agent_session import AgentSessionTitle


class AgentSessionCreateRequest(BaseModel):
    """A new, empty session and the registered target it starts with."""

    model_config = ConfigDict(extra="forbid")

    title: AgentSessionTitle
    target_registry_name: IdentifierStr = Field(..., min_length=1)


class AgentSessionRenameRequest(BaseModel):
    """A session's new title."""

    model_config = ConfigDict(extra="forbid")

    title: AgentSessionTitle


class AgentMessageRequest(BaseModel):
    """A user message for the agent and the registered target that should answer it."""

    model_config = ConfigDict(extra="forbid")

    target_registry_name: IdentifierStr = Field(..., min_length=1)
    text: TextStr = Field(..., min_length=1)


class AgentSessionListResponse(BaseModel):
    """Saved sessions, most recently used first."""

    items: list[AgentSession]


class AgentSessionMessagesResponse(BaseModel):
    """A session and every message in its conversation, including tool calls and their results."""

    session: AgentSession
    messages: list[MessageView]
