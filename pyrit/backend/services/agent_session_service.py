# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Agent chats: conversations between a user and a target that can call this server's REST API as tools."""

import logging
from typing import ClassVar
from uuid import UUID

from pyrit.backend.mappers import pyrit_messages_to_dto_async
from pyrit.backend.models.agent_sessions import (
    AgentMessageRequest,
    AgentSessionCreateRequest,
    AgentSessionMessagesResponse,
    AgentSessionRenameRequest,
)
from pyrit.backend.rest_tools import RestToolset
from pyrit.backend.services.component_lifecycle import construct_component_async, release_component_async
from pyrit.backend.services.manual_send_scheduler import get_manual_send_scheduler
from pyrit.backend.services.target_service import get_target_service
from pyrit.memory import CentralMemory, MemoryInterface
from pyrit.models import AgentSession, Message
from pyrit.prompt_normalizer import PromptNormalizer
from pyrit.prompt_target import OpenAIResponseTarget, PromptTarget
from pyrit.registry import TargetRegistry

logger = logging.getLogger(__name__)


class AgentSessionService:
    """
    Run agent sessions.

    Each session is one memory conversation, which answers one message at a time; sessions are
    independent of each other. Every send copies the chosen registered target with the REST tools
    attached, so the target's own tool loop calls the REST API with the user's credentials and the
    prompt normalizer saves every message, including tool calls and results. Sessions are not attack
    results.
    """

    SYSTEM_PROMPT: ClassVar[str] = (
        "You are the agent built into CoPyRIT, the web app for PyRIT (Python Risk Identification Tool), an "
        "open-source framework for red teaming generative AI systems. You help authorized security professionals "
        "plan, run, and analyze red-teaming runs using the tools this PyRIT server provides.\n\n" + RestToolset.GUIDE
    )
    MAX_TOOL_ROUNDS: ClassVar[int] = 25

    def __init__(
        self,
        *,
        toolset: RestToolset,
        authorization: str | None = None,
        memory: MemoryInterface | None = None,
    ) -> None:
        """
        Bind to the REST tools, the caller's credentials, and memory.

        Args:
            toolset (RestToolset): The REST operations the agent can call.
            authorization (str | None): The caller's Authorization header, sent with every tool call.
                Defaults to None.
            memory (MemoryInterface | None): Where sessions are saved. Defaults to central memory.
        """
        self._toolset = toolset
        self._authorization = authorization
        self._memory = memory or CentralMemory.get_memory_instance()

    async def list_sessions_async(self) -> list[AgentSession]:
        """
        List saved sessions.

        Returns:
            list[AgentSession]: Sessions, most recently used first.
        """
        return await self._memory.get_agent_sessions_async()

    async def get_session_messages_async(self, *, session_id: UUID) -> AgentSessionMessagesResponse:
        """
        Read a session and its messages.

        Returns:
            AgentSessionMessagesResponse: The session and its messages.
        """
        return await self._session_messages_async(await self._require_session_async(session_id))

    async def create_session_async(self, *, request: AgentSessionCreateRequest) -> AgentSession:
        """
        Create an empty session that starts with a target that can run tools.

        Returns:
            AgentSession: The new session.
        """
        self._require_agent_source(target_registry_name=request.target_registry_name)
        return await self._memory.add_agent_session_async(
            AgentSession(title=request.title, target_registry_name=request.target_registry_name)
        )

    async def rename_session_async(self, *, session_id: UUID, request: AgentSessionRenameRequest) -> AgentSession:
        """
        Change a session's title.

        Returns:
            AgentSession: The renamed session.
        """
        return await self._memory.rename_agent_session_async(session_id=session_id, title=request.title)

    async def send_message_async(
        self, *, session_id: UUID, request: AgentMessageRequest
    ) -> AgentSessionMessagesResponse:
        """
        Send a message and wait for the reply, optionally switching the session's target.

        Returns:
            AgentSessionMessagesResponse: The session and its messages.

        Raises:
            ManualSendConflictError: If the session is still answering another message.
        """
        session = await self._require_session_async(session_id)
        # Concurrent sends would interleave their tool loops in one conversation.
        with get_manual_send_scheduler().reserve(conversation_id=session.conversation_id):
            agent = await self._create_agent_async(target_registry_name=request.target_registry_name)
            try:
                return await self._send_async(agent=agent, session=session, request=request)
            finally:
                await release_component_async(agent)

    async def _send_async(
        self, *, agent: PromptTarget, session: AgentSession, request: AgentMessageRequest
    ) -> AgentSessionMessagesResponse:
        if not await self._memory.get_conversation_messages_async(conversation_id=session.conversation_id):
            await agent.set_system_prompt_async(
                system_prompt=self.SYSTEM_PROMPT, conversation_id=session.conversation_id
            )
        try:
            await PromptNormalizer().send_prompt_async(
                message=Message.from_prompt(prompt=request.text, role="user"),
                target=agent,
                conversation_id=session.conversation_id,
            )
        except Exception:
            # The normalizer saved an error response, which the chat shows in place of a reply.
            logger.exception("Agent send failed in session %s", session.id)
        session = await self._memory.touch_agent_session_async(
            session_id=session.id, target_registry_name=request.target_registry_name
        )
        return await self._session_messages_async(session)

    async def _create_agent_async(self, *, target_registry_name: str) -> PromptTarget:
        return await construct_component_async(
            TargetRegistry.get_registry_singleton().recreate_instance,
            source=self._require_agent_source(target_registry_name=target_registry_name),
            params={
                "tools": self._toolset.create_tools(authorization=self._authorization),
                "max_tool_rounds": self.MAX_TOOL_ROUNDS,
            },
        )

    async def _require_session_async(self, session_id: UUID) -> AgentSession:
        sessions = await self._memory.get_agent_sessions_async(session_ids=[session_id])
        if not sessions:
            raise LookupError(f"Agent session {session_id} not found")
        return sessions[0]

    async def _session_messages_async(self, session: AgentSession) -> AgentSessionMessagesResponse:
        messages = await self._memory.get_conversation_messages_async(conversation_id=session.conversation_id)
        return AgentSessionMessagesResponse(
            session=session, messages=await pyrit_messages_to_dto_async(list(messages), memory=self._memory)
        )

    @staticmethod
    def _require_agent_source(*, target_registry_name: str) -> OpenAIResponseTarget:
        source = get_target_service().get_target_object(target_registry_name=target_registry_name)
        if source is None:
            raise LookupError(f"Target '{target_registry_name}' not found")
        if not isinstance(source, OpenAIResponseTarget):
            raise ValueError(
                f"The agent needs an OpenAIResponseTarget, which can run tools; "
                f"'{target_registry_name}' is a {type(source).__name__}."
            )
        return source
