# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from datetime import UTC, datetime
from typing import Annotated, ClassVar
from uuid import UUID, uuid4

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field

from pyrit.models.request_limits import MAX_IDENTIFIER_LENGTH


def _normalize_agent_session_title(value: str) -> str:
    """
    Collapse whitespace, including line breaks, into single spaces and enforce the length limit.

    Returns:
        str: The one-line title.

    Raises:
        ValueError: If the title is blank or longer than ``AgentSession.MAX_TITLE_LENGTH`` characters.
    """
    title = " ".join(value.split())
    if not title:
        raise ValueError("Must not be blank.")
    if len(title) > AgentSession.MAX_TITLE_LENGTH:
        raise ValueError(f"Must be at most {AgentSession.MAX_TITLE_LENGTH} characters.")
    return title


AgentSessionTitle = Annotated[str, AfterValidator(_normalize_agent_session_title)]


class AgentSession(BaseModel):
    """A saved agent chat. Its messages are the memory conversation whose ID is the session ID."""

    model_config = ConfigDict(extra="forbid")

    MAX_TITLE_LENGTH: ClassVar[int] = 100

    id: UUID = Field(default_factory=uuid4)
    title: AgentSessionTitle
    target_registry_name: str = Field(min_length=1, max_length=MAX_IDENTIFIER_LENGTH)
    created_at: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def conversation_id(self) -> str:
        """The memory conversation that holds the session's messages."""
        return str(self.id)
