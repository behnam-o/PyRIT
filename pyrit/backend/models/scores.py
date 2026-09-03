# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Score-related API request models."""

import uuid

from pydantic import BaseModel, Field


class ManualScoreRequest(BaseModel):
    """Request to attach a user-supplied score to a message piece."""

    message_id: uuid.UUID = Field(..., description="ID of the message piece to score")
    value: float = Field(..., ge=0, le=1, description="Score value between 0 and 1")
    rationale: str = Field(..., description="Explanation for the score")
