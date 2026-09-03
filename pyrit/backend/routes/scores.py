# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Score API routes."""

import asyncio

from fastapi import APIRouter, HTTPException, status

from pyrit.backend.models.attacks import ScoreView
from pyrit.backend.models.common import ProblemDetail
from pyrit.backend.models.scores import ManualScoreRequest
from pyrit.memory import CentralMemory
from pyrit.models import MessageScorable
from pyrit.score import ManualScorer

router = APIRouter(prefix="/scores", tags=["scores"])


@router.post(
    "/manual",
    response_model=ScoreView,
    status_code=status.HTTP_201_CREATED,
    responses={
        404: {"model": ProblemDetail, "description": "Message not found"},
        422: {"model": ProblemDetail, "description": "Validation error"},
    },
)
async def create_manual_score(request: ManualScoreRequest) -> ScoreView:  # pyrit-async-suffix-exempt
    """
    Create and persist a manual score for a message piece.

    Returns:
        ScoreView: The persisted manual score.
    """
    memory = CentralMemory.get_memory_instance()
    pieces = await asyncio.to_thread(memory.get_message_pieces, prompt_ids=[request.message_id])
    if not any(str(piece.id) == str(request.message_id) for piece in pieces):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Message '{request.message_id}' not found",
        )

    scorer = ManualScorer(value=request.value, rationale=request.rationale)
    scores = await scorer.score_async(
        scorable=MessageScorable(message_piece_ids=(request.message_id,)),
    )
    return ScoreView.from_domain(scores[0])
