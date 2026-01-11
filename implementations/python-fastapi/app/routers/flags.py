"""Flags and challenges router."""

import json
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import User, Flag, FlagSubmission
from app.schemas import FlagSubmit, FlagResponse, ProgressResponse, ChallengeInfo
from app.vulnerabilities import get_current_user_required

router = APIRouter()

# Load challenges from specs
CHALLENGES_FILE = Path(__file__).parent.parent.parent.parent.parent / "specs" / "challenges.json"


def load_challenges() -> dict:
    """Load challenges from JSON file."""
    try:
        with open(CHALLENGES_FILE) as f:
            data = json.load(f)
            return {c["id"]: c for c in data.get("challenges", [])}
    except Exception:
        return {}


@router.get("/challenges")
async def list_challenges(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_required),
):
    """List all available challenges."""
    challenges = load_challenges()

    # Get user's completed challenges
    result = await db.execute(
        select(FlagSubmission)
        .where(FlagSubmission.user_id == current_user.id)
        .where(FlagSubmission.is_correct == 1)
    )
    completed = {sub.challenge_id for sub in result.scalars().all()}

    challenge_list = []
    for cid, challenge in challenges.items():
        challenge_list.append(ChallengeInfo(
            id=challenge["id"],
            name=challenge["name"],
            category=challenge["category"],
            difficulty=challenge["difficulty"],
            points=challenge["points"],
            description=challenge["description"],
            hints=challenge["hints"],
            completed=cid in completed,
        ))

    return challenge_list


@router.get("/challenges/progress", response_model=ProgressResponse)
async def get_progress(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_required),
):
    """Get user's challenge progress."""
    challenges = load_challenges()

    # Get user's completed challenges
    result = await db.execute(
        select(FlagSubmission)
        .where(FlagSubmission.user_id == current_user.id)
        .where(FlagSubmission.is_correct == 1)
    )
    completed_subs = result.scalars().all()
    completed_ids = {sub.challenge_id for sub in completed_subs}

    total_points = sum(c["points"] for c in challenges.values())
    earned_points = sum(
        challenges[cid]["points"]
        for cid in completed_ids
        if cid in challenges
    )

    challenge_list = []
    for cid, challenge in challenges.items():
        challenge_list.append(ChallengeInfo(
            id=challenge["id"],
            name=challenge["name"],
            category=challenge["category"],
            difficulty=challenge["difficulty"],
            points=challenge["points"],
            description=challenge["description"],
            hints=challenge["hints"],
            completed=cid in completed_ids,
        ))

    return ProgressResponse(
        total_challenges=len(challenges),
        completed=len(completed_ids),
        total_points=total_points,
        earned_points=earned_points,
        challenges=challenge_list,
    )


@router.post("/flags/submit", response_model=FlagResponse)
async def submit_flag(
    submission: FlagSubmit,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_required),
):
    """Submit a flag for a challenge."""
    challenges = load_challenges()

    if submission.challenge_id not in challenges:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Challenge not found"
        )

    challenge = challenges[submission.challenge_id]

    # Get the correct flag from database
    result = await db.execute(
        select(Flag).where(Flag.challenge_id == submission.challenge_id)
    )
    flag = result.scalar_one_or_none()

    if not flag:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Flag not configured for this challenge"
        )

    # Check if already completed
    result = await db.execute(
        select(FlagSubmission)
        .where(FlagSubmission.user_id == current_user.id)
        .where(FlagSubmission.challenge_id == submission.challenge_id)
        .where(FlagSubmission.is_correct == 1)
    )
    if result.scalar_one_or_none():
        return FlagResponse(
            success=True,
            message="You have already completed this challenge!",
            points=0,
        )

    # Check flag
    is_correct = submission.flag.strip() == flag.flag_value

    # Record submission
    flag_submission = FlagSubmission(
        user_id=current_user.id,
        challenge_id=submission.challenge_id,
        submitted_flag=submission.flag,
        is_correct=1 if is_correct else 0,
    )
    db.add(flag_submission)
    await db.commit()

    if is_correct:
        return FlagResponse(
            success=True,
            message=f"Congratulations! You solved {challenge['name']}!",
            points=challenge["points"],
        )
    else:
        return FlagResponse(
            success=False,
            message="Incorrect flag. Try again!",
            points=0,
        )


@router.get("/flags/hint/{challenge_id}")
async def get_hint(
    challenge_id: str,
    hint_index: int = 0,
    current_user: User = Depends(get_current_user_required),
):
    """Get a hint for a challenge."""
    challenges = load_challenges()

    if challenge_id not in challenges:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Challenge not found"
        )

    challenge = challenges[challenge_id]
    hints = challenge.get("hints", [])

    if hint_index < 0 or hint_index >= len(hints):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Hint index must be between 0 and {len(hints) - 1}"
        )

    return {
        "challenge_id": challenge_id,
        "hint_index": hint_index,
        "hint": hints[hint_index],
        "total_hints": len(hints),
    }
