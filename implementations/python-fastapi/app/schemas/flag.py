"""Flag schemas."""

from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class FlagSubmit(BaseModel):
    """Schema for submitting a flag."""
    challenge_id: str
    flag: str


class FlagResponse(BaseModel):
    """Response after flag submission."""
    success: bool
    message: str
    points: Optional[int] = None


class ChallengeInfo(BaseModel):
    """Challenge information."""
    id: str
    name: str
    category: str
    difficulty: str
    points: int
    description: str
    hints: List[str]
    completed: bool = False


class ProgressResponse(BaseModel):
    """User progress response."""
    total_challenges: int
    completed: int
    total_points: int
    earned_points: int
    challenges: List[ChallengeInfo]
