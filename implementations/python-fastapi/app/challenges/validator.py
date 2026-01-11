"""Flag validation utilities."""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import Flag


async def get_flag_for_challenge(db: AsyncSession, challenge_id: str) -> str | None:
    """Get the correct flag value for a challenge."""
    result = await db.execute(
        select(Flag).where(Flag.challenge_id == challenge_id)
    )
    flag = result.scalar_one_or_none()
    return flag.flag_value if flag else None


async def validate_flag(db: AsyncSession, challenge_id: str, submitted_flag: str) -> bool:
    """Validate a submitted flag against the correct value."""
    correct_flag = await get_flag_for_challenge(db, challenge_id)
    if not correct_flag:
        return False
    return submitted_flag.strip() == correct_flag
