"""Users router with BOLA and Mass Assignment vulnerabilities."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from app.database import get_db
from app.models import User
from app.schemas import UserResponse, UserResponseLegacy, UserUpdate
from app.vulnerabilities import (
    get_current_user,
    get_current_user_required,
    get_password_hash,
)

router = APIRouter()
router_v1 = APIRouter()  # Legacy API version


@router.get("/users", response_model=List[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List all users.

    VULNERABILITY V03: Returns all users with sensitive data
    VULNERABILITY: No pagination (DoS potential)
    """
    result = await db.execute(select(User))
    users = result.scalars().all()
    return users


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get user by ID.

    VULNERABILITY V01 (BOLA): No authorization check!
    Any authenticated user can access any other user's data.

    Exploit: GET /api/users/1 (access admin data)
    """
    # VULNERABILITY: No check if current_user.id == user_id
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Flag for V01 challenge - accessing other user's data
    if current_user and current_user.id != user_id:
        # User successfully exploited BOLA
        pass

    return user


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_required),
):
    """
    Update user.

    VULNERABILITY V01 (BOLA): Can update any user
    VULNERABILITY V05 (Mass Assignment): Can update role, is_active, etc.

    Exploit: PUT /api/users/1 with {"role": "admin"}
    """
    # VULNERABILITY V01: No authorization check
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # VULNERABILITY V05: Mass assignment - all fields from request are applied
    update_data = user_update.model_dump(exclude_unset=True)

    # Process password separately
    if "password" in update_data:
        update_data["password_hash"] = get_password_hash(update_data.pop("password"))

    # VULNERABLE: Directly applying all fields including role, is_active
    for field, value in update_data.items():
        if hasattr(user, field):
            setattr(user, field, value)

    await db.commit()
    await db.refresh(user)

    return user


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_required),
):
    """
    Delete user.

    VULNERABILITY V01: No authorization check
    VULNERABILITY V10: No logging of deletion
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # VULNERABILITY: No logging, no audit trail
    await db.delete(user)
    await db.commit()

    return {"message": "User deleted", "user_id": user_id}


# ==================== LEGACY API v1 (V09) ====================

@router_v1.get("/users", response_model=List[UserResponseLegacy])
async def list_users_v1(
    db: AsyncSession = Depends(get_db),
):
    """
    Legacy API: List all users.

    VULNERABILITY V09: Old API version with even more data exposure
    - No authentication required
    - Exposes password_hash!
    """
    result = await db.execute(select(User))
    users = result.scalars().all()
    return users


@router_v1.get("/users/{user_id}", response_model=UserResponseLegacy)
async def get_user_v1(
    user_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Legacy API: Get user by ID.

    VULNERABILITY V09: Exposes password hash and all sensitive data
    No authentication required!
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return user
