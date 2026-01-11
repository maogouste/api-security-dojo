"""Authentication router."""

from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import User
from app.schemas import UserCreate, UserResponse, Token
from app.vulnerabilities import (
    verify_password,
    get_password_hash,
    create_access_token,
    get_current_user_required,
)
from app.config import settings

router = APIRouter()


@router.post("/register", response_model=UserResponse)
async def register(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user.

    VULNERABILITIES:
    - No password strength validation
    - No email verification
    - Returns full user object with sensitive data
    """
    # Check if username exists
    result = await db.execute(select(User).where(User.username == user_data.username))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    # Check if email exists
    result = await db.execute(select(User).where(User.email == user_data.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # VULNERABILITY: No password strength validation
    hashed_password = get_password_hash(user_data.password)

    user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=hashed_password,
        role="user",
    )

    db.add(user)
    await db.commit()
    await db.refresh(user)

    # VULNERABILITY: Returns full user object
    return user


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """
    Login and get access token.

    VULNERABILITIES:
    - V04: No rate limiting
    - V02: Weak JWT implementation
    - Detailed error messages (user enumeration)
    """
    # VULNERABILITY: Different error messages allow user enumeration
    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalar_one_or_none()

    if not user:
        # VULNERABILITY: Reveals that username doesn't exist
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(form_data.password, user.password_hash):
        # VULNERABILITY: Reveals that password is wrong
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
        )

    access_token = create_access_token(
        data={
            "sub": user.username,
            "user_id": user.id,
            "role": user.role,  # VULNERABILITY: Role in token can be modified
        },
        expires_delta=timedelta(minutes=settings.jwt_expiration_minutes)
    )

    # VULNERABILITY: Returning sensitive info
    return Token(
        access_token=access_token,
        token_type="bearer",
        user_id=user.id,
        role=user.role,
    )


@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: User = Depends(get_current_user_required)
):
    """
    Get current user profile.

    VULNERABILITY V03: Returns excessive data (ssn, credit_card, etc.)
    """
    return current_user


@router.post("/token/refresh", response_model=Token)
async def refresh_token(
    current_user: User = Depends(get_current_user_required)
):
    """
    Refresh access token.

    VULNERABILITY: No refresh token rotation
    """
    access_token = create_access_token(
        data={
            "sub": current_user.username,
            "user_id": current_user.id,
            "role": current_user.role,
        },
        expires_delta=timedelta(minutes=settings.jwt_expiration_minutes)
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        user_id=current_user.id,
        role=current_user.role,
    )
