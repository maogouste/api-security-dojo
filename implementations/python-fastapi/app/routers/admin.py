"""Admin router."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List

from app.database import get_db
from app.models import User, Product, Order
from app.vulnerabilities import get_admin_user

router = APIRouter()


@router.get("/admin/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_admin_user),
):
    """Get application statistics (admin only)."""
    user_count = await db.execute(select(func.count(User.id)))
    product_count = await db.execute(select(func.count(Product.id)))
    order_count = await db.execute(select(func.count(Order.id)))

    return {
        "users": user_count.scalar(),
        "products": product_count.scalar(),
        "orders": order_count.scalar(),
    }


@router.get("/admin/users", response_model=List[dict])
async def admin_list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_admin_user),
):
    """List all users with full details (admin only)."""
    result = await db.execute(select(User))
    users = result.scalars().all()

    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "is_active": u.is_active,
            "ssn": u.ssn,
            "credit_card": u.credit_card,
            "api_key": u.api_key,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        }
        for u in users
    ]


@router.post("/admin/users/{user_id}/role")
async def change_user_role(
    user_id: int,
    role: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_admin_user),
):
    """Change user role (admin only)."""
    if role not in ["user", "admin", "superadmin"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role"
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user.role = role
    await db.commit()

    return {"message": f"User {user.username} role changed to {role}"}


@router.post("/admin/users/{user_id}/toggle-active")
async def toggle_user_active(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_admin_user),
):
    """Toggle user active status (admin only)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user.is_active = not user.is_active
    await db.commit()

    return {
        "message": f"User {user.username} is now {'active' if user.is_active else 'inactive'}",
        "is_active": user.is_active
    }
