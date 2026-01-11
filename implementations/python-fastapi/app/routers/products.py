"""Products router with SQL Injection vulnerability."""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from app.database import get_db
from app.models import Product
from app.schemas import ProductResponse, ProductCreate, ProductUpdate
from app.vulnerabilities import get_current_user, get_admin_user, search_products_vulnerable

router = APIRouter()


@router.get("/products", response_model=List[ProductResponse])
async def list_products(
    search: Optional[str] = Query(None, description="Search term"),
    db: AsyncSession = Depends(get_db),
):
    """
    List products with optional search.

    VULNERABILITY V06 (SQL Injection): Search parameter is not sanitized

    Exploit examples:
    - /api/products?search=' OR '1'='1
    - /api/products?search=' UNION SELECT * FROM users--
    """
    if search:
        # VULNERABILITY: Using vulnerable search function
        products = await search_products_vulnerable(db, search)
        return products

    # Normal query when no search
    result = await db.execute(select(Product).where(Product.is_active == True))
    products = result.scalars().all()
    return products


@router.get("/products/{product_id}", response_model=ProductResponse)
async def get_product(
    product_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Get product by ID.

    VULNERABILITY V03: Exposes internal_notes and supplier_cost
    """
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()

    if not product:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Product not found"
        )

    return product


@router.post("/products", response_model=ProductResponse)
async def create_product(
    product_data: ProductCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_admin_user),
):
    """Create a new product (admin only)."""
    product = Product(**product_data.model_dump())
    db.add(product)
    await db.commit()
    await db.refresh(product)
    return product


@router.put("/products/{product_id}", response_model=ProductResponse)
async def update_product(
    product_id: int,
    product_update: ProductUpdate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_admin_user),
):
    """Update a product (admin only)."""
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()

    if not product:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Product not found"
        )

    update_data = product_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(product, field, value)

    await db.commit()
    await db.refresh(product)
    return product


@router.delete("/products/{product_id}")
async def delete_product(
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_admin_user),
):
    """Delete a product (admin only)."""
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()

    if not product:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Product not found"
        )

    await db.delete(product)
    await db.commit()

    return {"message": "Product deleted", "product_id": product_id}
