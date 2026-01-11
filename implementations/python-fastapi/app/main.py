"""VulnAPI - Main application entry point."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
from app.seed import seed_database
from app.routers import auth, users, products, tools, admin, flags


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown events."""
    # Startup
    await init_db()
    await seed_database()
    yield
    # Shutdown
    pass


app = FastAPI(
    title="VulnAPI",
    description="""
    ## Deliberately Vulnerable API for Security Learning

    **WARNING**: This API contains intentional security vulnerabilities.
    Do NOT deploy in production.

    ### Vulnerabilities included:
    - OWASP API Security Top 10
    - SQL Injection
    - Command Injection
    - Broken Authentication
    - And more...

    ### Mode: """ + settings.mode,
    version="0.1.0",
    lifespan=lifespan,
)

# VULNERABILITY: CORS misconfiguration - allows all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # VULNERABLE: Should be specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api", tags=["Authentication"])
app.include_router(users.router, prefix="/api", tags=["Users"])
app.include_router(products.router, prefix="/api", tags=["Products"])
app.include_router(tools.router, prefix="/api", tags=["Tools"])
app.include_router(admin.router, prefix="/api", tags=["Admin"])
app.include_router(flags.router, prefix="/api", tags=["Flags"])

# VULNERABILITY: Old API version still accessible (V09)
app.include_router(users.router_v1, prefix="/api/v1", tags=["Users (Legacy)"])


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": "VulnAPI",
        "version": "0.1.0",
        "mode": settings.mode,
        "message": "Welcome to VulnAPI - A deliberately vulnerable API",
        "documentation": "/docs",
        "endpoints": {
            "auth": "/api/login, /api/register",
            "users": "/api/users",
            "products": "/api/products",
            "tools": "/api/tools",
        }
    }


@app.get("/health", tags=["Health"])
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "debug": settings.debug}
