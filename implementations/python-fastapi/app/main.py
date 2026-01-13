"""API Security Dojo - Main application entry point."""

import os
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
from app.seed import seed_database
from app.routers import auth, users, products, tools, admin, flags, docs
from app.graphql import create_graphql_router


def check_production_environment():
    """
    Check if running in a production-like environment and warn/block.

    This application is INTENTIONALLY VULNERABLE and should NEVER
    be deployed in production environments.
    """
    # Indicators that suggest production environment
    production_indicators = {
        "PRODUCTION": os.getenv("PRODUCTION"),
        "PROD": os.getenv("PROD"),
        "NODE_ENV=production": os.getenv("NODE_ENV") == "production",
        "ENVIRONMENT=production": os.getenv("ENVIRONMENT") == "production",
        "AWS_EXECUTION_ENV": os.getenv("AWS_EXECUTION_ENV"),
        "AWS_LAMBDA_FUNCTION_NAME": os.getenv("AWS_LAMBDA_FUNCTION_NAME"),
        "KUBERNETES_SERVICE_HOST": os.getenv("KUBERNETES_SERVICE_HOST"),
        "ECS_CONTAINER_METADATA_URI": os.getenv("ECS_CONTAINER_METADATA_URI"),
        "GOOGLE_CLOUD_PROJECT": os.getenv("GOOGLE_CLOUD_PROJECT"),
        "AZURE_FUNCTIONS_ENVIRONMENT": os.getenv("AZURE_FUNCTIONS_ENVIRONMENT"),
        "HEROKU_APP_NAME": os.getenv("HEROKU_APP_NAME"),
        "RAILWAY_ENVIRONMENT": os.getenv("RAILWAY_ENVIRONMENT"),
        "RENDER": os.getenv("RENDER"),
        "VERCEL": os.getenv("VERCEL"),
        "FLY_APP_NAME": os.getenv("FLY_APP_NAME"),
    }

    detected = {k: v for k, v in production_indicators.items() if v}

    if detected:
        warning_message = """
================================================================================
                    CRITICAL SECURITY WARNING
================================================================================

  API Security Dojo has detected a PRODUCTION-LIKE environment!

  Detected indicators:
"""
        for indicator, value in detected.items():
            warning_message += f"    - {indicator}: {value}\n"

        warning_message += """
  THIS APPLICATION IS INTENTIONALLY VULNERABLE!
  It contains security vulnerabilities by design for educational purposes.

  DO NOT DEPLOY IN PRODUCTION - You WILL be compromised!

  Vulnerabilities include:
    - SQL Injection (V06)
    - Command Injection (V07)
    - Broken Authentication (V02)
    - BOLA/IDOR (V01)
    - And many more...

================================================================================
"""
        print(warning_message, file=sys.stderr)

        # Block startup unless explicitly overridden
        if os.getenv("DOJO_FORCE_START") != "true":
            print(
                "  To override this safety check (NOT RECOMMENDED), set:\n"
                "    DOJO_FORCE_START=true\n",
                file=sys.stderr,
            )
            sys.exit(1)
        else:
            print(
                "  WARNING: DOJO_FORCE_START=true detected.\n"
                "  Proceeding despite production environment detection.\n"
                "  YOU HAVE BEEN WARNED!\n",
                file=sys.stderr,
            )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown events."""
    # Check for production environment before starting
    check_production_environment()

    # Startup
    await init_db()
    await seed_database()
    yield
    # Shutdown
    pass


app = FastAPI(
    title="API Security Dojo",
    description="""
    ## Deliberately Vulnerable API for Security Learning

    **WARNING**: This API contains intentional security vulnerabilities.
    Do NOT deploy in production.

    ### Vulnerabilities included:
    - OWASP API Security Top 10
    - SQL Injection
    - Command Injection
    - Broken Authentication
    - GraphQL-specific vulnerabilities (G01-G05)
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
app.include_router(docs.router, prefix="/api/docs", tags=["Documentation"])

# VULNERABILITY: Old API version still accessible (V09)
app.include_router(users.router_v1, prefix="/api/v1", tags=["Users (Legacy)"])

# GraphQL endpoint (Phase 2)
# VULNERABILITIES:
# - G01: Introspection enabled
# - G02: No query depth limits
# - G03: Batching allowed
# - G04: Field suggestions in errors
# - G05: Missing authorization on resolvers
graphql_router = create_graphql_router()
app.include_router(graphql_router, prefix="/graphql", tags=["GraphQL"])


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": "API Security Dojo",
        "version": "0.2.0",
        "mode": settings.mode,
        "message": "Welcome to API Security Dojo - A deliberately vulnerable API",
        "swagger_docs": "/docs",
        "endpoints": {
            "auth": "/api/login, /api/register",
            "users": "/api/users",
            "products": "/api/products",
            "tools": "/api/tools",
            "graphql": "/graphql/",
            "vulnerabilities": "/api/docs/vulnerabilities",
        },
        "mode_info": {
            "current": settings.mode,
            "challenge": "Limited info - find vulnerabilities yourself",
            "documentation": "Full details - exploitation steps and remediation",
            "switch": "Set DOJO_MODE=documentation to enable full docs",
        }
    }


@app.get("/health", tags=["Health"])
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "debug": settings.debug}
