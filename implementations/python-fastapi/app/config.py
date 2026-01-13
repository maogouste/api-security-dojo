"""Application configuration."""

from pydantic_settings import BaseSettings
from typing import Literal


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application mode
    mode: Literal["challenge", "documentation"] = "challenge"

    # Database
    db_url: str = "sqlite+aiosqlite:///./vulnapi.db"

    # VULNERABILITY: Weak secret key, hardcoded default
    secret_key: str = "intentionally-weak-secret-key-do-not-use-in-production"

    # VULNERABILITY: Algorithm can be changed (allows "none" attack)
    jwt_algorithm: str = "HS256"
    jwt_expiration_minutes: int = 30

    # Debug mode
    debug: bool = True

    # API version
    api_version: str = "v1"

    # VULNERABILITY: No rate limiting by default
    rate_limit_enabled: bool = False
    rate_limit_requests: int = 100
    rate_limit_window: int = 60

    class Config:
        env_prefix = "DOJO_"
        env_file = ".env"


settings = Settings()
