"""Application configuration loaded from environment variables.

Reads from `.env` in development. In production, env vars override.
"""
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All runtime config. Add new fields here, never hardcode values in app code."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # ignore unrelated env vars present on the machine
    )

    # ─── App metadata ─────────────────────────────────────────────────
    app_name: str = Field(default="secure-audit-log-gateway")
    app_version: str = Field(default="0.1.0")
    environment: str = Field(default="development", description="development | production")

    # ─── MongoDB ──────────────────────────────────────────────────────
    mongo_url: str = Field(default="mongodb://localhost:27017")
    mongo_db_name: str = Field(default="audit_logs")
    mongo_collection: str = Field(default="entries")

    # ─── JWT ──────────────────────────────────────────────────────────
    jwt_secret: str = Field(
        ...,  # required — must be set in .env
        min_length=16,
        description="HS256 shared secret. Placeholder for solo dev, real value from instructor for integration.",
    )
    jwt_algorithm: str = Field(default="HS256")
    jwt_issuer: str | None = Field(default=None, description="Expected `iss` claim, if enforced.")

    # ─── Admin UI ─────────────────────────────────────────────────────
    admin_username: str = Field(default="admin", description="Username for the admin login form.")
    admin_password_hash: str = Field(..., description="bcrypt hash of the admin password. Generate via scripts/make_admin_password_hash.")
    admin_jwt_lifetime_hours: int = Field(default=24, ge=1, le=168, description="How long an admin JWT stays valid after login.")

    # ─── Schema ───────────────────────────────────────────────────────
    schema_version: int = Field(default=1, description="Stamped on every stored log entry.")

    # ─── Server ───────────────────────────────────────────────────────
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000, ge=1, le=65535)


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor.

    Use this everywhere instead of instantiating Settings() directly.
    `@lru_cache` ensures we parse `.env` exactly once per process.
    """
    return Settings()
