"""Application settings, read from environment variables (and `.env` in local dev).

Thresholds and limits live here rather than in code so they can be tuned on the
validation set without touching the detectors or the risk engine.
"""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

API_VERSION = "0.1.0"


class Settings(BaseSettings):
    """Typed view of the environment. Unknown variables are ignored."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"

    # Verdict bands: SAFE < suspicious <= SUSPICIOUS < scam <= SCAM
    risk_threshold_suspicious: int = Field(default=30, ge=0, le=100)
    risk_threshold_scam: int = Field(default=70, ge=0, le=100)

    rate_limit_per_minute: int = Field(default=30, gt=0)


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings (cached so `.env` is read once)."""
    return Settings()
