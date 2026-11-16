"""Application settings, read from environment variables (and `.env` in local dev).

Thresholds, weights and limits live here rather than in code so they can be tuned
on the validation set without touching the detectors or the risk engine.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

API_VERSION = "0.2.0"
REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    """Typed view of the environment. Unknown variables are ignored."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"

    # Storage. SQLite and the in-memory cache are local-dev fallbacks so the API
    # runs without Docker; set both URLs for Postgres + Redis.
    database_url: str = "sqlite:///./jasusi.db"
    redis_url: str = ""

    # Model artifacts (gitignored). Missing files fall back to rule-based detectors.
    text_model_path: str = "ml/models/text/current.joblib"
    url_model_path: str = "ml/models/url/current.json"

    # Verdict bands: SAFE < suspicious <= SUSPICIOUS < scam <= SCAM
    risk_threshold_suspicious: int = Field(default=30, ge=0, le=100)
    risk_threshold_scam: int = Field(default=70, ge=0, le=100)

    # Risk engine weights (renormalised over the detectors that actually ran).
    weight_text: float = 0.6
    weight_url: float = 0.3
    weight_intel: float = 0.1
    rule_bonus_urgency_money: int = 10
    # Real reversals go through M-Pesa itself, never to a number in the message.
    rule_bonus_reversal: int = 15
    intel_malicious_floor: int = 90
    verified_sender_cap: int = 20
    # Sender IDs that official services use. Sender IDs can be spoofed, so this only
    # lowers risk when nothing else in the message looks malicious (see risk_engine).
    verified_senders: list[str] = ["MPESA", "M-PESA", "SAFARICOM", "KRA", "KCB", "EQUITY BANK"]

    # Input limits
    max_sms_chars: int = 2000
    max_email_bytes: int = 50_000
    max_url_chars: int = 2048
    max_body_bytes: int = 64_000

    # Access control
    rate_limit_per_minute: int = Field(default=30, gt=0)
    require_api_key: bool = False
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Threat intelligence (each provider is skipped when its key is empty)
    virustotal_api_key: str = ""
    google_safe_browsing_api_key: str = ""
    phishtank_app_key: str = ""
    whois_enabled: bool = False
    intel_timeout_seconds: float = 3.0
    intel_cache_ttl_seconds: int = 86_400
    young_domain_days: int = 30

    # Fernet key for raw text donated through /feedback. Empty = raw text is never stored.
    feedback_encryption_key: str = ""

    def resolve(self, path: str) -> Path:
        """Resolve a possibly-relative artifact path against the repo root."""
        p = Path(path)
        return p if p.is_absolute() else REPO_ROOT / p


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings (cached so `.env` is read once)."""
    return Settings()
