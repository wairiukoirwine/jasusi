"""Shared fixtures. Tests never need trained models, Redis, Postgres or the network:
model paths point at nothing (rule fallback), the DB is in-memory SQLite."""

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


def make_settings(**overrides) -> Settings:
    base = {
        "app_env": "test",
        "database_url": "sqlite:///:memory:",
        "redis_url": "",
        "text_model_path": "does/not/exist.joblib",
        "url_model_path": "does/not/exist.json",
        "rate_limit_per_minute": 1000,
        "virustotal_api_key": "",
        "google_safe_browsing_api_key": "",
        "phishtank_app_key": "",
        "whois_enabled": False,
        "require_api_key": False,
        "feedback_encryption_key": "",
    }
    return Settings(_env_file=None, **{**base, **overrides})


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def client(settings: Settings, tmp_path) -> TestClient:
    with TestClient(create_app(settings, dashboard_dir=tmp_path / "none")) as c:
        yield c
