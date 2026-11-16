"""Tests for GET /v1/health."""

from fastapi.testclient import TestClient

from app.core.config import API_VERSION, Settings, get_settings
from app.main import create_app


def test_health_returns_ok() -> None:
    client = TestClient(create_app())

    response = client.get("/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == API_VERSION
    assert set(body) == {"status", "version", "environment"}


def test_health_reports_configured_environment() -> None:
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: Settings(app_env="test")

    response = TestClient(app).get("/v1/health")

    assert response.json()["environment"] == "test"


def test_health_is_versioned_under_v1() -> None:
    client = TestClient(create_app())

    assert client.get("/health").status_code == 404
