"""Tests for GET /v1/health."""

from app.core.config import API_VERSION


def test_health_returns_ok(client) -> None:
    response = client.get("/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == API_VERSION
    assert body["environment"] == "test"
    assert body["text_model"] == "text-rules-v0"
    assert body["threat_intel_enabled"] is False


def test_health_is_versioned_under_v1(client) -> None:
    assert client.get("/health").status_code == 404


def test_security_headers_are_set(client) -> None:
    headers = client.get("/v1/health").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
