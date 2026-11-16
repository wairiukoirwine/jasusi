"""End-to-end API tests: scan endpoints, privacy of stored data, feedback, limits, auth, stats."""

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import create_api_key
from app.db.models import Feedback, Scan, ScanIOC
from app.extract.anonymise import anonymise
from app.main import create_app
from tests.conftest import make_settings

SCAM_SMS = "Nimekutumia Ksh 3,500 kimakosa. Tafadhali rudisha haraka kwa 0712345678"


def db(client):
    return client.app.state.session_factory()


def test_scan_sms_scam_has_full_contract(client) -> None:
    r = client.post("/v1/scan/sms", json={"text": SCAM_SMS})
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {
        "scan_id", "verdict", "risk_score", "category", "reasons", "iocs", "detectors",
        "intel_unavailable", "model_version", "latency_ms",
    }  # fmt: skip
    assert body["verdict"] == "SCAM" and body["risk_score"] >= 70
    assert body["category"] == "mpesa_reversal_scam"
    assert body["reasons"] and body["iocs"]["phones"] == ["0712xxxxxx"]
    assert body["detectors"]["text"] > 0.5 and body["detectors"]["url"] is None


def test_scan_sms_legit_is_safe_with_a_reason(client) -> None:
    body = client.post("/v1/scan/sms", json={"text": "Tukutane kesho saa nne"}).json()
    assert body["verdict"] == "SAFE" and body["category"] == "legit" and body["reasons"]


def test_scan_sms_with_bad_link_flags_intel_unavailable(client) -> None:
    text = "KRA: account suspended. Verify at http://kra-itax-verify.xyz/login"
    body = client.post("/v1/scan/sms", json={"text": text}).json()
    assert body["verdict"] == "SCAM" and body["detectors"]["url"] > 0.7
    assert body["intel_unavailable"] is True
    assert body["iocs"]["urls"] == ["http://kra-itax-verify.xyz/login"]


def test_scan_url_and_email(client) -> None:
    url = client.post("/v1/scan/url", json={"url": "http://safaricom-rewards.top/claim"}).json()
    assert url["verdict"] == "SCAM" and url["category"] == "phishing_link"
    assert url["detectors"]["text"] is None

    safe = client.post("/v1/scan/url", json={"url": "https://www.kra.go.ke"}).json()
    assert safe["verdict"] == "SAFE"

    email = client.post(
        "/v1/scan/email",
        json={
            "subject": "Job offer",
            "body": "Pay Ksh 1,500 processing fee to paybill 522522 today",
        },
    ).json()
    assert email["verdict"] != "SAFE" and email["iocs"]["paybills"] == ["522522"]


def test_input_validation_and_size_limits(client) -> None:
    assert client.post("/v1/scan/sms", json={"text": "   "}).status_code == 422
    assert client.post("/v1/scan/sms", json={"text": "a" * 2001}).status_code == 422
    assert client.post("/v1/scan/sms", json={}).status_code == 422
    assert client.post("/v1/scan/url", json={"url": "not a url"}).status_code == 422
    assert client.post("/v1/scan/email", json={"body": "x" * 50_001}).status_code == 422
    huge = client.post(
        "/v1/scan/email", content=b"x" * 70_000, headers={"content-type": "application/json"}
    )
    assert huge.status_code == 413


def test_no_raw_text_or_unmasked_iocs_are_stored(client) -> None:
    scan_id = client.post("/v1/scan/sms", json={"text": SCAM_SMS + " http://bad.xyz/a"}).json()[
        "scan_id"
    ]
    with db(client) as session:
        scan = session.get(Scan, scan_id)
        iocs = session.scalars(select(ScanIOC).where(ScanIOC.scan_id == scan_id)).all()
    assert len(scan.content_hash) == 64 and "kimakosa" not in scan.content_hash
    stored = {(i.type, i.value_masked) for i in iocs}
    assert stored == {("phone", "0712xxxxxx"), ("url", "hxxp://bad[.]xyz/a")}


def test_feedback_without_key_never_stores_text(client) -> None:
    scan_id = client.post("/v1/scan/sms", json={"text": SCAM_SMS}).json()["scan_id"]
    r = client.post(
        "/v1/feedback",
        json={
            "scan_id": scan_id,
            "user_label": "scam",
            "consent_raw_text": True,
            "raw_text": SCAM_SMS,
        },
    )
    assert r.json() == {"status": "recorded", "raw_text_stored": False}
    with db(client) as session:
        row = session.scalars(select(Feedback)).one()
    assert row.raw_text_encrypted is None and row.consent_raw_text is False


def test_feedback_with_consent_stores_anonymised_encrypted_text(tmp_path) -> None:
    key = Fernet.generate_key().decode()
    app = create_app(make_settings(feedback_encryption_key=key), dashboard_dir=tmp_path / "none")
    with TestClient(app) as client:
        scan_id = client.post("/v1/scan/sms", json={"text": SCAM_SMS}).json()["scan_id"]
        payload = {"scan_id": scan_id, "user_label": "scam", "raw_text": SCAM_SMS}
        no_consent = client.post("/v1/feedback", json={**payload, "consent_raw_text": False})
        assert no_consent.json()["raw_text_stored"] is False
        consent = client.post("/v1/feedback", json={**payload, "consent_raw_text": True})
        assert consent.json()["raw_text_stored"] is True
        with db(client) as session:
            rows = session.scalars(select(Feedback).order_by(Feedback.id)).all()
    assert rows[0].raw_text_encrypted is None
    assert b"0712345678" not in rows[1].raw_text_encrypted
    assert Fernet(key.encode()).decrypt(rows[1].raw_text_encrypted).decode() == anonymise(SCAM_SMS)


def test_feedback_for_unknown_scan_is_404(client) -> None:
    r = client.post("/v1/feedback", json={"scan_id": "0" * 36, "user_label": "legit"})
    assert r.status_code == 404


def test_rate_limit_returns_429(tmp_path) -> None:
    app = create_app(make_settings(rate_limit_per_minute=3), dashboard_dir=tmp_path / "none")
    with TestClient(app) as client:
        codes = [
            client.post("/v1/scan/sms", json={"text": "hello there"}).status_code for _ in range(5)
        ]
    assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]


def test_api_key_required_when_configured(tmp_path) -> None:
    app = create_app(make_settings(require_api_key=True), dashboard_dir=tmp_path / "none")
    with TestClient(app) as client:
        with db(client) as session:
            key = create_api_key(session, "tester")
        body = {"text": "hello there"}
        assert client.post("/v1/scan/sms", json=body).status_code == 401
        assert (
            client.post("/v1/scan/sms", json=body, headers={"X-API-Key": "jsk_wrong"}).status_code
            == 401
        )
        assert client.post("/v1/scan/sms", json=body, headers={"X-API-Key": key}).status_code == 200
        assert client.get("/v1/stats/summary").status_code == 401
        assert client.get("/v1/health").status_code == 200


def test_stats_summary_aggregates_without_sensitive_data(client) -> None:
    scam_id = client.post("/v1/scan/sms", json={"text": SCAM_SMS}).json()["scan_id"]
    client.post("/v1/scan/sms", json={"text": "Tukutane kesho"})
    client.post("/v1/scan/url", json={"url": "http://safaricom-rewards.top/claim"})
    client.post("/v1/feedback", json={"scan_id": scam_id, "user_label": "scam"})

    stats = client.get("/v1/stats/summary?days=7").json()
    assert stats["total_scans"] == 3 and len(stats["daily"]) == 7
    assert {v["name"]: v["count"] for v in stats["verdicts"]} == {"SCAM": 2, "SAFE": 1}
    assert stats["daily"][-1]["total"] == 3
    assert stats["feedback"] == {"total": 1, "agree": 1, "disagree": 0, "unsure": 0}
    assert "0712345678" not in str(stats) and "kimakosa" not in str(stats)
    assert {"type": "phone", "value_masked": "0712xxxxxx"}.items() <= stats["recent_iocs"][
        0
    ].items() or any(i["value_masked"] == "0712xxxxxx" for i in stats["recent_iocs"])
