"""Risk engine weights, overrides and verdict bands; explainer output."""

from app.detectors.base import DetectorResult, Evidence
from app.detectors.threat_intel import IntelResult
from app.engine import explainer, risk_engine
from tests.conftest import make_settings

S = make_settings()


def combine(text=None, url=None, intel=None, signals=(), sender=None, has_url=False):
    return risk_engine.combine(
        text=DetectorResult(text, "x") if text is not None else None,
        url=DetectorResult(url, "x") if url is not None else None,
        intel=intel,
        signals=[Evidence(code, code) for code in signals],
        has_url=has_url,
        sender=sender,
        settings=S,
    )


def test_verdict_bands_follow_config() -> None:
    assert combine(text=0.29).verdict == "SAFE"
    assert combine(text=0.30).verdict == "SUSPICIOUS"
    assert combine(text=0.69).verdict == "SUSPICIOUS"
    assert combine(text=0.70).verdict == "SCAM"


def test_weights_are_renormalised_over_available_detectors() -> None:
    assert combine(text=0.5).risk_score == 50
    assert combine(url=0.4).risk_score == 40
    # 0.6*0.2 + 0.3*0.2 over 0.9 = 0.2
    assert combine(text=0.2, url=0.2, has_url=True).risk_score == 20


def test_bad_link_is_not_averaged_away_by_harmless_text() -> None:
    assert combine(text=0.0, url=1.0, has_url=True).verdict == "SCAM"


def test_urgency_plus_money_adds_bonus() -> None:
    base = combine(text=0.5, signals=["urgency"]).risk_score
    boosted = combine(text=0.5, signals=["urgency", "money_request"])
    assert boosted.risk_score == base + S.rule_bonus_urgency_money
    assert any(e.code == "rule_urgency_money" for e in boosted.applied_rules)


def test_malicious_intel_forces_scam() -> None:
    intel = IntelResult(score=1.0, malicious=True, unavailable=False)
    result = combine(text=0.0, url=0.0, intel=intel, has_url=True)
    assert result.risk_score >= 90 and result.verdict == "SCAM"


def test_verified_sender_caps_risk_unless_link_is_bad() -> None:
    assert combine(text=0.95, sender="mpesa").risk_score == S.verified_sender_cap
    assert combine(text=0.95, sender="0712345678").risk_score == 95
    spoofed = combine(text=0.95, url=0.9, sender="MPESA", has_url=True)
    assert spoofed.verdict == "SCAM"


def test_category_is_legit_when_safe_and_rule_based_otherwise() -> None:
    assert combine(text=0.1, signals=["loan"]).category == "legit"
    assert combine(text=0.9, signals=["loan"]).category == "loan_scam"
    assert combine(text=0.9, has_url=True).category == "phishing_link"
    assert combine(url=0.9, has_url=True).category == "phishing_link"


def test_reasons_are_never_empty_and_are_ordered() -> None:
    assert explainer.build_reasons("SAFE", [], used_fallback=False, intel_unavailable=False)
    assert explainer.build_reasons("SCAM", [], used_fallback=False, intel_unavailable=False)
    evidence = [
        Evidence("a", "weak", 0.1),
        Evidence("b", "strong", 0.9),
        Evidence("c", "strong", 0.9),
    ]
    reasons = explainer.build_reasons("SCAM", evidence, used_fallback=True, intel_unavailable=True)
    assert reasons[:2] == ["strong", "weak"]
    assert any("basic rules" in r for r in reasons) and any("reputation" in r for r in reasons)


def test_safe_verdict_does_not_list_accusations() -> None:
    evidence = [Evidence("urgency", "Uses urgency to rush you", 0.3)]
    reasons = explainer.build_reasons(
        "SAFE", evidence, used_fallback=False, intel_unavailable=False
    )
    assert reasons == ["No strong scam indicators were found"]


def test_reversal_request_with_pressure_adds_bonus() -> None:
    plain = combine(text=0.5, signals=["reversal"]).risk_score
    pressured = combine(text=0.5, signals=["reversal", "call_back"])
    assert pressured.risk_score == plain + S.rule_bonus_reversal
    assert any(e.code == "rule_reversal" for e in pressured.applied_rules)
