"""Detectors: rule fallbacks, and the trained-model code paths on tiny throwaway models."""

import joblib
import numpy as np
import xgboost as xgb
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from app.detectors import rules
from app.detectors.text_detector import RULES_VERSION, TextDetector
from app.detectors.url_detector import UrlDetector
from ml.features import url_features

SCAM = "Nimekutumia pesa kimakosa, tafadhali rudisha Ksh 2000 haraka kwa 0712345678"
LEGIT = "Tukutane kesho saa nne asubuhi kwa ofisi"


def test_rules_fire_on_swahili_reversal_scam() -> None:
    codes = {e.code for e in rules.find_signals(SCAM)}
    assert {"reversal", "urgency"} <= codes
    assert rules.categorise(rules.find_signals(SCAM), has_url=False) == "mpesa_reversal_scam"


def test_rules_ignore_warning_not_to_share_pin() -> None:
    codes = {e.code for e in rules.find_signals("Your OTP is 1234. Do not share your PIN.")}
    assert "credential_request" not in codes


def test_rule_score_is_bounded_and_monotonic() -> None:
    one = rules.rule_score(rules.find_signals("urgent"))
    many = rules.rule_score(rules.find_signals(SCAM))
    assert 0 < one < many <= 1


def test_text_detector_falls_back_to_rules_without_model(tmp_path) -> None:
    detector = TextDetector(tmp_path / "missing.joblib")
    assert not detector.uses_model
    scam, legit = detector.predict(SCAM), detector.predict(LEGIT)
    assert scam.model_version == RULES_VERSION
    assert scam.score > 0.6 and scam.label == "scam" and scam.evidence
    assert legit.score == 0.0 and legit.label == "legit"


def test_text_detector_uses_trained_model(tmp_path) -> None:
    scams = [SCAM, "rudisha pesa haraka umeshinda zawadi", "tuma pesa kimakosa rudisha sasa"]
    legit = [LEGIT, "habari ya asubuhi tutaonana kesho", "niko njiani nakuja ofisi"]
    texts = (scams + legit) * 3
    labels = [1, 1, 1, 0, 0, 0] * 3
    features = FeatureUnion(
        [
            ("word", TfidfVectorizer()),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 3))),
        ]
    )
    pipeline = Pipeline([("features", features), ("clf", LogisticRegression(C=10))]).fit(
        texts, labels
    )
    path = tmp_path / "model.joblib"
    joblib.dump({"pipeline": pipeline, "version": "text-test"}, path)

    detector = TextDetector(path)
    result = detector.predict("rudisha pesa kimakosa")
    assert detector.uses_model and result.model_version == "text-test"
    assert result.score > 0.5
    assert any(e.code == "model_terms" for e in result.evidence)
    assert detector.predict("tutaonana kesho ofisi").score < 0.5


def test_url_detector_heuristic_without_model(tmp_path) -> None:
    detector = UrlDetector(tmp_path / "missing.json")
    bad = detector.predict("http://safaricom-rewards.top/login")
    assert bad.score > 0.7 and bad.label == "malicious"
    assert any("brand" in e.message for e in bad.evidence)
    assert detector.predict("https://example.org/about").score < 0.3


def test_url_detector_trusted_host_and_shortener(tmp_path) -> None:
    detector = UrlDetector(tmp_path / "missing.json")
    assert detector.predict("https://www.safaricom.co.ke/personal/m-pesa/login").score <= 0.05
    assert detector.predict("https://portal.myschool.ac.ke/student/login").score <= 0.2
    short = detector.predict("bit.ly/3abcd")
    assert short.score == 0.5 and "shortened" in short.evidence[0].message


def test_url_detector_uses_trained_model(tmp_path) -> None:
    bad = ["http://safaricom-rewards.top/login", "http://192.168.1.1/verify", "kra-itax.xyz/secure"]
    good = ["example.org/about", "news.example.com/sport", "university.ac.ke/courses"]
    x = np.asarray([url_features.to_vector(u) for u in (bad + good) * 10], dtype=np.float32)
    y = np.asarray(([1] * 3 + [0] * 3) * 10)
    booster = xgb.train(
        {"objective": "binary:logistic", "max_depth": 2, "min_child_weight": 0},
        xgb.DMatrix(x, label=y, feature_names=url_features.FEATURE_NAMES),
        num_boost_round=20,
    )
    booster.set_attr(version="url-test")
    path = tmp_path / "url.json"
    booster.save_model(str(path))

    detector = UrlDetector(path)
    assert detector.uses_model and detector.model_version == "url-test"
    assert detector.predict("http://safaricom-rewards.top/login").score > 0.5
    assert detector.predict("example.org/about").score < 0.5
