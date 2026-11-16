"""URL detector: phishing probability from lexical features only (never fetches the URL).

Uses the trained XGBoost model when present; otherwise a small heuristic over the same
features, reported as `model_version = "url-rules-v0"`.
"""

import logging
import time
from pathlib import Path

from app.detectors.base import DetectorResult, Evidence
from ml.features import url_features

logger = logging.getLogger(__name__)
RULES_VERSION = "url-rules-v0"

# Feature -> (message, heuristic weight). Messages are shown when the feature drives the score.
_MESSAGES: dict[str, tuple[str, float]] = {
    "has_ip": ("Link uses a raw IP address instead of a domain name", 0.6),
    "brand_mismatch": ("Link uses a known brand name on a domain the brand does not own", 0.7),
    "brand_lookalike": ("Domain is a look-alike spelling of a known brand", 0.7),
    "is_shortener": ("Link is shortened, hiding the real destination", 0.35),
    "tld_suspicious": ("Domain ending is common in throwaway scam sites", 0.4),
    "has_at": ("Link contains '@', which can disguise the real destination", 0.5),
    "has_punycode": ("Domain uses special characters that can imitate other letters", 0.5),
    "n_suspicious_words": ("Link contains words like 'login', 'verify' or 'secure'", 0.3),
    "n_subdomains": ("Link has an unusual number of subdomains", 0.25),
    "n_hyphens_host": ("Domain has several hyphens, typical of imitation sites", 0.2),
    "url_len": ("Link is unusually long", 0.15),
    "host_len": ("Domain name is unusually long", 0.15),
    "entropy_host": ("Domain looks randomly generated", 0.25),
    "entropy_path": ("Link path looks randomly generated", 0.15),
    "n_digits": ("Link contains many digits", 0.15),
    "digit_ratio": ("Link contains many digits", 0.15),
    "has_port": ("Link uses a non-standard port", 0.3),
}
_BINARY = ("has_ip", "brand_mismatch", "brand_lookalike", "is_shortener", "tld_suspicious",
           "has_at", "has_punycode", "has_port")  # fmt: skip


# A message is only shown when the feature value itself is unusual, not merely because the
# model leaned on that feature.
_GATES: dict[str, float] = {
    "n_suspicious_words": 1, "n_subdomains": 3, "n_hyphens_host": 2, "url_len": 75,
    "host_len": 30, "entropy_host": 3.8, "entropy_path": 4.5, "n_digits": 8, "digit_ratio": 0.2,
}  # fmt: skip
_GENERIC = Evidence("url_structure", "The link's structure resembles known phishing links", 0.3)


class UrlDetector:
    """Callable on its own: `UrlDetector(path).predict("example.com/login")`."""

    def __init__(self, model_path: Path | None = None) -> None:
        self._booster = None
        self.model_version = RULES_VERSION
        if model_path and model_path.exists():
            import xgboost as xgb

            self._xgb = xgb
            self._booster = xgb.Booster()
            self._booster.load_model(str(model_path))
            self.model_version = self._booster.attr("version") or "url-xgb"
            logger.info("Loaded URL model %s from %s", self.model_version, model_path)

    @property
    def uses_model(self) -> bool:
        return self._booster is not None

    def _heuristic(self, feats: dict[str, float]) -> tuple[float, list[Evidence]]:
        evidence = [
            Evidence(f"url_{name}", _MESSAGES[name][0], _MESSAGES[name][1])
            for name in _BINARY
            if feats[name]
        ]
        if feats["n_suspicious_words"] >= 1:
            evidence.append(Evidence("url_n_suspicious_words", *_MESSAGES["n_suspicious_words"]))
        if feats["n_subdomains"] >= 3:
            evidence.append(Evidence("url_n_subdomains", *_MESSAGES["n_subdomains"]))
        if feats["n_hyphens_host"] >= 2:
            evidence.append(Evidence("url_n_hyphens_host", *_MESSAGES["n_hyphens_host"]))
        remaining = 1.0
        for item in evidence:
            remaining *= 1.0 - item.weight
        return 1.0 - remaining, evidence

    def _model(self, feats: dict[str, float]) -> tuple[float, list[Evidence]]:
        row = [[feats[name] for name in url_features.FEATURE_NAMES]]
        matrix = self._xgb.DMatrix(row, feature_names=url_features.FEATURE_NAMES)
        score = float(self._booster.predict(matrix)[0])
        # TreeSHAP contributions (built into XGBoost): which features pushed towards phishing.
        contribs = self._booster.predict(matrix, pred_contribs=True)[0][:-1]
        ranked = sorted(zip(contribs, url_features.FEATURE_NAMES, strict=True), reverse=True)
        evidence: list[Evidence] = []
        seen: set[str] = set()
        for value, name in ranked:
            if value <= 0.15 or name not in _MESSAGES or len(evidence) >= 3:
                continue
            if name in _BINARY and not feats[name]:
                continue
            if name in _GATES and feats[name] < _GATES[name]:
                continue
            message, weight = _MESSAGES[name]
            if message not in seen:
                seen.add(message)
                evidence.append(Evidence(f"url_{name}", message, weight))
        return score, evidence

    def predict(self, url: str) -> DetectorResult:
        start = time.perf_counter()
        feats = url_features.extract(url)
        score, evidence = self._model(feats) if self._booster else self._heuristic(feats)
        if url_features.is_trusted_host(url):
            # Lexical models over-flag long paths on real sites; the official host wins.
            score = min(score, 0.05)
            evidence = [Evidence("url_trusted", "Link goes to a well-known official website", 0.2)]
        elif url_features.is_restricted_ke_domain(url) and not feats["brand_lookalike"]:
            score = min(score, 0.2)
            evidence = [
                Evidence(
                    "url_trusted",
                    "Domain ending is reserved for registered Kenyan institutions",
                    0.2,
                )
            ]
        elif feats["is_shortener"]:
            # The destination is hidden, so the link cannot be judged either way.
            score = 0.5
            evidence = [Evidence("url_is_shortener", *_MESSAGES["is_shortener"])]
        elif score >= 0.5 and not evidence:
            evidence = [_GENERIC]
        # Brand impersonation is the strongest plain-language reason; always surface it.
        for name in ("brand_mismatch", "brand_lookalike"):
            if feats[name] and not any(e.code == f"url_{name}" for e in evidence):
                evidence.append(Evidence(f"url_{name}", *_MESSAGES[name]))
        label = "malicious" if score >= 0.5 else "legit"
        latency = (time.perf_counter() - start) * 1000
        return DetectorResult(
            round(score, 4), label, evidence, round(latency, 2), self.model_version
        )
