"""Text detector: scam probability for SMS / e-mail text.

Uses the trained TF-IDF + Logistic Regression baseline when its artifact exists
(`ml/training/train_text.py`). Without it, falls back to the transparent rule score so
the API still runs, and says so through `model_version = "text-rules-v0"`.
"""

import logging
import time
from pathlib import Path

from app.detectors import rules
from app.detectors.base import DetectorResult, Evidence

logger = logging.getLogger(__name__)
RULES_VERSION = "text-rules-v0"
_FILLER = frozenset(
    "the a an to of in on at for and or is are was be been your you we our us this that it its "
    "with from by as have has had will can not no do does if but so me my i he she they them "
    "ya wa na kwa ni la za cha vya hii hiyo huu huo yako yangu wewe mimi sisi kwenye katika au "
    "dear hello hi habari new now get here via please".split()
)


class TextDetector:
    """Callable on its own: `TextDetector(path).predict("...")`."""

    def __init__(self, model_path: Path | None = None) -> None:
        self._pipeline = None
        self._word_names: list[str] = []
        self._word_coefs = None
        self.model_version = RULES_VERSION
        if model_path and model_path.exists():
            self._load(model_path)

    def _load(self, path: Path) -> None:
        import joblib  # heavy import, only needed when a model is present

        # joblib uses pickle: only ever load artifacts produced by our own training script.
        bundle = joblib.load(path)
        self._pipeline = bundle["pipeline"]
        self.model_version = bundle["version"]
        union = self._pipeline.named_steps["features"]
        word_vec = dict(union.transformer_list)["word"]
        self._word_names = list(word_vec.get_feature_names_out())
        self._word_coefs = self._pipeline.named_steps["clf"].coef_[0][: len(self._word_names)]
        self._word_vec = word_vec
        logger.info("Loaded text model %s from %s", self.model_version, path)

    @property
    def uses_model(self) -> bool:
        return self._pipeline is not None

    def _top_terms(self, text: str, k: int = 3) -> list[str]:
        """Words/phrases in this message that push the model most towards 'scam'."""
        row = self._word_vec.transform([text])
        contributions = row.multiply(self._word_coefs).tocoo()
        ranked = sorted(zip(contributions.data, contributions.col, strict=True), reverse=True)
        terms: list[str] = []
        for value, col in ranked:
            if value <= 0.05 or len(terms) >= k:
                break
            term = self._word_names[col]
            words = term.split()
            # Numbers and filler words are not meaningful reasons to show a person.
            if any(w.isdigit() for w in words) or all(w in _FILLER or len(w) < 3 for w in words):
                continue
            if not any(term in t or t in term for t in terms):
                terms.append(term)
        return terms

    def predict(self, text: str) -> DetectorResult:
        start = time.perf_counter()
        signals = rules.find_signals(text)
        evidence = list(signals)
        if self._pipeline is not None:
            score = float(self._pipeline.predict_proba([text])[0][1])
            terms = self._top_terms(text) if score >= 0.3 else []
            if terms:
                quoted = ", ".join(f"“{t}”" for t in terms)
                evidence.append(
                    Evidence("model_terms", f"Wording often seen in scam messages: {quoted}", 0.35)
                )
        else:
            score = rules.rule_score(signals)
        label = "scam" if score >= 0.5 else "legit"
        latency = (time.perf_counter() - start) * 1000
        return DetectorResult(score, label, evidence, round(latency, 2), self.model_version)
