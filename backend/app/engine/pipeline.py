"""Scan pipeline: extract IOCs -> run detectors -> risk engine -> explanation.

One place that wires the modules together, so the API layer stays thin and the same
pipeline can be reused by a bot or a batch job later.
"""

import asyncio
import hashlib
import time
from dataclasses import dataclass

from app.core.config import Settings
from app.detectors import rules
from app.detectors.base import DetectorResult, Evidence
from app.detectors.text_detector import TextDetector
from app.detectors.threat_intel import IntelResult, ThreatIntel
from app.detectors.url_detector import UrlDetector
from app.engine import explainer, risk_engine
from app.extract.iocs import IOCs, extract_iocs

MAX_URLS_PER_SCAN = 5


@dataclass
class ScanOutcome:
    channel: str
    content_hash: str
    verdict: str
    risk_score: int
    category: str
    reasons: list[str]
    iocs: IOCs
    text_score: float | None
    url_score: float | None
    intel_score: float | None
    intel_unavailable: bool
    model_version: str
    latency_ms: int


class ScanPipeline:
    def __init__(
        self, settings: Settings, text: TextDetector, url: UrlDetector, intel: ThreatIntel
    ) -> None:
        self.settings = settings
        self.text = text
        self.url = url
        self.intel = intel

    async def _scan_urls(self, urls: list[str]) -> tuple[DetectorResult | None, IntelResult | None]:
        """Score each link and keep the worst: one bad link is enough to make a message bad."""
        if not urls:
            return None, None
        urls = urls[:MAX_URLS_PER_SCAN]
        url_results = [self.url.predict(u) for u in urls]
        worst_url = max(url_results, key=lambda r: r.score)
        intel_results = await asyncio.gather(*(self.intel.lookup(u) for u in urls))
        worst_intel = max(intel_results, key=lambda r: (r.malicious, r.score or 0.0))
        worst_intel.unavailable = all(r.unavailable for r in intel_results)
        return worst_url, worst_intel

    async def scan(
        self, channel: str, *, text: str | None, url: str | None = None, sender: str | None = None
    ) -> ScanOutcome:
        start = time.perf_counter()
        content = text if text is not None else (url or "")
        iocs = extract_iocs(text) if text is not None else IOCs(urls=[url or ""])

        text_result = self.text.predict(text) if text is not None else None
        url_result, intel_result = await self._scan_urls(iocs.urls)
        signals = rules.find_signals(text) if text is not None else []

        risk = risk_engine.combine(
            text=text_result,
            url=url_result,
            intel=intel_result,
            signals=signals,
            has_url=bool(iocs.urls),
            sender=sender,
            settings=self.settings,
        )

        evidence: list[Evidence] = list(risk.applied_rules)
        if text_result:
            evidence += text_result.evidence
        if url_result and (url_result.score >= 0.3 or risk.verdict != risk_engine.SAFE):
            evidence += url_result.evidence
        if intel_result:
            evidence += intel_result.evidence
        if iocs.urls and text is not None and risk.verdict != risk_engine.SAFE:
            evidence.append(Evidence("has_link", "Contains a link", 0.15))

        used_fallback = (text is not None and not self.text.uses_model) or (
            bool(iocs.urls) and not self.url.uses_model
        )
        intel_unavailable = bool(iocs.urls) and (intel_result is None or intel_result.unavailable)
        reasons = explainer.build_reasons(
            risk.verdict,
            evidence,
            used_fallback=used_fallback,
            intel_unavailable=intel_unavailable,
            link_only=text is None,
        )
        versions = [text_result.model_version] if text_result else []
        if url_result:
            versions.append(url_result.model_version)

        return ScanOutcome(
            channel=channel,
            content_hash=hashlib.sha256(content.encode()).hexdigest(),
            verdict=risk.verdict,
            risk_score=risk.risk_score,
            category=risk.category,
            reasons=reasons,
            iocs=iocs,
            text_score=round(text_result.score, 4) if text_result else None,
            url_score=round(url_result.score, 4) if url_result else None,
            intel_score=intel_result.score if intel_result else None,
            intel_unavailable=intel_unavailable,
            model_version="+".join(versions),
            latency_ms=int((time.perf_counter() - start) * 1000),
        )
