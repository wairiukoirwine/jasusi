"""Threat-intelligence lookups for URLs: VirusTotal, Google Safe Browsing, PhishTank, domain age.

Rules this module follows:
- The suspicious URL itself is NEVER requested. Only reputation services are asked about it.
- Lookups are async, run in parallel, cached for 24h and fail open: a provider that is
  down, slow or unconfigured is skipped, and `unavailable` is set if none answered.
- A provider without an API key is not called at all.
"""

import asyncio
import base64
import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

import httpx

from app.core.cache import Cache
from app.core.config import Settings
from app.detectors.base import Evidence
from ml.features.url_features import registered_domain, split

logger = logging.getLogger(__name__)


@dataclass
class IntelResult:
    """Combined reputation verdict. `score` is None when no provider answered."""

    score: float | None = None
    malicious: bool = False
    unavailable: bool = True
    sources: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    latency_ms: float = 0.0


def _with_scheme(url: str) -> str:
    return url if "://" in url else f"http://{url}"


class ThreatIntel:
    """Callable on its own: `await ThreatIntel(settings, cache).lookup(url)`."""

    def __init__(
        self, settings: Settings, cache: Cache, client: httpx.AsyncClient | None = None
    ) -> None:
        self._s = settings
        self._cache = cache
        self._client = client or httpx.AsyncClient(
            timeout=settings.intel_timeout_seconds, follow_redirects=False
        )

    @property
    def enabled(self) -> bool:
        s = self._s
        return bool(
            s.virustotal_api_key
            or s.google_safe_browsing_api_key
            or s.phishtank_app_key
            or s.whois_enabled
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    # --- providers: each returns True (malicious), False (clean) or None (no opinion) ---

    async def _virustotal(self, url: str) -> bool | None:
        url_id = base64.urlsafe_b64encode(_with_scheme(url).encode()).decode().rstrip("=")
        r = await self._client.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": self._s.virustotal_api_key},
        )
        if r.status_code == 404:
            return None
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0)) >= 2

    async def _safe_browsing(self, url: str) -> bool | None:
        body = {
            "client": {"clientId": "jasusi", "clientVersion": "1"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": _with_scheme(url)}],
            },
        }
        r = await self._client.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": self._s.google_safe_browsing_api_key},
            json=body,
        )
        r.raise_for_status()
        return bool(r.json().get("matches"))

    async def _phishtank(self, url: str) -> bool | None:
        r = await self._client.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": _with_scheme(url), "format": "json", "app_key": self._s.phishtank_app_key},
            headers={"User-Agent": "phishtank/jasusi"},
        )
        r.raise_for_status()
        results = r.json()["results"]
        if not results.get("in_database"):
            return None
        return bool(results.get("valid"))

    async def _domain_age_days(self, url: str) -> int | None:
        """Domain age from RDAP (the registry's record, not the suspicious site)."""
        domain = registered_domain(split(url)[0])
        r = await self._client.get(f"https://rdap.org/domain/{domain}", follow_redirects=True)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        for event in r.json().get("events", []):
            if event.get("eventAction") == "registration":
                created = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                return (datetime.now(UTC) - created).days
        return None

    # --- orchestration ---

    async def _safe(self, name: str, coro) -> tuple[str, object, bool]:
        """Run one provider; never raise. Returns (name, value, answered)."""
        try:
            value = await asyncio.wait_for(coro, timeout=self._s.intel_timeout_seconds)
            return name, value, True
        except Exception as exc:  # noqa: BLE001 - fail open by design
            # Log the exception type only: URLs and keys must not end up in logs.
            logger.warning("Threat intel provider %s failed: %s", name, type(exc).__name__)
            return name, None, False

    async def lookup(self, url: str) -> IntelResult:
        if not self.enabled:
            return IntelResult()
        start = time.perf_counter()
        key = "intel:" + hashlib.sha256(url.strip().lower().encode()).hexdigest()
        cached = await self._cache.get(key)
        if cached:
            data = json.loads(cached)
            data["evidence"] = [Evidence(**e) for e in data["evidence"]]
            return IntelResult(**data)

        s = self._s
        tasks = []
        if s.virustotal_api_key:
            tasks.append(self._safe("VirusTotal", self._virustotal(url)))
        if s.google_safe_browsing_api_key:
            tasks.append(self._safe("Google Safe Browsing", self._safe_browsing(url)))
        if s.phishtank_app_key:
            tasks.append(self._safe("PhishTank", self._phishtank(url)))
        if s.whois_enabled:
            tasks.append(self._safe("domain_age", self._domain_age_days(url)))

        result = IntelResult()
        clean_votes = 0
        young = False
        for name, value, answered in await asyncio.gather(*tasks):
            if not answered:
                continue
            result.unavailable = False
            if name == "domain_age":
                if isinstance(value, int) and value < s.young_domain_days:
                    young = True
                    result.sources.append("domain_age")
                    result.evidence.append(
                        Evidence(
                            "intel_young_domain", f"Domain was registered {value} days ago", 0.5
                        )
                    )
                continue
            if value is True:
                result.malicious = True
                result.sources.append(name)
                result.evidence.append(
                    Evidence("intel_malicious", f"{name} lists this link as malicious", 1.0)
                )
            elif value is False:
                clean_votes += 1

        if result.malicious:
            result.score = 1.0
        elif young:
            result.score = 0.6
        elif clean_votes:
            result.score = 0.0
        result.latency_ms = round((time.perf_counter() - start) * 1000, 2)
        if not result.unavailable:
            await self._cache.set(key, json.dumps(asdict(result)), s.intel_cache_ttl_seconds)
        return result
