"""Threat intel against a mocked HTTP transport: verdicts, caching and fail-open behaviour.
No real network calls are made."""

import httpx

from app.core.cache import MemoryCache
from app.detectors.threat_intel import ThreatIntel
from tests.conftest import make_settings

URL = "http://bad.example.com/login"


def make_intel(handler, **settings) -> tuple[ThreatIntel, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(wrapped))
    return ThreatIntel(make_settings(**settings), MemoryCache(), client), seen


async def test_disabled_without_keys_and_makes_no_calls() -> None:
    intel, seen = make_intel(lambda r: httpx.Response(500))
    result = await intel.lookup(URL)
    assert not intel.enabled and result.unavailable and result.score is None and seen == []


async def test_virustotal_malicious_verdict() -> None:
    body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "suspicious": 1}}}}
    intel, seen = make_intel(lambda r: httpx.Response(200, json=body), virustotal_api_key="k")
    result = await intel.lookup(URL)
    assert result.malicious and result.score == 1.0 and not result.unavailable
    assert result.sources == ["VirusTotal"]
    assert seen[0].headers["x-apikey"] == "k"
    assert "bad.example.com" not in str(seen[0].url)  # only the encoded id is sent


async def test_clean_and_unknown_urls() -> None:
    clean = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70}}}}
    intel, _ = make_intel(lambda r: httpx.Response(200, json=clean), virustotal_api_key="k")
    assert (await intel.lookup(URL)).score == 0.0

    intel, _ = make_intel(lambda r: httpx.Response(404), virustotal_api_key="k")
    unknown = await intel.lookup(URL)
    assert unknown.score is None and not unknown.unavailable


async def test_safe_browsing_and_phishtank() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "safebrowsing" in request.url.host:
            return httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})
        return httpx.Response(200, json={"results": {"in_database": True, "valid": True}})

    intel, _ = make_intel(handler, google_safe_browsing_api_key="g", phishtank_app_key="p")
    result = await intel.lookup(URL)
    assert result.malicious and set(result.sources) == {"Google Safe Browsing", "PhishTank"}


async def test_fails_open_when_providers_error_or_time_out() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "virustotal" in request.url.host:
            raise httpx.ConnectTimeout("down")
        return httpx.Response(503)

    intel, _ = make_intel(handler, virustotal_api_key="k", phishtank_app_key="p")
    result = await intel.lookup(URL)
    assert result.unavailable and result.score is None and not result.malicious


async def test_results_are_cached() -> None:
    body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}}
    intel, seen = make_intel(lambda r: httpx.Response(200, json=body), virustotal_api_key="k")
    first = await intel.lookup(URL)
    second = await intel.lookup(URL)
    assert len(seen) == 1 and second.malicious == first.malicious and second.evidence


async def test_young_domain_raises_score() -> None:
    recent = {"events": [{"eventAction": "registration", "eventDate": "2999-01-01T00:00:00Z"}]}
    intel, seen = make_intel(lambda r: httpx.Response(200, json=recent), whois_enabled=True)
    result = await intel.lookup(URL)
    assert result.score == 0.6 and "domain_age" in result.sources
    assert seen[0].url.path == "/domain/example.com"  # the registry is asked, not the site
