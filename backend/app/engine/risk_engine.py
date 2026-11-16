"""Risk engine: combines detector scores and rules into one 0-100 score and a verdict.

    base = w_text*text + w_url*url + w_intel*intel     (weights renormalised over what ran)
    + bonus when urgency and a money request appear together
    + bonus when a payment reversal is requested with pressure or a number to pay
    overrides: intel says malicious -> at least 90; verified sender -> at most 20

All numbers come from `Settings`, never from this file.
"""

from dataclasses import dataclass, field

from app.core.config import Settings
from app.detectors import rules
from app.detectors.base import DetectorResult, Evidence
from app.detectors.threat_intel import IntelResult

SAFE, SUSPICIOUS, SCAM = "SAFE", "SUSPICIOUS", "SCAM"


@dataclass
class RiskResult:
    risk_score: int
    verdict: str
    category: str
    applied_rules: list[Evidence] = field(default_factory=list)


def verdict_for(score: int, settings: Settings) -> str:
    if score >= settings.risk_threshold_scam:
        return SCAM
    if score >= settings.risk_threshold_suspicious:
        return SUSPICIOUS
    return SAFE


def is_verified_sender(sender: str | None, settings: Settings) -> bool:
    return bool(sender) and sender.strip().upper() in {v.upper() for v in settings.verified_senders}


def combine(
    *,
    text: DetectorResult | None,
    url: DetectorResult | None,
    intel: IntelResult | None,
    signals: list[Evidence],
    has_url: bool,
    sender: str | None,
    settings: Settings,
) -> RiskResult:
    """Produce the final risk score, verdict and category for one scan."""
    parts: list[tuple[float, float]] = []
    if text is not None:
        parts.append((settings.weight_text, text.score))
    if url is not None:
        parts.append((settings.weight_url, url.score))
    if intel is not None and intel.score is not None:
        parts.append((settings.weight_intel, intel.score))
    total_weight = sum(w for w, _ in parts)
    base = sum(w * s for w, s in parts) / total_weight if total_weight else 0.0

    # A clearly bad link should not be averaged away by harmless surrounding text.
    if url is not None and text is not None:
        base = max(base, 0.85 * url.score)

    risk = round(base * 100)
    applied: list[Evidence] = []
    codes = {s.code for s in signals}

    if "urgency" in codes and codes & {"money_request", "credential_request", "reversal"}:
        risk += settings.rule_bonus_urgency_money
        applied.append(
            Evidence(
                "rule_urgency_money", "Combines pressure with a request for money or codes", 0.5
            )
        )

    if "reversal" in codes and codes & {"money_request", "call_back", "urgency"}:
        risk += settings.rule_bonus_reversal
        applied.append(
            Evidence(
                "rule_reversal",
                "Genuine M-Pesa reversals are done by Safaricom, not by sending money back yourself",
                0.7,
            )
        )

    intel_malicious = bool(intel and intel.malicious)
    if intel_malicious:
        risk = max(risk, settings.intel_malicious_floor)

    # Sender IDs can be spoofed, so a "verified" sender only lowers risk when the message
    # carries no link that the URL model or threat intel considers bad.
    url_bad = url is not None and url.score >= 0.5
    if is_verified_sender(sender, settings) and not intel_malicious and not url_bad:
        if risk > settings.verified_sender_cap:
            applied.append(
                Evidence("rule_verified_sender", "Sender ID matches an official service", 0.2)
            )
        risk = min(risk, settings.verified_sender_cap)

    risk = max(0, min(100, risk))
    verdict = verdict_for(risk, settings)
    if verdict == SAFE:
        category = "legit"
    elif text is None:
        category = "phishing_link"
    else:
        category = rules.categorise(signals, has_url)
    return RiskResult(risk, verdict, category, applied)
