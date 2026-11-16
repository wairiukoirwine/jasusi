"""Explainer: turns detector evidence and applied rules into plain-language reasons.

Every response must carry at least one reason, including SAFE verdicts.
"""

from app.detectors.base import Evidence
from app.engine.risk_engine import SAFE, SCAM

MAX_REASONS = 5
_REASSURING = {"rule_verified_sender", "url_trusted"}


def build_reasons(
    verdict: str,
    evidence: list[Evidence],
    *,
    used_fallback: bool,
    intel_unavailable: bool,
    link_only: bool = False,
) -> list[str]:
    """Order evidence by weight, drop duplicates and cap the list."""
    seen: set[str] = set()
    reasons: list[str] = []
    for item in sorted(evidence, key=lambda e: e.weight, reverse=True):
        if item.message in seen:
            continue
        seen.add(item.message)
        reasons.append(item.message)
        if len(reasons) >= MAX_REASONS:
            break

    if verdict == SAFE:
        # Weak signals on a safe message would read as accusations: keep only reassurance.
        reasons = ["No strong scam indicators were found"] + [
            e.message for e in evidence if e.code in _REASSURING and e.message in seen
        ]
    elif not reasons:
        reasons.append(
            "The link's structure resembles known phishing links"
            if link_only
            else (
                "The overall wording matches known scam messages"
                if verdict == SCAM
                else "Some features of this message resemble scam messages"
            )
        )
    if used_fallback:
        reasons.append("Checked with basic rules only (no trained model is installed)")
    if intel_unavailable and verdict != SAFE:
        reasons.append("Link reputation services were not consulted")
    return reasons
