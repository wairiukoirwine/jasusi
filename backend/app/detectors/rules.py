"""Keyword/regex signals in English, Swahili and Sheng.

Signals serve three purposes: (1) plain-language reasons for every verdict,
(2) the scam category, which the public training data does not label, and
(3) a transparent fallback score when no trained text model is installed.
They are deliberately simple and auditable; the trained model carries the accuracy.
"""

import re
from dataclasses import dataclass

from app.detectors.base import Evidence


@dataclass(frozen=True)
class Signal:
    code: str
    pattern: re.Pattern[str]
    message: str
    weight: float


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


_MONEY = r"(?:pesa|hela|money|cash|ksh|kes|kshs|sh\b|/=|\d{3,})"

SIGNALS: list[Signal] = [
    Signal(
        "reversal",
        _rx(
            r"\b(revers\w*|rudish\w*|nirudishie|kimakosa|by mistake|wrongly sent|sent .{0,20}wrong(?:ly)? number|erroneously)\b"
        ),
        "Asks you to reverse or return a payment",
        0.6,
    ),
    Signal(
        "money_request",
        _rx(
            rf"\b(tuma|nitumie|tumia|nitumia|send|deposit|weka|lipa|pay|transfer|nisaidie na|naomba)\b.{{0,40}}{_MONEY}"
        ),
        "Asks you to send money",
        0.45,
    ),
    Signal(
        "urgency",
        _rx(
            r"\b(urgent\w*|immediately|right now|act now|within \d+ ?(?:hrs?|hours?|minutes?|mins?)|haraka|sasa hivi|mara moja|upesi|last chance|final notice|expires? today|leo tu)\b"
        ),
        "Uses urgency to rush you",
        0.3,
    ),
    Signal(
        "account_threat",
        _rx(
            r"\b(suspend\w*|blocked|locked|deactivat\w*|restricted|imefungwa|itafungwa|imesitishwa|frozen|unusual activity|unauthori[sz]ed)\b"
        ),
        "Threatens that an account is blocked or suspended",
        0.4,
    ),
    Signal(
        "credential_request",
        _rx(
            r"(?<!not )(?<!never )(?<!usi)\b(share|send|enter|confirm|provide|verify|tuma|toa|weka|thibitisha)\b.{0,30}\b(pin|password|otp|verification code|namba ya siri|nywila|siri)\b"
        ),
        "Asks for a PIN, password or one-time code",
        0.6,
    ),
    Signal(
        "prize",
        _rx(
            r"\b(congratulations|hongera|umeshinda|you(?:'ve| have) won|winner|prize|zawadi|jackpot|lucky draw|claim your|bonus)\b"
        ),
        "Promises a prize or reward you did not enter for",
        0.4,
    ),
    Signal(
        "advance_fee",
        _rx(
            r"\b(registration fee|processing fee|activation fee|clearance fee|ada ya \w+|freemason|illuminati)\b"
        ),
        "Asks for an upfront fee",
        0.55,
    ),
    Signal(
        "loan",
        _rx(r"\b(loan|mkopo|mikopo|credit limit|approved for|qualif\w+ for)\b"),
        "Offers a loan or credit",
        0.25,
    ),
    Signal(
        "job",
        _rx(
            r"\b(job|kazi|vacanc\w+|hiring|work from home|part[- ]time|per day|interview|applicant|recruit\w*|salary)\b"
        ),
        "Offers a job or easy income",
        0.25,
    ),
    Signal(
        "authority",
        _rx(
            r"\b(kra|itax|ntsa|e-?citizen|huduma|hustler fund|helb|nssf|nhif|sha|kcb|equity|co-?op(?:erative)? bank|absa|ncba|stanbic|dtb|family bank|your bank|benki)\b"
        ),
        "Claims to come from a bank or government agency",
        0.25,
    ),
    Signal(
        "impersonation",
        _rx(
            r"\b(hey mum|hi mum|hey dad|hi dad|new number|namba (?:yangu )?mpya|this is my new|simu yangu (?:imeharibika|imepotea)|ni mimi)\b"
        ),
        "Pretends to be someone you know",
        0.45,
    ),
    Signal(
        "call_back",
        _rx(r"\b(call|piga|contact|whatsapp)\b.{0,25}(?:\+?254|0)[17]\d{2}"),
        "Tells you to call or message a personal number",
        0.3,
    ),
]

# First matching signal wins; order encodes how specific each category is.
_CATEGORY_ORDER = [
    ("reversal", "mpesa_reversal_scam"),
    ("impersonation", "impersonation"),
    ("job", "job_scam"),
    ("loan", "loan_scam"),
    ("authority", "fake_bank_or_kra"),
    ("account_threat", "fake_bank_or_kra"),
    ("prize", "prize_or_promo_scam"),
    ("advance_fee", "other_scam"),
]


def find_signals(text: str) -> list[Evidence]:
    """Return evidence for every signal that fires on `text`."""
    return [Evidence(s.code, s.message, s.weight) for s in SIGNALS if s.pattern.search(text)]


def rule_score(signals: list[Evidence]) -> float:
    """Noisy-OR of signal weights: more independent signals -> higher score, never above 1."""
    remaining = 1.0
    for signal in signals:
        remaining *= 1.0 - signal.weight
    return round(1.0 - remaining, 4)


def categorise(signals: list[Evidence], has_url: bool) -> str:
    """Pick the scam category from fired signals (used only when the verdict is not SAFE)."""
    codes = {s.code for s in signals}
    for code, category in _CATEGORY_ORDER:
        if code in codes:
            return category
    return "phishing_link" if has_url else "other_scam"
