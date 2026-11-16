"""Indicator-of-compromise (IOC) extraction: URLs, phone numbers, paybill/till numbers, emails.

Pure functions with no I/O. Nothing here ever visits a URL.
"""

import re
from dataclasses import dataclass, field

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")

# Bare domains (no scheme) are only accepted with these endings, to avoid matching
# ordinary text such as "e.g" or "Mr.John".
_TLDS = (
    "com|net|org|info|biz|xyz|top|ly|me|io|app|site|online|club|shop|link|live|cc|tk|ml|ga|cf|gq|"
    "africa|vip|icu|cyou|buzz|click|page|dev|gl|co|ke|tz|ug|ng|za|uk|us|ru|cn|in"
)
URL_RE = re.compile(rf"""(?ix)
    (?<![@\w.])
    (
        (?:https?://|www\.)[^\s<>"'()]+
        |
        (?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{_TLDS})\b(?:[/?\#][^\s<>"'()]*)?
    )
    """)
_TRAILING = ".,;:!?)]}'\""

# Kenyan mobile numbers: 07xx / 01xx / +2547xx / 2541xx, with optional spaces or dashes.
KE_PHONE_RE = re.compile(r"(?<![\d+])(?:\+?254|0)[\s-]?([17]\d{2})[\s-]?(\d{3})[\s-]?(\d{3})(?!\d)")
INTL_PHONE_RE = re.compile(r"(?<![\d+])\+(?!254)\d{9,14}(?!\d)")

PAYBILL_RE = re.compile(
    r"(?i)(?:pay\s?bill|business\s+(?:no|number)|till|buy\s+goods|lipa\s+na\s+m-?pesa)"
    r"(?:\s*(?:no|number|namba|nambari))?\.?\s*[:#-]?\s*(\d{5,7})(?!\d)"
)


@dataclass
class IOCs:
    """Indicators found in one message. Phone numbers are normalised to +254 form."""

    urls: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    paybills: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.urls or self.phones or self.paybills or self.emails)


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def extract_iocs(text: str) -> IOCs:
    """Extract all supported IOC types from free text."""
    emails = _unique(EMAIL_RE.findall(text))
    without_emails = EMAIL_RE.sub(" ", text)

    urls = _unique([m.group(1).rstrip(_TRAILING) for m in URL_RE.finditer(without_emails)])
    without_urls = URL_RE.sub(" ", without_emails)

    phones = [f"+254{a}{b}{c}" for a, b, c in KE_PHONE_RE.findall(without_urls)]
    phones += INTL_PHONE_RE.findall(without_urls)

    paybills = _unique(PAYBILL_RE.findall(without_urls))
    return IOCs(urls=urls, phones=_unique(phones), paybills=paybills, emails=emails)


def mask_phone(phone: str) -> str:
    """Mask a phone number for display/storage, e.g. +254712345678 -> 0712xxxxxx."""
    if phone.startswith("+254") and len(phone) == 13:
        return "0" + phone[4:7] + "xxxxxx"
    return phone[:4] + "x" * max(len(phone) - 4, 0)


def mask_email(email: str) -> str:
    """Keep the first character and the domain: j***@example.com."""
    local, _, domain = email.partition("@")
    return f"{local[:1]}***@{domain}"


def defang(url: str) -> str:
    """Make a URL non-clickable for storage and dashboards (hxxp, [.])."""
    return re.sub(r"(?i)^http", "hxxp", url).replace(".", "[.]")
