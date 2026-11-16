"""Anonymisation applied before any message text is stored or used for training.

Kenya Data Protection Act 2019: phone numbers, names, e-mail addresses and ID numbers
are replaced with placeholders. Amounts are kept because they matter for scam detection.

Phones, e-mails and ID numbers follow patterns and are masked reliably. Names do not:
they are masked by context rules (greetings, titles, "jina", M-Pesa "to/from NAME NAME"),
so some names will be missed. Treat the output as reduced-risk, not risk-free, and keep
donated text encrypted and access-controlled.
"""

import re

from app.extract.iocs import EMAIL_RE, INTL_PHONE_RE, KE_PHONE_RE

PHONE, NAME, ID, EMAIL = "<PHONE>", "<NAME>", "<ID>", "<EMAIL>"

_KRA_PIN_RE = re.compile(r"\b[AP]\d{9}[A-Z]\b")
_NATIONAL_ID_RE = re.compile(
    r"(?i)\b((?:national\s+)?id(?:\s+(?:no|number|namba))?|kitambulisho(?:\s+(?:no|namba))?|passport(?:\s+no)?)"
    r"(\.?\s*[:#-]?\s*)([A-Z]?\d{6,9})\b"
)

_WORD = r"[A-Z][a-zA-Z'’-]+"
_CAPS = r"[A-Z][A-Z'’-]+"
# Words that look like names in these positions but are not personal data.
_NOT_NAMES = {
    "customer", "client", "sir", "madam", "user", "member", "parent", "guardian", "tenant",
    "applicant", "friend", "all", "team", "subscriber", "mteja", "ndugu", "student", "winner",
    "valued", "esteemed", "safaricom", "mpesa", "m-pesa", "airtel", "telkom", "equity", "kcb",
    "kra", "bank", "limited", "ltd", "kenya", "fuliza", "paybill", "account", "agent",
}  # fmt: skip

_GREETING_RE = re.compile(
    rf"\b((?i:dear|hi|hello|hey|habari|mpendwa|ndugu|mr|mrs|ms|miss|dr|prof|bw|bi)\.?,?\s+)"
    rf"({_WORD}(?:\s+{_WORD}){{0,2}})"
)
_JINA_RE = re.compile(
    rf"((?i:jina(?:\s+(?:la|ni|litakuja|litatokea))?|name(?:\s+is)?|majina)\s*[:(-]?\s*)"
    rf"({_WORD}(?:\s+{_WORD}){{0,2}})"
)
_MPESA_PARTY_RE = re.compile(
    rf"((?i:\b(?:to|from|kwa|kutoka\s+kwa|sent\s+to|received\s+from|paid\s+to)\s+))({_CAPS}(?:\s+{_CAPS}){{1,3}})\b"
)


def _mask_name(match: re.Match[str]) -> str:
    prefix, candidate = match.group(1), match.group(2)
    kept: list[str] = []
    masked = False
    for word in candidate.split():
        if word.lower().strip("'’-") in _NOT_NAMES:
            kept.append(word)
        elif not masked:
            kept.append(NAME)
            masked = True
    return prefix + " ".join(kept)


def anonymise(text: str) -> str:
    """Return `text` with phones, e-mails, ID numbers and context-detected names masked."""
    out = EMAIL_RE.sub(EMAIL, text)
    out = KE_PHONE_RE.sub(PHONE, out)
    out = INTL_PHONE_RE.sub(PHONE, out)
    out = _KRA_PIN_RE.sub(ID, out)
    out = _NATIONAL_ID_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{ID}", out)
    out = _MPESA_PARTY_RE.sub(_mask_name, out)
    out = _JINA_RE.sub(_mask_name, out)
    out = _GREETING_RE.sub(_mask_name, out)
    return out
