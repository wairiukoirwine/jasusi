"""Lexical URL features, shared by training (`ml/training/train_url.py`) and inference
(`backend/app/detectors/url_detector.py`). Training and serving MUST call `extract`.

Purely lexical: the URL is parsed as a string and is never resolved or fetched.
The scheme and a leading "www." are stripped first because the public legit set has
neither, and keeping them would let the model learn the data source instead of the URL.
"""

import math
import re
from collections import Counter

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rb.gy", "rebrand.ly", "shorturl.at", "tiny.cc", "t.ly", "s.id", "lnkd.in", "qr.ae",
}  # fmt: skip
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "icu", "cyou", "buzz", "click", "link", "live",
    "club", "online", "site", "shop", "vip", "work", "rest", "cfd", "sbs", "monster", "quest",
}  # fmt: skip
SUSPICIOUS_WORDS = (
    "login", "signin", "verify", "secure", "account", "update", "confirm", "wallet", "bonus",
    "free", "reward", "claim", "unlock", "suspend", "password", "bank", "pay", "gift", "promo",
)  # fmt: skip
# Second-level labels that are part of the public suffix under a country TLD (co.ke, go.ke...).
_SLD = {"co", "com", "go", "ac", "or", "ne", "org", "net", "gov", "edu", "sc", "me", "info"}

# Brand -> registered domains that legitimately use it (Kenyan focus, plus common globals).
BRANDS: dict[str, set[str]] = {
    "safaricom": {"safaricom.co.ke", "safaricom.com"},
    "mpesa": {"safaricom.co.ke", "m-pesa.africa", "mpesa.africa"},
    "airtel": {"airtelkenya.com", "airtel.co.ke", "airtel.africa", "airtel.in", "airtel.com"},
    "telkom": {"telkom.co.ke", "telkom.co.za"},
    "equity": {"equitybank.co.ke", "equitygroupholdings.com", "equitybankgroup.com"},
    "kcb": {"kcbgroup.com", "kcb.co.ke"},
    "coopbank": {"co-opbank.co.ke"},
    "absa": {"absabank.co.ke", "absa.co.za", "absa.africa"},
    "ncba": {"ncbagroup.com"},
    "stanbic": {"stanbicbank.co.ke"},
    "kra": {"kra.go.ke"},
    "itax": {"kra.go.ke"},
    "ecitizen": {"ecitizen.go.ke"},
    "ntsa": {"ntsa.go.ke"},
    "helb": {"helb.co.ke"},
    "paypal": {"paypal.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "facebook": {"facebook.com", "fb.com"},
    "netflix": {"netflix.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.co.jp"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "google": {"google.com", "google.co.ke"},
}  # fmt: skip

# Well-known sites that are safe when the link's host is exactly the domain (or www.domain).
# Subdomains are NOT trusted: scams are often hosted on sites.google.com, docs.google.com etc.
_POPULAR = {
    "google.com", "youtube.com", "facebook.com", "instagram.com", "x.com", "twitter.com",
    "linkedin.com", "wikipedia.org", "github.com", "microsoft.com", "apple.com", "amazon.com",
    "netflix.com", "whatsapp.com", "tiktok.com", "zoom.us", "paypal.com", "yahoo.com",
    "jumia.co.ke", "nation.africa", "standardmedia.co.ke", "kplc.co.ke", "ecitizen.go.ke",
    "hudumakenya.go.ke", "centralbank.go.ke", "aiu.ac.ke", "uonbi.ac.ke", "mygov.go.ke",
}  # fmt: skip
TRUSTED_HOSTS = _POPULAR | {domain for official in BRANDS.values() for domain in official}


def is_trusted_host(url: str) -> bool:
    """True when the link's host is exactly a well-known official domain."""
    return split(url)[0] in TRUSTED_HOSTS


# Kenyan second-level domains that KeNIC only issues to verified institutions
# (government, universities, schools). Not proof of safety, but a strong prior.
RESTRICTED_KE_SUFFIXES = (".go.ke", ".ac.ke", ".sc.ke")


def is_restricted_ke_domain(url: str) -> bool:
    return split(url)[0].endswith(RESTRICTED_KE_SUFFIXES)


FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "query_len", "n_dots_host", "n_hyphens_host",
    "n_subdomains", "n_digits", "digit_ratio", "n_slashes", "n_params", "n_special",
    "has_ip", "has_at", "has_port", "has_punycode", "entropy_host", "entropy_path",
    "tld_len", "tld_suspicious", "is_shortener", "n_suspicious_words", "brand_mismatch",
    "brand_lookalike", "longest_host_label", "hex_ratio_path",
]  # fmt: skip

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^0x[0-9a-f]+$|^\d{8,10}$", re.IGNORECASE)


def normalise(url: str) -> str:
    """Lower-case, strip scheme, credentials-free leading `www.` and trailing slash."""
    u = _SCHEME_RE.sub("", url.strip())
    if u.lower().startswith("www."):
        u = u[4:]
    return u.rstrip("/")


def split(url: str) -> tuple[str, str, str]:
    """Split a normalised URL into (host, path, query). Host excludes port and userinfo."""
    u = normalise(url)
    rest, _, query = u.partition("?")
    hostport, slash, path = rest.partition("/")
    host = hostport.rsplit("@", 1)[-1].split(":", 1)[0].lower().strip(".")
    return host, slash + path, query


def registered_domain(host: str) -> str:
    """Approximate registrable domain without the public-suffix list (which needs a download)."""
    labels = [x for x in host.split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _edit_distance_le1(a: str, b: str) -> bool:
    """True when a and b differ by at most one insert, delete or substitution."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = j = diffs = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        diffs += 1
        if diffs > 1:
            return False
        if len(a) == len(b):
            i += 1
        j += 1
    return True


_DIGIT_SWAPS = str.maketrans("01345", "oieas")


def brand_flags(host: str) -> tuple[str | None, str | None]:
    """Return (mismatched_brand, lookalike_brand) for a host.

    mismatch: a brand name appears in the host but the registered domain is not the brand's.
    lookalike: a host token is one edit (or a digit swap such as 0->o) away from a brand.
    """
    reg = registered_domain(host)
    tokens = [t for t in re.split(r"[.\-_]", host) if t]
    mismatch = lookalike = None
    for brand, official in BRANDS.items():
        if reg in official:
            continue
        exact = brand in tokens if len(brand) <= 4 else brand in host.replace("-", "")
        if exact:
            mismatch = mismatch or brand
            continue
        if len(brand) < 5:
            continue
        for token in tokens:
            # Common visual tricks: digits for letters (0->o, 4->a) and 'rn' for 'm'.
            if token.translate(_DIGIT_SWAPS).replace("rn", "m") == brand or (
                abs(len(token) - len(brand)) <= 1 and _edit_distance_le1(token, brand)
            ):
                lookalike = lookalike or brand
    return mismatch, lookalike


def extract(url: str) -> dict[str, float]:
    """Compute every feature in FEATURE_NAMES for one URL."""
    host, path, query = split(url)
    full = normalise(url)
    labels = [x for x in host.split(".") if x]
    reg = registered_domain(host)
    tld = labels[-1] if labels else ""
    is_ip = bool(_IP_RE.match(host))
    mismatch, lookalike = brand_flags(host) if not is_ip else (None, None)
    lowered = full.lower()
    hexish = sum(c in "0123456789abcdef" for c in path.lower())
    return {
        "url_len": float(len(full)),
        "host_len": float(len(host)),
        "path_len": float(len(path)),
        "query_len": float(len(query)),
        "n_dots_host": float(host.count(".")),
        "n_hyphens_host": float(host.count("-")),
        "n_subdomains": float(max(len(labels) - len(reg.split(".")), 0)) if not is_ip else 0.0,
        "n_digits": float(sum(c.isdigit() for c in full)),
        "digit_ratio": sum(c.isdigit() for c in full) / max(len(full), 1),
        "n_slashes": float(path.count("/")),
        "n_params": float(query.count("=")),
        "n_special": float(sum(c in "%&=_~+;!$*," for c in full)),
        "has_ip": float(is_ip),
        "has_at": float("@" in normalise(url).split("/", 1)[0]),
        "has_port": float(":" in normalise(url).split("/", 1)[0].rsplit("@", 1)[-1]),
        "has_punycode": float("xn--" in host),
        "entropy_host": _entropy(host),
        "entropy_path": _entropy(path + query),
        "tld_len": float(len(tld)),
        "tld_suspicious": float(tld in SUSPICIOUS_TLDS),
        "is_shortener": float(reg in SHORTENERS or host in SHORTENERS),
        "n_suspicious_words": float(sum(w in lowered for w in SUSPICIOUS_WORDS)),
        "brand_mismatch": float(mismatch is not None),
        "brand_lookalike": float(lookalike is not None),
        "longest_host_label": float(max((len(x) for x in labels), default=0)),
        "hex_ratio_path": hexish / max(len(path), 1),
    }


def to_vector(url: str) -> list[float]:
    """Feature values in FEATURE_NAMES order (the model's column order)."""
    feats = extract(url)
    return [feats[name] for name in FEATURE_NAMES]
