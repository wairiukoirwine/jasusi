"""URL feature extraction (shared by training and inference)."""

from ml.features import url_features as uf


def test_vector_matches_feature_names() -> None:
    assert len(uf.to_vector("http://example.com/a?b=1")) == len(uf.FEATURE_NAMES)
    assert set(uf.extract("example.com")) == set(uf.FEATURE_NAMES)


def test_scheme_and_www_do_not_change_features() -> None:
    assert uf.extract("https://www.example.com/path") == uf.extract("example.com/path")


def test_registered_domain_handles_kenyan_suffixes() -> None:
    assert uf.registered_domain("secure.login.safaricom.co.ke") == "safaricom.co.ke"
    assert uf.registered_domain("a.b.example.com") == "example.com"
    assert uf.registered_domain("kra.go.ke") == "kra.go.ke"


def test_brand_on_foreign_domain_is_flagged() -> None:
    assert uf.extract("http://safaricom-rewards.top/claim")["brand_mismatch"] == 1.0
    assert uf.extract("http://kra-itax.verify-now.com")["brand_mismatch"] == 1.0
    assert uf.extract("https://www.safaricom.co.ke/personal")["brand_mismatch"] == 0.0
    assert uf.extract("https://okra-recipes.com")["brand_mismatch"] == 0.0


def test_lookalike_spelling_is_flagged() -> None:
    assert uf.extract("http://saf4ricom.com/login")["brand_lookalike"] == 1.0
    assert uf.extract("http://safaricorn.co.ke")["brand_lookalike"] == 1.0
    assert uf.extract("http://example.com")["brand_lookalike"] == 0.0


def test_ip_shortener_and_tld_flags() -> None:
    assert uf.extract("http://192.168.10.5/mpesa")["has_ip"] == 1.0
    assert uf.extract("bit.ly/3abc")["is_shortener"] == 1.0
    assert uf.extract("promo.xyz")["tld_suspicious"] == 1.0


def test_trusted_host_is_exact_match_only() -> None:
    assert uf.is_trusted_host("https://www.kra.go.ke/individual")
    assert not uf.is_trusted_host("https://sites.google.com/view/mpesa-promo")
    assert not uf.is_trusted_host("https://kra.go.ke.evil.com")
