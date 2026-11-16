"""IOC extraction and masking."""

from app.extract.iocs import defang, extract_iocs, mask_email, mask_phone


def test_extracts_urls_with_and_without_scheme() -> None:
    iocs = extract_iocs(
        "Visit http://kra-verify.xyz/login now or www.example.com, also bit.ly/abc."
    )
    assert iocs.urls == ["http://kra-verify.xyz/login", "www.example.com", "bit.ly/abc"]


def test_does_not_treat_ordinary_text_as_url() -> None:
    assert extract_iocs("Meet Mr.John at 3.30pm e.g tomorrow. Ksh1,200.00 paid.").urls == []


def test_kenyan_phones_are_normalised() -> None:
    iocs = extract_iocs("Call 0712 345 678 or +254 733-111-222 or 0110123456 or 254722000111")
    assert iocs.phones == ["+254712345678", "+254733111222", "+254110123456", "+254722000111"]


def test_long_digit_runs_are_not_phones() -> None:
    assert extract_iocs("Token 07123456789012345678").phones == []


def test_paybill_and_till_numbers() -> None:
    iocs = extract_iocs(
        "Pay via paybill 522522 account 1234 or Till No. 891234. Lipa na M-PESA 174379"
    )
    assert iocs.paybills == ["522522", "891234", "174379"]


def test_emails_are_separate_from_urls() -> None:
    iocs = extract_iocs("Write to hr@jobs-kenya.com today")
    assert iocs.emails == ["hr@jobs-kenya.com"]
    assert iocs.urls == []


def test_masking_helpers() -> None:
    assert mask_phone("+254712345678") == "0712xxxxxx"
    assert mask_email("jane.doe@example.com") == "j***@example.com"
    assert defang("http://bad.example.com/x") == "hxxp://bad[.]example[.]com/x"
