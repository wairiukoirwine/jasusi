"""Anonymiser: phones, e-mails, IDs and context-detected names are masked; amounts are kept."""

from app.extract.anonymise import anonymise


def test_masks_phone_numbers_in_all_formats() -> None:
    out = anonymise("Tuma kwa 0712345678 au +254 733 111 222")
    assert "0712345678" not in out and "733" not in out
    assert out.count("<PHONE>") == 2


def test_keeps_amounts() -> None:
    out = anonymise("Nimekutumia Ksh 3,500 kimakosa, rudisha 3500 kwa 0712345678")
    assert "Ksh 3,500" in out and "3500" in out


def test_masks_mpesa_counterparty_name() -> None:
    out = anonymise("Ksh1,200.00 sent to JOHN KAMAU 0722000111 on 3/11/26")
    assert "JOHN" not in out and "KAMAU" not in out
    assert "sent to <NAME> <PHONE>" in out


def test_masks_greeting_and_jina_names() -> None:
    assert anonymise("Dear Wanjiku, your parcel is ready") == "Dear <NAME>, your parcel is ready"
    assert "PETER" not in anonymise("namba hii ya Airtel. jina (PETER NYANGE)")


def test_does_not_mask_generic_greetings_or_brands() -> None:
    assert anonymise("Dear Customer, welcome") == "Dear Customer, welcome"
    assert anonymise("Ksh500 paid to SAFARICOM LIMITED") == "Ksh500 paid to SAFARICOM LIMITED"


def test_masks_ids_and_emails() -> None:
    out = anonymise("ID No: 31234567, KRA PIN A012345678Z, email jane@example.com")
    assert "31234567" not in out and "A012345678Z" not in out and "jane@" not in out
    assert out.count("<ID>") == 2 and "<EMAIL>" in out
