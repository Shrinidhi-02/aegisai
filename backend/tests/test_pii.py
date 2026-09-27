"""Tests for PII and secret redaction."""

from app.detectors.pii import luhn_ok, redact_pii


def test_credit_card_redacted():
    """A valid test card number should be redacted."""

    result = redact_pii(
        "card 4111 1111 1111 1111"
    )

    assert "4111" not in result
    assert "[REDACTED_CARD]" in result


def test_email_redacted():
    """An email address should be redacted."""

    result = redact_pii(
        "Contact test@example.com for help."
    )

    assert "test@example.com" not in result
    assert "[REDACTED_EMAIL]" in result


def test_invalid_card_number_not_redacted():
    """A number that fails Luhn should not be treated as a card."""

    result = redact_pii(
        "Reference number 4111 1111 1111 1112"
    )

    assert "4111 1111 1111 1112" in result


def test_luhn_validation():
    """Verify the Luhn validator with test values."""

    assert luhn_ok("4111 1111 1111 1111")
    assert not luhn_ok("4111 1111 1111 1112")


def test_mobile_redacted():
    """An Indian mobile number should be redacted."""

    result = redact_pii(
        "Call me at 9876543210."
    )

    assert "9876543210" not in result
    assert "[REDACTED_MOBILE]" in result


def test_pan_redacted():
    """A PAN-format value should be redacted."""

    result = redact_pii(
        "PAN: ABCDE1234F"
    )

    assert "ABCDE1234F" not in result
    assert "[REDACTED_PAN]" in result


def test_api_key_redacted():
    """A dummy API-key-shaped value should be redacted."""

    result = redact_pii(
        "key: sk-test_abcdefghijklmnopqrstuvwxyz"
    )

    assert "sk-test_abcdefghijklmnopqrstuvwxyz" not in result
    assert "[REDACTED_API_KEY]" in result