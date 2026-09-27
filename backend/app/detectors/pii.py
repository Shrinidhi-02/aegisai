"""PII and secret detection with safe redaction."""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PiiMatch:
    """Represent one detected sensitive value."""

    type: str
    value: str
    replacement: str


EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

INDIAN_MOBILE_PATTERN = re.compile(
    r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"
)

PAN_PATTERN = re.compile(
    r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    re.IGNORECASE,
)

CARD_PATTERN = re.compile(
    r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"
)

AWS_ACCESS_KEY_PATTERN = re.compile(
    r"\bAKIA[0-9A-Z]{16}\b"
)

GITHUB_TOKEN_PATTERN = re.compile(
    r"\bghp_[A-Za-z0-9]{36}\b"
)

GENERIC_API_KEY_PATTERN = re.compile(
    r"\b(?:sk|api|key)[-_][A-Za-z0-9_-]{20,}\b",
    re.IGNORECASE,
)

JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\."
    r"[A-Za-z0-9_-]+\."
    r"[A-Za-z0-9_-]+\b"
)

PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)

PASSWORD_PATTERN = re.compile(
    r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*\S+"
)


def luhn_ok(number: str) -> bool:
    """Return True when a card number passes the Luhn checksum."""

    digits = [int(char) for char in number if char.isdigit()]

    if not 13 <= len(digits) <= 19:
        return False

    total = 0

    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2

            if digit > 9:
                digit -= 9

        total += digit

    return total % 10 == 0


def redact_pii(text: str) -> str:
    """Detect supported PII/secrets and replace them with safe labels."""

    result = text

    result = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", result)

    result = INDIAN_MOBILE_PATTERN.sub("[REDACTED_MOBILE]", result)

    result = PAN_PATTERN.sub("[REDACTED_PAN]", result)

    result = AWS_ACCESS_KEY_PATTERN.sub("[REDACTED_AWS_KEY]", result)

    result = GITHUB_TOKEN_PATTERN.sub("[REDACTED_GITHUB_TOKEN]", result)

    result = GENERIC_API_KEY_PATTERN.sub("[REDACTED_API_KEY]", result)

    result = JWT_PATTERN.sub("[REDACTED_JWT]", result)

    result = PRIVATE_KEY_PATTERN.sub("[REDACTED_PRIVATE_KEY]", result)

    result = PASSWORD_PATTERN.sub("[REDACTED_PASSWORD]", result)

    def replace_card(match: re.Match[str]) -> str:
        """Replace only card-like numbers that pass Luhn validation."""

        value = match.group(0)

        if luhn_ok(value):
            return "[REDACTED_CARD]"

        return value

    result = CARD_PATTERN.sub(replace_card, result)

    return result