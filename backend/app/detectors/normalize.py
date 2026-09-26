"""Text normalization utilities for AegisAI detectors."""

import re
import unicodedata


ZERO_WIDTH_CHARS = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
MULTIPLE_SPACES = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """Normalize text before security detection."""

    normalized = unicodedata.normalize("NFKC", text)

    normalized = ZERO_WIDTH_CHARS.sub("", normalized)

    normalized = normalized.lower()

    normalized = MULTIPLE_SPACES.sub(" ", normalized)

    return normalized.strip()