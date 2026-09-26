"""Rule-based prompt injection and jailbreak detector."""

import re
from dataclasses import dataclass

from app.detectors.normalize import normalize_text


@dataclass(frozen=True)
class Rule:
    """Describe one injection-detection rule."""

    name: str
    pattern: re.Pattern[str]
    weight: int


RULES = [
    Rule(
        name="instruction_override",
        pattern=re.compile(
            r"\b(ignore|disregard|forget)\b.{0,30}"
            r"\b(previous|prior|above)\b.{0,20}"
            r"\b(instructions?|rules?|prompts?)\b",
            re.IGNORECASE,
        ),
        weight=40,
    ),
    Rule(
        name="system_prompt_extraction",
        pattern=re.compile(
            r"\b(reveal|show|print|repeat)\b.{0,30}"
            r"\b(system|hidden|initial)\s+prompt\b",
            re.IGNORECASE,
        ),
        weight=35,
    ),
    Rule(
        name="roleplay_jailbreak",
        pattern=re.compile(
            r"\b(you are now|pretend to be|act as)\b.{0,40}"
            r"\b(no (rules|restrictions)|dan)\b",
            re.IGNORECASE,
        ),
        weight=25,
    ),
    Rule(
        name="policy_bypass",
        pattern=re.compile(
            r"\b(for educational purposes only|"
            r"this is a test.{0,30}(ignore|bypass).{0,20}safety)\b",
            re.IGNORECASE,
        ),
        weight=20,
    ),
    Rule(
        name="delimiter_tricks",
        pattern=re.compile(
            r"(?m)^\s*(system|assistant|developer)\s*:"
            r"|<\s*/?\s*(system|assistant|prompt)\s*>",
            re.IGNORECASE,
        ),
        weight=20,
    ),
]


def scan_rules(text: str) -> tuple[int, list[str]]:
    """Scan text and return a capped risk score and matched rule names."""

    normalized = normalize_text(text)

    score = 0
    hits: list[str] = []

    for rule in RULES:
        if rule.pattern.search(normalized):
            hits.append(rule.name)
            score += rule.weight

    return min(score, 100), hits