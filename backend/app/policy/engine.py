"""Policy engine for combining detector results into a security decision."""

from app.policy.schemas import PolicyDecision, Threat


def calculate_risk_score(
    rule_score: int,
    ml_score: int,
    extra_threat_categories: int = 0,
) -> int:
    """Calculate the final AegisAI risk score."""

    risk = (
        0.6 * rule_score
        + 0.4 * ml_score
        + 5 * extra_threat_categories
    )

    return min(100, round(risk))


def decide_action(
    risk_score: int,
    has_pii: bool = False,
    block_threshold: int = 70,
    warn_threshold: int = 40,
) -> str:
    """Choose an action from the risk score and detector results."""

    if has_pii:
        return "redact"

    if risk_score >= block_threshold:
        return "block"

    if risk_score >= warn_threshold:
        return "warn"

    return "allow"


def build_decision(
    rule_score: int,
    ml_score: int,
    threats: list[Threat] | None = None,
    has_pii: bool = False,
    block_threshold: int = 70,
    warn_threshold: int = 40,
    sanitized_text: str | None = None,
) -> PolicyDecision:
    """Build the final policy decision."""

    threats = threats or []

    extra_categories = len({threat.type for threat in threats})

    risk_score = calculate_risk_score(
        rule_score=rule_score,
        ml_score=ml_score,
        extra_threat_categories=extra_categories,
    )

    action = decide_action(
        risk_score=risk_score,
        has_pii=has_pii,
        block_threshold=block_threshold,
        warn_threshold=warn_threshold,
    )

    return PolicyDecision(
        allowed=action != "block",
        action=action,
        risk_score=risk_score,
        threats=threats,
        sanitized_text=sanitized_text,
    )