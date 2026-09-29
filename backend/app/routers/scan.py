"""API endpoints for scanning AI input and output."""

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.detectors.injection import scan_rules
from app.detectors.ml import ml_score
from app.detectors.pii import redact_pii
from app.policy.engine import build_decision
from app.policy.schemas import Threat


router = APIRouter(
    prefix="/api/v1",
    tags=["scanning"],
)


class ScanRequest(BaseModel):
    """Request body for a text scan."""

    text: str = Field(min_length=1)
    user_id: str | None = None
    session_id: str | None = None
    mode: str = "prompt"


class ScanResponse(BaseModel):
    """Response returned after scanning text."""

    allowed: bool
    action: str
    risk_score: int = Field(ge=0, le=100)
    threats: list[dict]
    sanitized_text: str | None = None


@router.post("/scan-input", response_model=ScanResponse)
def scan_input(request: ScanRequest) -> ScanResponse:
    """Scan a user prompt before it reaches an AI model."""

    rule_score, rule_hits = scan_rules(request.text)

    model_score = ml_score(request.text)

    sanitized_text = redact_pii(request.text)
    has_pii = sanitized_text != request.text

    threats = [
        Threat(
            type=rule_name,
            severity="high",
            confidence=0.90,
        )
        for rule_name in rule_hits
    ]

    if has_pii:
        threats.append(
            Threat(
                type="pii",
                severity="high",
                confidence=0.95,
            )
        )

    decision = build_decision(
        rule_score=rule_score,
        ml_score=model_score,
        threats=threats,
        has_pii=has_pii,
        sanitized_text=sanitized_text,
    )

    return ScanResponse(
        allowed=decision.allowed,
        action=decision.action,
        risk_score=decision.risk_score,
        threats=[threat.model_dump() for threat in decision.threats],
        sanitized_text=decision.sanitized_text,
    )

@router.post("/scan-output", response_model=ScanResponse)
def scan_output(request: ScanRequest) -> ScanResponse:
    """Scan an AI model response before it reaches the user."""

    rule_score, rule_hits = scan_rules(request.text)

    model_score = ml_score(request.text)

    sanitized_text = redact_pii(request.text)
    has_pii = sanitized_text != request.text

    threats = [
        Threat(
            type=rule_name,
            severity="high",
            confidence=0.90,
        )
        for rule_name in rule_hits
    ]

    if has_pii:
        threats.append(
            Threat(
                type="pii",
                severity="high",
                confidence=0.95,
            )
        )

    decision = build_decision(
        rule_score=rule_score,
        ml_score=model_score,
        threats=threats,
        has_pii=has_pii,
        sanitized_text=sanitized_text,
    )

    return ScanResponse(
        allowed=decision.allowed,
        action=decision.action,
        risk_score=decision.risk_score,
        threats=[threat.model_dump() for threat in decision.threats],
        sanitized_text=decision.sanitized_text,
    )