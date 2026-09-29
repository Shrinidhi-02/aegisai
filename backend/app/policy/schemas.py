"""Schemas used by the AegisAI policy engine."""

from pydantic import BaseModel, Field


class Threat(BaseModel):
    """Describe one security finding."""

    type: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)


class PolicyDecision(BaseModel):
    """Final decision returned by the policy engine."""

    allowed: bool
    action: str
    risk_score: int = Field(ge=0, le=100)
    threats: list[Threat] = []
    sanitized_text: str | None = None