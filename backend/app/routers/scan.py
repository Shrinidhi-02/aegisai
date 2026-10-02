"""API endpoints for scanning AI input and output."""

from time import perf_counter
from uuid import uuid4

from fastapi import APIRouter, Depends, Request
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.alerts.service import create_alert
from app.auth import verify_api_key
from app.db.database import get_db
from app.db.models import APIKey, AuditLog
from app.detectors.injection import scan_rules
from app.detectors.ml import ml_score
from app.detectors.pii import redact_pii
from app.policy.engine import build_decision
from app.policy.schemas import Threat
from app.rate_limit import check_rate_limit


router = APIRouter(
    prefix="/api/v1",
    tags=["scanning"],
)


api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=True,
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


def authenticate_api_key(
    api_key: str = Depends(api_key_header),
    db: Session = Depends(get_db),
) -> APIKey:
    """Authenticate the request using the supplied API key."""

    return verify_api_key(db, api_key)


def get_client_identifier(
    request: Request,
    api_key_record: APIKey = Depends(authenticate_api_key),
) -> str:
    """Return a stable identifier for rate limiting."""

    client_ip = request.client.host if request.client else "unknown"

    return f"{api_key_record.id}:{client_ip}"


def create_audit_log(
    db: Session,
    request: ScanRequest,
    request_id: str,
    direction: str,
    risk_score: int,
    action: str,
    threats: list[Threat],
    sanitized_text: str | None,
    source_ip: str,
    latency_ms: float,
) -> None:
    """Store a security audit record without saving raw sensitive text."""

    threat_types = ",".join(
        threat.type for threat in threats
    )

    log = AuditLog(
        request_id=request_id,
        action=action,
        risk_score=risk_score,
        threat_types=threat_types,
        user_id=request.user_id,
        session_id=request.session_id,
    )

    db.add(log)
    db.commit()


@router.post("/scan-input", response_model=ScanResponse)
def scan_input(
    request: ScanRequest,
    http_request: Request,
    identifier: str = Depends(get_client_identifier),
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Scan a user prompt before it reaches an AI model."""

    start_time = perf_counter()

    check_rate_limit(identifier)

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

    alert = create_alert(
        action=decision.action,
        risk_score=decision.risk_score,
        threats=[threat.type for threat in decision.threats],
    )

    if alert:
        print(alert.message)

    request_id = str(uuid4())

    source_ip = (
        http_request.client.host
        if http_request.client
        else "unknown"
    )

    latency_ms = (perf_counter() - start_time) * 1000

    create_audit_log(
        db=db,
        request=request,
        request_id=request_id,
        direction="input",
        risk_score=decision.risk_score,
        action=decision.action,
        threats=decision.threats,
        sanitized_text=decision.sanitized_text,
        source_ip=source_ip,
        latency_ms=latency_ms,
    )

    return ScanResponse(
        allowed=decision.allowed,
        action=decision.action,
        risk_score=decision.risk_score,
        threats=[
            threat.model_dump()
            for threat in decision.threats
        ],
        sanitized_text=decision.sanitized_text,
    )


@router.post("/scan-output", response_model=ScanResponse)
def scan_output(
    request: ScanRequest,
    http_request: Request,
    identifier: str = Depends(get_client_identifier),
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Scan an AI model response before it reaches the user."""

    start_time = perf_counter()

    check_rate_limit(identifier)

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

    alert = create_alert(
        action=decision.action,
        risk_score=decision.risk_score,
        threats=[threat.type for threat in decision.threats],
    )

    if alert:
        print(alert.message)

    request_id = str(uuid4())

    source_ip = (
        http_request.client.host
        if http_request.client
        else "unknown"
    )

    latency_ms = (perf_counter() - start_time) * 1000

    create_audit_log(
        db=db,
        request=request,
        request_id=request_id,
        direction="output",
        risk_score=decision.risk_score,
        action=decision.action,
        threats=decision.threats,
        sanitized_text=decision.sanitized_text,
        source_ip=source_ip,
        latency_ms=latency_ms,
    )

    return ScanResponse(
        allowed=decision.allowed,
        action=decision.action,
        risk_score=decision.risk_score,
        threats=[
            threat.model_dump()
            for threat in decision.threats
        ],
        sanitized_text=decision.sanitized_text,
    )


@router.get("/audit-logs")
def get_audit_logs(
    db: Session = Depends(get_db),
    identifier: str = Depends(get_client_identifier),
) -> list[dict]:
    """Return recent security audit logs for the dashboard."""

    check_rate_limit(identifier)

    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.id.desc())
        .limit(20)
        .all()
    )

    return [
        {
            "id": log.id,
            "request_id": log.request_id,
            "action": log.action,
            "risk_score": log.risk_score,
            "threat_types": log.threat_types,
            "user_id": log.user_id,
            "session_id": log.session_id,
            "created_at": log.created_at.isoformat(),
        }
        for log in logs
    ]