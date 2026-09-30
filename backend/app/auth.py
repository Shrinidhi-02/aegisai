"""Authentication utilities for AegisAI."""

import hashlib
import secrets

from sqlalchemy.orm import Session

from app.db.models import APIKey


API_KEY_PREFIX = "aeg_"


def generate_api_key() -> str:
    """Generate a new random AegisAI API key."""

    random_part = secrets.token_urlsafe(32)

    return f"{API_KEY_PREFIX}{random_part}"


def hash_api_key(api_key: str) -> str:
    """Return the SHA-256 hash of an API key."""

    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def get_key_prefix(api_key: str) -> str:
    """Return a short safe prefix for identifying an API key."""

    return api_key[:12]


def create_api_key(db: Session, name: str) -> tuple[str, APIKey]:
    """Create an API key and store only its hash."""

    api_key = generate_api_key()

    record = APIKey(
        name=name,
        key_prefix=get_key_prefix(api_key),
        key_hash=hash_api_key(api_key),
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    return api_key, record

from fastapi import HTTPException, status
from sqlalchemy import select


def verify_api_key(db: Session, api_key: str) -> APIKey:
    """Verify an API key and return its database record."""

    key_hash = hash_api_key(api_key)

    statement = select(APIKey).where(
        APIKey.key_hash == key_hash,
        APIKey.is_active.is_(True),
    )

    record = db.execute(statement).scalar_one_or_none()

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive API key",
        )

    return record