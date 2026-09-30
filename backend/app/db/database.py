"""Database connection setup for AegisAI."""

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


DATABASE_PATH = Path(__file__).resolve().parents[3] / "aegisai.db"

DATABASE_URL = f"sqlite:///{DATABASE_PATH}"


class Base(DeclarativeBase):
    """Base class for all AegisAI database models."""

    pass


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)


SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)

def init_db() -> None:
    """Create all database tables."""

    from app.db import models  # noqa: F401

    Base.metadata.create_all(bind=engine)

def get_db():
    """Provide a database session to a FastAPI request."""

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()