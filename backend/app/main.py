"""Main FastAPI application for AegisAI."""

from fastapi import FastAPI

from app.config import settings


app = FastAPI(
    title=settings.app_name,
    description="AI Security Gateway for protecting LLM applications.",
    version="0.1.0",
)


@app.get("/health")
def health_check() -> dict[str, str]:
    """Return the current health status of the API."""

    return {
        "status": "healthy",
        "service": settings.app_name,
        "environment": settings.app_env,
    }