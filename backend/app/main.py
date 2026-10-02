"""Main FastAPI application for AegisAI."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers.scan import router as scan_router


app = FastAPI(
    title=settings.app_name,
    description="AI Security Gateway for protecting LLM applications.",
    version="0.1.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(scan_router)


@app.get("/health")
def health_check() -> dict[str, str]:
    """Return the current health status of the API."""

    return {
        "status": "healthy",
        "service": settings.app_name,
        "environment": settings.app_env,
    }