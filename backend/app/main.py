"""FastAPI entrypoint for JASUSI.

Run locally with: `cd backend && uvicorn app.main:app --reload`
"""

from fastapi import FastAPI

from app.api import health
from app.core.config import API_VERSION


def create_app() -> FastAPI:
    """Build the app. A factory keeps tests isolated from module-level state."""
    app = FastAPI(
        title="JASUSI API",
        description="Phishing and smishing shield for Kenya.",
        version=API_VERSION,
    )
    app.include_router(health.router, prefix="/v1")
    return app


app = create_app()
