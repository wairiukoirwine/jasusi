"""FastAPI entrypoint for JASUSI.

Run locally from the repo root:  uvicorn app.main:app --app-dir backend --reload
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api import feedback, health, scan, stats
from app.core.cache import build_cache
from app.core.config import API_VERSION, REPO_ROOT, Settings, get_settings
from app.db.session import make_session_factory
from app.detectors.text_detector import TextDetector
from app.detectors.threat_intel import ThreatIntel
from app.detectors.url_detector import UrlDetector
from app.engine.pipeline import ScanPipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def build_pipeline(settings: Settings, cache) -> ScanPipeline:
    return ScanPipeline(
        settings,
        TextDetector(settings.resolve(settings.text_model_path)),
        UrlDetector(settings.resolve(settings.url_model_path)),
        ThreatIntel(settings, cache),
    )


def create_app(settings: Settings | None = None, dashboard_dir: Path | None = None) -> FastAPI:
    """Build the app. A factory keeps tests isolated from module-level state."""
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        await app.state.pipeline.intel.aclose()

    app = FastAPI(
        title="JASUSI API",
        description="Phishing and smishing shield for Kenya. Risk guidance, not a guarantee.",
        version=API_VERSION,
        lifespan=lifespan,
    )
    app.state.session_factory = make_session_factory(settings.database_url)  # creates tables
    app.state.cache = build_cache(settings.redis_url)
    app.state.pipeline = build_pipeline(settings, app.state.cache)
    app.dependency_overrides[get_settings] = lambda: settings

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Key"],
    )

    @app.middleware("http")
    async def limits_and_headers(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.max_body_bytes:
            return JSONResponse({"detail": "Request body too large"}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    for router in (health.router, scan.router, feedback.router, stats.router):
        app.include_router(router, prefix="/v1")

    # Serve the built dashboard (npm run build) at / when it exists; the API lives under /v1.
    dist = dashboard_dir or REPO_ROOT / "dashboard" / "dist"
    if dist.is_dir():
        app.mount("/", StaticFiles(directory=dist, html=True), name="dashboard")
    return app


app = create_app()
