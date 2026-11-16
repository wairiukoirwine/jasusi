"""Health router: lets clients, CI and the load balancer check the API is up."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.core.config import API_VERSION, Settings, get_settings
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(
    request: Request, settings: Annotated[Settings, Depends(get_settings)]
) -> HealthResponse:
    """Report liveness plus which models are loaded (rules = no trained model installed)."""
    pipeline = request.app.state.pipeline
    return HealthResponse(
        status="ok",
        version=API_VERSION,
        environment=settings.app_env,
        text_model=pipeline.text.model_version,
        url_model=pipeline.url.model_version,
        threat_intel_enabled=pipeline.intel.enabled,
    )
