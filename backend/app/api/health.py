"""Health router: lets clients, CI and the load balancer check the API is up."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.config import API_VERSION, Settings, get_settings
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(settings: Annotated[Settings, Depends(get_settings)]) -> HealthResponse:
    """Report that the process is alive, with its version and environment."""
    return HealthResponse(status="ok", version=API_VERSION, environment=settings.app_env)
