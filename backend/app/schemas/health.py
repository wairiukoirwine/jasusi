"""Response model for the health endpoint."""

from typing import Literal

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Liveness report, including which detector versions are serving."""

    status: Literal["ok"]
    version: str
    environment: str
    text_model: str
    url_model: str
    threat_intel_enabled: bool
