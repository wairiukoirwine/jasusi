"""Response model for the health endpoint."""

from typing import Literal

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Liveness report. Dependency checks (db, redis) are added when those arrive."""

    status: Literal["ok"]
    version: str
    environment: str
