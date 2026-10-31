"""Pydantic schemas for application health and readiness checks."""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class LivenessResponse(BaseModel):
    """Liveness probe confirmation that the ASGI process is responsive."""
    status: str = Field(default="alive", description="Process liveness indicator")
    timestamp: str = Field(default_factory=utc_now_iso, description="UTC timestamp of the probe")


class ReadinessResponse(BaseModel):
    """Readiness probe verifying operational state including database connectivity."""
    status: str = Field(..., description="Overall readiness: 'ready' or 'not_ready'")
    database: str = Field(..., description="Database connection state: 'connected' or 'disconnected'")
    timestamp: str = Field(default_factory=utc_now_iso, description="UTC timestamp of the probe")
    details: Optional[str] = Field(default=None, description="Diagnostic summary without sensitive details")


class ApiHealthResponse(BaseModel):
    """Standard REST API v1 health descriptor."""
    status: str = Field(default="healthy", description="API subsystem health")
    version: str = Field(..., description="Application semantic version")
    app_name: str = Field(..., description="Application branding title")
    timestamp: str = Field(default_factory=utc_now_iso, description="UTC timestamp of response")
