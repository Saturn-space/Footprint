"""API routers export."""

from app.api.health import router as health_router
from app.api.investigations import router as investigations_router

__all__ = ["health_router", "investigations_router"]
