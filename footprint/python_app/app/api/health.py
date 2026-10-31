"""Health and readiness probe endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.config import get_settings
from app.database import get_db, check_database_connection
from app.schemas.health import LivenessResponse, ReadinessResponse, ApiHealthResponse
from app.logging_config import get_logger

logger = get_logger("footprintiq.api.health")

router = APIRouter(tags=["Health & Diagnostics"])


@router.get(
    "/health/live",
    response_model=LivenessResponse,
    summary="Liveness Probe",
    description="Confirms that the application process is running and able to handle HTTP requests."
)
def get_liveness():
    """Returns 200 OK if the ASGI process is active."""
    return LivenessResponse(status="alive")


@router.get(
    "/health/ready",
    response_model=ReadinessResponse,
    responses={
        200: {"description": "Application and required database are operational."},
        503: {"description": "Application dependencies are unavailable."}
    },
    summary="Readiness Probe",
    description="Verifies the operational status of the application and its required database connection."
)
def get_readiness(db: Session = Depends(get_db)):
    """Verifies that the database engine can execute queries successfully."""
    is_connected, message = check_database_connection(db)

    if not is_connected:
        logger.error(f"Readiness check failed: {message}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "not_ready",
                "database": "disconnected",
                "details": "Database connection probe failed. Check database configuration."
            }
        )

    return ReadinessResponse(
        status="ready",
        database="connected",
        details="Database operational."
    )


@router.get(
    "/api/v1/health",
    response_model=ApiHealthResponse,
    summary="API v1 Health Descriptor",
    description="Returns metadata about the active API runtime."
)
def get_api_health(request: Request):
    """Returns simple JSON status and semantic application version."""
    settings = getattr(request.app.state, "settings", get_settings())
    return ApiHealthResponse(
        status="healthy",
        version=settings.APP_VERSION,
        app_name=settings.APP_NAME
    )
