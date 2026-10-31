"""Tests for application health and readiness probe endpoints."""

import pytest
from starlette.testclient import TestClient
from sqlalchemy import create_engine
from app.database import get_db
from app.main import create_app
from app.config import Settings


def test_liveness_endpoint_returns_200(client: TestClient):
    """Requirement 1: Verify successful liveness response confirms process is active."""
    response = client.get("/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "alive"
    assert "timestamp" in data


def test_readiness_endpoint_successful_when_db_available(client: TestClient):
    """Requirement 2: Verify successful readiness response when database is connected."""
    response = client.get("/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["database"] == "connected"
    assert data["details"] == "Database operational."


def test_readiness_endpoint_fails_503_when_db_unavailable(test_settings: Settings):
    """Requirement 3: Verify readiness failure (HTTP 503) when database is unavailable."""
    # Point to a broken/invalid database engine
    broken_engine = create_engine("sqlite:///nonexistent_dir/forbidden_path/invalid.db")
    
    app = create_app(settings=test_settings)
    
    # Override get_db with a session bound to the broken engine
    from sqlalchemy.orm import sessionmaker
    BrokenSession = sessionmaker(bind=broken_engine)

    def broken_get_db():
        session = BrokenSession()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = broken_get_db

    with TestClient(app, raise_server_exceptions=False) as broken_client:
        response = broken_client.get("/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["error"]["status_code"] == 503
        detail = data["error"]["message"]
        assert detail["status"] == "not_ready"
        assert detail["database"] == "disconnected"
        # Ensure no sensitive system file path or credentials leaked
        assert "forbidden_path" not in str(data)

    app.dependency_overrides.clear()
    broken_engine.dispose()


def test_api_v1_health_descriptor(client: TestClient, test_settings: Settings):
    """Requirement 4: Verify JSON API v1 health endpoint metadata."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == test_settings.APP_VERSION
    assert data["app_name"] == test_settings.APP_NAME
    assert "timestamp" in data
