"""Tests for SQLAlchemy database session lifecycle and model constraints."""

import pytest
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.database import get_db, check_database_connection
from app.models.investigation import InvestigationModel


def test_database_connection_probe(test_engine):
    """Verify check_database_connection probe returns True on active engine."""
    is_ok, msg = check_database_connection(engine_override=test_engine)
    assert is_ok is True
    assert "operational" in msg.lower()


def test_database_session_lifecycle(test_engine):
    """Requirement 6: Verify database session creation, rollback, and cleanup."""
    from sqlalchemy.orm import sessionmaker
    SessionFactory = sessionmaker(bind=test_engine)
    session = SessionFactory()

    try:
        inv = InvestigationModel(
            id="inv-temp-01",
            name="Temporary Rollback Test",
            organization_name="Test Org",
            description="Testing rollback",
            lead_investigator="Tester",
            team_members=[],
            owned_domains=["test.example"],
            approved_ips=[],
            approved_cidrs=[],
            active_targets=[]
        )
        session.add(inv)
        session.flush()
        assert session.get(InvestigationModel, "inv-temp-01") is not None
        session.rollback()
        # After rollback, record should not exist
        assert session.get(InvestigationModel, "inv-temp-01") is None
    finally:
        session.close()


def test_investigation_model_constraints_and_defaults(db_session: Session):
    """Requirement 8: Verify InvestigationModel fields, defaults, timestamps, and JSON serialization."""
    inv = InvestigationModel(
        id="inv-model-01",
        name="Model Constraint Validation",
        organization_name="Cybersecurity Research Group",
        description="Verifying default values and serialization.",
        lead_investigator="Dr. Marcus Vance",
        team_members=["Analyst One", "Analyst Two"],
        owned_domains=["research.example", "sub.research.example"],
        approved_ips=["192.168.1.10"],
        approved_cidrs=["192.168.1.0/24"],
        active_targets=["192.168.1.10"]
    )
    db_session.add(inv)
    db_session.commit()
    db_session.refresh(inv)

    # Verify defaults
    assert inv.status == "active"
    assert inv.active_scanning_enabled is False
    assert isinstance(inv.created_at, datetime)
    assert isinstance(inv.updated_at, datetime)

    # Verify to_dict serialization
    serialized = inv.to_dict()
    assert serialized["id"] == "inv-model-01"
    assert serialized["organization_name"] == "Cybersecurity Research Group"
    assert len(serialized["team_members"]) == 2
    assert "research.example" in serialized["scope"]["owned_domains"]


def test_investigation_model_primary_key_uniqueness(db_session: Session):
    """Verify primary key constraint prevents duplicate investigation IDs."""
    inv1 = InvestigationModel(
        id="inv-duplicate-test",
        name="Original",
        organization_name="Org",
        description="Desc",
        lead_investigator="Lead",
        team_members=[],
        owned_domains=[],
        approved_ips=[],
        approved_cidrs=[],
        active_targets=[]
    )
    db_session.add(inv1)
    db_session.commit()
    db_session.expunge(inv1)

    inv2 = InvestigationModel(
        id="inv-duplicate-test",  # Same ID
        name="Duplicate",
        organization_name="Org",
        description="Desc",
        lead_investigator="Lead",
        team_members=[],
        owned_domains=[],
        approved_ips=[],
        approved_cidrs=[],
        active_targets=[]
    )
    db_session.add(inv2)

    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
