"""Automated tests for target authorization verification, scope validation, and audit recording."""

import pytest
from datetime import datetime, timezone, timedelta
from app.models.investigation import InvestigationModel
from app.models.recon import TargetAuthorizationModel
from app.models.user import UserModel
from app.services.target_authorization import (
    classify_target,
    is_target_in_investigation_scope,
    verify_target_authorization,
)
from app.core.security import hash_password


def test_classify_target():
    assert classify_target("192.168.1.1") == "IP"
    assert classify_target("2001:db8::1") == "IP"
    assert classify_target("10.0.0.0/24") == "CIDR"
    assert classify_target("example.com") == "DOMAIN"
    assert classify_target("sub.target.co.uk") == "DOMAIN"
    assert classify_target("https://example.com/test") == "UNKNOWN"


def test_scope_membership(db_session):
    inv = InvestigationModel(
        id="inv-scope-test",
        name="Scope Test Campaign",
        organization_name="Acme Corp",
        description="Testing scope boundaries",
        lead_investigator="Lead",
        owned_domains=["acme.com", "api.acme.com"],
        approved_ips=["198.51.100.1"],
        approved_cidrs=["203.0.113.0/24"],
        active_targets=["portal.acme.com"],
    )

    # In scope
    assert is_target_in_investigation_scope(inv, "acme.com")[0] is True
    assert is_target_in_investigation_scope(inv, "sub.acme.com")[0] is True
    assert is_target_in_investigation_scope(inv, "api.acme.com")[0] is True
    assert is_target_in_investigation_scope(inv, "198.51.100.1")[0] is True
    assert is_target_in_investigation_scope(inv, "203.0.113.55")[0] is True
    assert is_target_in_investigation_scope(inv, "portal.acme.com")[0] is True

    # Out of scope
    assert is_target_in_investigation_scope(inv, "evilcorp.com")[0] is False
    assert is_target_in_investigation_scope(inv, "acme.com.attacker.org")[0] is False
    assert is_target_in_investigation_scope(inv, "198.51.100.2")[0] is False
    assert is_target_in_investigation_scope(inv, "192.168.1.1")[0] is False


def test_target_authorization_validation_logic(db_session):
    now = datetime.now(timezone.utc)
    inv = InvestigationModel(
        id="inv-auth-test-1",
        name="Auth Test Campaign",
        organization_name="Target Org",
        description="Testing authorization records",
        lead_investigator="Lead",
        owned_domains=["authorized.com"],
        approved_ips=[],
        approved_cidrs=[],
        active_targets=["authorized.com"],
    )
    db_session.add(inv)

    user = UserModel(
        id="usr-recon-1",
        username="recon_analyst",
        email="analyst@footprintiq.local",
        password_hash=hash_password("AnalystPassword123!"),
        role="analyst",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    # 1. Target out of scope -> denied
    authorized, reason = verify_target_authorization(
        db=db_session,
        investigation=inv,
        target="unauthorized-domain.org",
        operation="RECON_PASSIVE",
        actor_user=user,
    )
    assert authorized is False
    assert "scope" in reason.lower()

    # 2. In scope, but no authorization record -> denied
    authorized, reason = verify_target_authorization(
        db=db_session,
        investigation=inv,
        target="authorized.com",
        operation="RECON_PASSIVE",
        actor_user=user,
    )
    assert authorized is False
    assert "no valid administrative authorization" in reason.lower()

    # 3. Create valid authorization record
    auth_rec = TargetAuthorizationModel(
        id="auth-rec-1",
        investigation_id=inv.id,
        target="authorized.com",
        target_type="DOMAIN",
        allowed_operations=["RECON_PASSIVE"],
        authorization_reference="AUTH-RO-2026-001",
        approved_by="CISO Admin",
        valid_from=now - timedelta(days=1),
        valid_to=now + timedelta(days=30),
        is_revoked=False,
    )
    db_session.add(auth_rec)
    db_session.commit()

    authorized, reason = verify_target_authorization(
        db=db_session,
        investigation=inv,
        target="authorized.com",
        operation="RECON_PASSIVE",
        actor_user=user,
    )
    assert authorized is True
    assert "record" in reason.lower() or "authorized" in reason.lower()

    # 4. Expired authorization record -> denied
    auth_rec.valid_to = now - timedelta(hours=1)
    db_session.commit()

    authorized, reason = verify_target_authorization(
        db=db_session,
        investigation=inv,
        target="authorized.com",
        operation="RECON_PASSIVE",
        actor_user=user,
    )
    assert authorized is False
    assert "expired" in reason.lower()

    # 5. Revoked authorization record -> denied
    auth_rec.valid_to = now + timedelta(days=30)
    auth_rec.is_revoked = True
    db_session.commit()

    authorized, reason = verify_target_authorization(
        db=db_session,
        investigation=inv,
        target="authorized.com",
        operation="RECON_PASSIVE",
        actor_user=user,
    )
    assert authorized is False
    assert "revoked" in reason.lower()

    # 6. Active scanning operation requested when record only permits passive -> denied
    auth_rec.is_revoked = False
    auth_rec.allowed_operations = ["RECON_PASSIVE"]
    db_session.commit()

    authorized, reason = verify_target_authorization(
        db=db_session,
        investigation=inv,
        target="authorized.com",
        operation="SCAN_ACTIVE",
        actor_user=user,
    )
    assert authorized is False
    assert "not permitted" in reason.lower()
