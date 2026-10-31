"""Tests verifying Alembic schema migrations on a fresh temporary database."""

import os
from pathlib import Path
from alembic.config import Config
from alembic import command
from sqlalchemy import create_engine, inspect


def test_alembic_fresh_database_initialization(tmp_path):
    """Requirement 7: Verify a fresh database can be initialized and rolled back through migrations."""
    db_file = tmp_path / "fresh_migration_test.db"
    db_url = f"sqlite:///{db_file}"

    # Configure Alembic with dynamic test database URL
    python_app_dir = Path(__file__).resolve().parent.parent
    alembic_ini_path = python_app_dir / "alembic.ini"
    
    alembic_cfg = Config(str(alembic_ini_path))
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    alembic_cfg.set_main_option("script_location", str(python_app_dir / "migrations"))

    engine = create_engine(db_url)

    # 1. Apply all migrations (upgrade head)
    command.upgrade(alembic_cfg, "head")

    inspector = inspect(engine)
    tables = inspector.get_table_names()
    assert "investigations" in tables
    assert "users" in tables
    assert "user_sessions" in tables
    assert "audit_logs" in tables
    assert "target_authorizations" in tables
    assert "collection_jobs" in tables
    assert "evidence" in tables
    assert "entities" in tables
    assert "active_scan_jobs" in tables
    assert "scan_hosts" in tables
    assert "scan_ports" in tables
    assert "vuln_scan_jobs" in tables
    assert "vuln_findings" in tables
    assert "alembic_version" in tables

    # Verify column definitions on created table
    columns = {c["name"]: c for c in inspector.get_columns("investigations")}
    assert "id" in columns
    assert "organization_name" in columns
    assert "active_scanning_enabled" in columns
    assert "created_at" in columns

    # Verify users table columns
    user_columns = {c["name"]: c for c in inspector.get_columns("users")}
    assert "id" in user_columns
    assert "username" in user_columns
    assert "password_hash" in user_columns
    assert "role" in user_columns

    # Verify evidence table columns
    evidence_columns = {c["name"]: c for c in inspector.get_columns("evidence")}
    assert "id" in evidence_columns
    assert "source_type" in evidence_columns
    assert "content_hash" in evidence_columns

    # Verify active_scan_jobs columns
    scan_columns = {c["name"]: c for c in inspector.get_columns("active_scan_jobs")}
    assert "id" in scan_columns
    assert "investigation_id" in scan_columns
    assert "scan_profile" in scan_columns
    assert "status" in scan_columns

    # Verify vuln_scan_jobs columns
    vuln_columns = {c["name"]: c for c in inspector.get_columns("vuln_scan_jobs")}
    assert "id" in vuln_columns
    assert "investigation_id" in vuln_columns
    assert "gvm_task_id" in vuln_columns
    assert "profile_id" in vuln_columns
    assert "status" in vuln_columns

    # Verify vuln_findings columns
    finding_columns = {c["name"]: c for c in inspector.get_columns("vuln_findings")}
    assert "id" in finding_columns
    assert "job_id" in finding_columns
    assert "severity" in finding_columns
    assert "cvss_score" in finding_columns
    assert "cve_references" in finding_columns

    # 2. Rollback migrations (downgrade base)
    command.downgrade(alembic_cfg, "base")

    inspector_after = inspect(engine)
    tables_after = inspector_after.get_table_names()
    assert "investigations" not in tables_after
    assert "users" not in tables_after
    assert "user_sessions" not in tables_after
    assert "audit_logs" not in tables_after
    assert "target_authorizations" not in tables_after
    assert "collection_jobs" not in tables_after
    assert "evidence" not in tables_after
    assert "entities" not in tables_after
    assert "active_scan_jobs" not in tables_after
    assert "scan_hosts" not in tables_after
    assert "scan_ports" not in tables_after
    assert "vuln_scan_jobs" not in tables_after
    assert "vuln_findings" not in tables_after


    engine.dispose()
