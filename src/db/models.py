"""
FootprintIQ - Microsoft SQL Server 2022 Express ORM Models
Defines all database entities, tables, relationships, foreign keys, constraints, and indexes.
Strict Rule: Pure Microsoft SQL Server dialect and types.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean, DateTime,
    ForeignKey, Index, CheckConstraint, UniqueConstraint
)
from sqlalchemy.orm import relationship
from src.db.session import Base


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('admin', 'investigator')", name="chk_users_role"),
        CheckConstraint("theme_preference IN ('light', 'dark', 'system')", name="chk_users_theme_preference"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    uuid = Column(String(36), default=lambda: str(uuid.uuid4()), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(150), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="investigator", nullable=False)  # 'admin', 'investigator'
    is_active = Column(Boolean, default=True, nullable=False)
    is_approved = Column(Boolean, default=False, nullable=False)  # Admin approval required
    last_login_at = Column(DateTime, nullable=True)
    theme_preference = Column(String(20), default="light", nullable=False)
    timezone_preference = Column(String(64), default="Asia/Kolkata", nullable=False)
    notification_preferences_json = Column(Text, nullable=True)
    token_version = Column(Integer, default=1, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    investigations = relationship("Investigation", back_populates="creator", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (
        CheckConstraint("exposure_score >= 0.0 AND exposure_score <= 100.0", name="chk_investigations_exposure_score"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(64), unique=True, nullable=False, index=True)  # e.g. "INV-20261110-001"
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    creator_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    status = Column(String(50), default="active", nullable=False)  # 'active', 'completed', 'archived'
    exposure_score = Column(Float, default=0.0, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    creator = relationship("User", back_populates="investigations")
    campaigns = relationship("Campaign", back_populates="investigation", cascade="all, delete-orphan")
    targets = relationship("AuthorizedTarget", back_populates="investigation", cascade="all, delete-orphan")
    scans = relationship("ScanExecution", back_populates="investigation", cascade="all, delete-orphan")
    findings = relationship("VulnerabilityFinding", back_populates="investigation", cascade="all, delete-orphan")
    evidence = relationship("EvidenceRecord", back_populates="investigation", cascade="all, delete-orphan")
    reports = relationship("ReportRecord", back_populates="investigation", cascade="all, delete-orphan")
    shares = relationship("InvestigationShare", back_populates="investigation", cascade="all, delete-orphan")


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, autoincrement=True)
    campaign_id = Column(String(64), unique=True, nullable=False, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    investigation = relationship("Investigation", back_populates="campaigns")


class AuthorizedTarget(Base):
    __tablename__ = "authorized_targets"
    __table_args__ = (
        CheckConstraint(
            "authorization_status IN ('AUTHORIZED_LOCAL_LAB', 'AUTHORIZED', 'PENDING_AUTHORIZATION', 'REVOKED')",
            name="chk_authorized_targets_status"
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(String(64), unique=True, nullable=False, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    target = Column(String(255), nullable=False, index=True)  # e.g. "192.168.56.111"
    target_type = Column(String(50), nullable=False)  # 'ipv4', 'domain', 'hostname'
    name = Column(String(200), nullable=False)
    category = Column(String(100), default="authorized_lab", nullable=False)
    scope = Column(String(255), nullable=False)
    permitted_profiles = Column(String(255), default="lab-basic,lab-safe-minimal", nullable=False)
    allowed_ports = Column(String(100), default="1-65535", nullable=False)
    authorization_status = Column(String(50), default="AUTHORIZED_LOCAL_LAB", nullable=False)
    authorized_by = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    investigation = relationship("Investigation", back_populates="targets")


class ReconCampaign(Base):
    __tablename__ = "recon_campaigns"
    __table_args__ = (
        CheckConstraint(
            "status IN ('Draft', 'Pending Authorization', 'Authorized', 'Queued', 'Running', 'Completed', 'Partially Completed', 'Failed', 'Cancelled', 'Interrupted')",
            name="chk_recon_campaigns_status"
        ),
        CheckConstraint("progress >= 0 AND progress <= 100", name="chk_recon_campaigns_progress"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    recon_id = Column(String(64), unique=True, nullable=False, index=True)  # e.g. "FIQ-REC-20261110-0001"
    investigation_id = Column(String(64), nullable=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    purpose = Column(String(255), nullable=True)
    scope_description = Column(Text, nullable=True)
    target_type = Column(String(50), default="ipv4", nullable=False)  # 'ipv4', 'range', 'domain', 'hostname'
    target_value = Column(String(255), nullable=False)
    excluded_targets = Column(Text, nullable=True)
    excluded_ports = Column(String(255), nullable=True)
    allowed_methods = Column(String(255), default="all", nullable=False)
    allowed_ports = Column(String(255), default="1-65535", nullable=False)
    authorization_status = Column(String(50), default="Authorized", nullable=False)
    authorized_by = Column(String(100), default="asip_ali", nullable=False)
    authorized_at = Column(DateTime, default=utcnow, nullable=False)
    status = Column(String(50), default="Draft", nullable=False)
    selected_scan_types = Column(Text, nullable=True)
    scan_config_json = Column(Text, nullable=True)
    progress = Column(Integer, default=0, nullable=False)
    current_stage = Column(String(100), nullable=True)
    creator_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    version_id = Column(Integer, default=1, nullable=False)  # Optimistic concurrency versioning
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    creator = relationship("User")
    events = relationship("ScanExecutionEvent", back_populates="campaign", cascade="all, delete-orphan")


class ScanExecution(Base):
    __tablename__ = "scan_executions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled', 'interrupted', 'partially_completed')",
            name="chk_scan_executions_status"
        ),
        Index("ix_scan_executions_inv_run", "investigation_id", "run_number"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), unique=True, nullable=False, index=True)  # e.g. "SCAN-20261110-12345"
    recon_id = Column(String(64), ForeignKey("recon_campaigns.recon_id", ondelete="SET NULL"), nullable=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    run_number = Column(Integer, default=1, nullable=False)
    scan_type = Column(String(50), nullable=False)
    target = Column(String(255), nullable=False)
    profile = Column(String(100), default="default", nullable=False)
    status = Column(String(50), default="queued", nullable=False)
    initiating_user_id = Column(Integer, ForeignKey("users.id", ondelete="NO ACTION"), nullable=True)
    initiated_by = Column(String(100), nullable=True)
    selected_scanners_json = Column(Text, nullable=True)
    selected_components_json = Column(Text, nullable=True)
    scan_config_json = Column(Text, nullable=True)
    scanner_versions_json = Column(Text, nullable=True)
    target_authorization_ref = Column(String(128), nullable=True)
    privilege_consent_given = Column(Boolean, default=False, nullable=False)
    privilege_elevation_required = Column(Boolean, default=False, nullable=False)
    privilege_status = Column(String(32), default="none", nullable=False)
    privilege_authorized_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    error_message = Column(Text, nullable=True)
    result_summary_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    investigation = relationship("Investigation", back_populates="scans")
    findings = relationship("VulnerabilityFinding", back_populates="scan", cascade="all, delete-orphan")
    evidence = relationship("EvidenceRecord", back_populates="scan", cascade="all, delete-orphan")


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('Critical', 'High', 'Medium', 'Low', 'Informational', 'Info')",
            name="chk_vulnerability_findings_severity"
        ),
        CheckConstraint(
            "finding_status IN ('open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive')",
            name="chk_vulnerability_findings_status"
        ),
        CheckConstraint("port IS NULL OR (port >= 1 AND port <= 65535)", name="chk_vulnerability_findings_port"),
        CheckConstraint("cvss_score IS NULL OR (cvss_score >= 0.0 AND cvss_score <= 10.0)", name="chk_vulnerability_findings_cvss"),
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="chk_vulnerability_findings_confidence"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(64), unique=True, nullable=False, index=True)  # e.g. "VULN-20261110-001"
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    scan_execution_id = Column(Integer, ForeignKey("scan_executions.id", ondelete="SET NULL"), nullable=True)
    target_ip = Column(String(100), nullable=False, index=True)
    hostname = Column(String(255), nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(20), default="tcp", nullable=False)
    service = Column(String(100), nullable=True)
    service_version = Column(String(100), nullable=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=True)
    cve_identifiers = Column(String(500), nullable=True, index=True)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String(50), default="Informational", nullable=False, index=True)
    confidence = Column(Float, default=1.0, nullable=False)
    detection_source = Column(String(50), nullable=False)
    scanner_vt_id = Column(String(100), nullable=True)
    remediation = Column(Text, nullable=True)
    remediation_notes = Column(Text, nullable=True)
    evidence_reference = Column(String(255), nullable=True)
    verification_status = Column(String(50), default="unverified", nullable=False)
    finding_status = Column(String(50), default="open", nullable=False)
    status_updated_by = Column(String(100), nullable=True)
    status_updated_at = Column(DateTime, nullable=True)
    version_id = Column(Integer, default=1, nullable=False)  # Optimistic concurrency versioning
    first_detected = Column(DateTime, default=utcnow, nullable=False)
    last_detected = Column(DateTime, default=utcnow, nullable=False)

    investigation = relationship("Investigation", back_populates="findings")
    scan = relationship("ScanExecution", back_populates="findings")


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    evidence_id = Column(String(64), unique=True, nullable=False, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    scan_execution_id = Column(Integer, ForeignKey("scan_executions.id", ondelete="SET NULL"), nullable=True)
    scan_id = Column(String(64), nullable=True, index=True)
    run_number = Column(Integer, nullable=True)
    scanner_source = Column(String(64), nullable=True, index=True)
    target = Column(String(255), nullable=True)
    evidence_type = Column(String(50), nullable=False)
    file_name = Column(String(255), nullable=False)
    file_size = Column(Integer, default=0, nullable=False)
    content_type = Column(String(100), default="application/octet-stream", nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    seaweed_fid = Column(String(100), nullable=True)
    seaweed_url = Column(String(255), nullable=True)
    local_path = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    investigation = relationship("Investigation", back_populates="evidence")
    scan = relationship("ScanExecution", back_populates="evidence")


class ReportRecord(Base):
    __tablename__ = "report_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(String(64), unique=True, nullable=False, index=True)
    recon_id = Column(String(64), ForeignKey("recon_campaigns.recon_id", ondelete="SET NULL"), nullable=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    scan_execution_id = Column(Integer, ForeignKey("scan_executions.id", ondelete="NO ACTION"), nullable=True)
    scan_id = Column(String(64), nullable=True, index=True)
    run_number = Column(Integer, nullable=True)
    scan_type = Column(String(50), nullable=True)
    investigation_name = Column(String(200), nullable=True)
    generated_by_user_id = Column(Integer, ForeignKey("users.id", ondelete="NO ACTION"), nullable=True)
    generated_by_username = Column(String(100), nullable=True)
    report_type = Column(String(50), default="pdf", nullable=False)
    report_status = Column(String(40), default="completed", nullable=False)
    file_name = Column(String(255), nullable=False)
    file_size = Column(Integer, default=0, nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    seaweed_fid = Column(String(100), nullable=True)
    generated_at = Column(DateTime, default=utcnow, nullable=False)

    investigation = relationship("Investigation", back_populates="reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint("outcome IN ('SUCCESS', 'DENIED', 'FAILED')", name="chk_audit_logs_outcome"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    actor_role = Column(String(50), nullable=True)
    action = Column(String(100), nullable=False, index=True)
    target_resource = Column(String(255), nullable=True)
    outcome = Column(String(30), default="SUCCESS", nullable=False)
    details_json = Column(Text, nullable=True)
    ip_address = Column(String(50), nullable=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False)

    user = relationship("User", back_populates="audit_logs")


class InvestigationShare(Base):
    __tablename__ = "investigation_shares"
    __table_args__ = (
        UniqueConstraint("investigation_id", "user_id", name="uq_investigation_share_user"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="NO ACTION"), nullable=False, index=True)
    granted_by_id = Column(Integer, ForeignKey("users.id", ondelete="NO ACTION"), nullable=True)
    permission_level = Column(String(30), default="read_write", nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    investigation = relationship("Investigation", back_populates="shares")


class ScanExecutionEvent(Base):
    __tablename__ = "scan_execution_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), nullable=False, index=True)
    recon_id = Column(String(64), ForeignKey("recon_campaigns.recon_id", ondelete="CASCADE"), nullable=True, index=True)
    event_type = Column(String(50), default="log", nullable=False)
    stage = Column(String(100), nullable=True)
    message = Column(Text, nullable=False)
    details_json = Column(Text, nullable=True)
    progress = Column(Integer, nullable=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False)

    campaign = relationship("ReconCampaign", back_populates="events")


class SavedScanProfile(Base):
    __tablename__ = "saved_scan_profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(50), default="general", nullable=False)
    config_json = Column(Text, nullable=False)
    is_builtin = Column(Boolean, default=False, nullable=False)
    created_by = Column(String(100), default="system", nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class RemediationHistory(Base):
    __tablename__ = "remediation_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(64), ForeignKey("vulnerability_findings.finding_id", ondelete="CASCADE"), nullable=False, index=True)
    previous_status = Column(String(50), nullable=False)
    new_status = Column(String(50), nullable=False)
    changed_by = Column(String(100), nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class ExternalArtifactOutbox(Base):
    """
    Transactional Outbox for reliable asynchronous reconciliation of external
    artifacts (SeaweedFS blobs, external scanner task UUIDs).
    Guarantees at-least-once reconciliation and prevents orphaned storage objects.
    """
    __tablename__ = "external_artifacts_outbox"

    id = Column(Integer, primary_key=True, autoincrement=True)
    artifact_id = Column(String(64), unique=True, nullable=False, index=True)
    investigation_id = Column(String(64), nullable=False, index=True)
    recon_id = Column(String(64), nullable=True, index=True)
    artifact_type = Column(String(50), nullable=False)  # 'seaweed_blob', 'nessus_scan', 'openvas_task', 'nmap_execution', 'pdf_report'
    external_reference_id = Column(String(255), nullable=True)  # Seaweed FID or scanner scan UUID
    status = Column(String(50), default="staged", nullable=False, index=True)  # 'staged', 'committed', 'orphaned', 'reconciled', 'cleaned_up', 'failed'
    file_name = Column(String(255), nullable=True)
    sha256_hash = Column(String(64), nullable=True)
    details_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


# Compound Indexes for optimal query performance
Index("ix_vulnerability_target_port", VulnerabilityFinding.target_ip, VulnerabilityFinding.port)
Index("ix_vulnerability_investigation_severity", VulnerabilityFinding.investigation_id, VulnerabilityFinding.severity)
Index("ix_scan_investigation_status", ScanExecution.investigation_id, ScanExecution.status)
Index("ix_evidence_investigation_type", EvidenceRecord.investigation_id, EvidenceRecord.evidence_type)
Index("ix_scan_event_scan_timestamp", ScanExecutionEvent.scan_id, ScanExecutionEvent.timestamp)
Index("ix_recon_campaign_status", ReconCampaign.status)
Index("ix_outbox_status_type", ExternalArtifactOutbox.status, ExternalArtifactOutbox.artifact_type)
