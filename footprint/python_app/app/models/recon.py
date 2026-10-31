"""SQLAlchemy data models for passive reconnaissance, evidence, entities, and target authorization."""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import Boolean, DateTime, Integer, JSON, String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


def utc_now() -> datetime:
    """Returns current datetime in UTC timezone."""
    return datetime.now(timezone.utc)


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensures datetime object is timezone-aware UTC, even when stored naive in SQLite."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class TargetAuthorizationModel(Base):
    """Explicit administrative record authorizing specific reconnaissance operations on a target."""

    __tablename__ = "target_authorizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)  # DOMAIN, IP, CIDR
    allowed_operations: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    authorization_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_by: Mapped[str] = mapped_column(String(64), nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    def is_valid_for(self, operation: str) -> tuple[bool, str]:
        """Validates if authorization record covers the specified operation and is not expired/revoked."""
        if self.is_revoked:
            return False, "Target authorization has been revoked."
        now = datetime.now(timezone.utc)
        valid_to_utc = ensure_utc(self.valid_to)
        valid_from_utc = ensure_utc(self.valid_from)
        if now < valid_from_utc:
            return False, f"Target authorization not yet active (valid from {valid_from_utc.isoformat()})."
        if now > valid_to_utc:
            return False, f"Target authorization expired on {valid_to_utc.isoformat()}."
        allowed = self.allowed_operations or []
        op_set = {operation}
        if operation in ("SCAN_VULN", "SCAN_VULNERABILITY"):
            op_set.update({"SCAN_VULN", "SCAN_VULNERABILITY"})
        if not any(op in allowed for op in op_set):
            return False, f"Operation '{operation}' not permitted by authorization record."
        return True, "Authorization valid."


    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "target": self.target,
            "target_type": self.target_type,
            "allowed_operations": self.allowed_operations or [],
            "authorization_reference": self.authorization_reference,
            "approved_by": self.approved_by,
            "valid_from": self.valid_from.isoformat() if self.valid_from else None,
            "valid_to": self.valid_to.isoformat() if self.valid_to else None,
            "is_revoked": self.is_revoked,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class CollectionJobModel(Base):
    """Tracks collection jobs dispatched by the passive reconnaissance orchestrator."""

    __tablename__ = "collection_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    collector_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="QUEUED", nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    result_summary: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    error_category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "target": self.target,
            "collector_name": self.collector_name,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result_summary": self.result_summary or {},
            "error_category": self.error_category,
            "error_message": self.error_message,
        }


class EvidenceModel(Base):
    """Immutable forensic evidence record storing raw collection data and metadata."""

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    job_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("collection_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    source_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_name: Mapped[str] = mapped_column(String(128), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    collection_status: Mapped[str] = mapped_column(String(32), default="SUCCESS", nullable=False)
    raw_content_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    content_size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    source_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "job_id": self.job_id,
            "source_type": self.source_type,
            "source_name": self.source_name,
            "target": self.target,
            "collection_status": self.collection_status,
            "raw_content_path": self.raw_content_path,
            "content_hash": self.content_hash,
            "content_size_bytes": self.content_size_bytes,
            "source_metadata": self.source_metadata or {},
            "collected_at": self.collected_at.isoformat() if self.collected_at else None,
        }


class EntityModel(Base):
    """Normalized, deduplicated cybersecurity OSINT entity with evidence provenance."""

    __tablename__ = "entities"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    canonical_value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    original_value: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    evidence_ids: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "entity_type": self.entity_type,
            "canonical_value": self.canonical_value,
            "original_value": self.original_value,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "evidence_ids": self.evidence_ids or [],
            "metadata": self.metadata_json or {},
        }
