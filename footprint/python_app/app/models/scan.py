"""SQLAlchemy data models for active Nmap reconnaissance jobs, hosts, and port/service findings."""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import Boolean, DateTime, Float, Integer, JSON, String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


def utc_now() -> datetime:
    """Returns current datetime in UTC timezone."""
    return datetime.now(timezone.utc)


class ActiveScanJobModel(Base):
    """Tracks active Nmap reconnaissance scan jobs executed against authorized targets."""

    __tablename__ = "active_scan_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    requested_by: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    resolved_ips: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    scan_profile: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scan_profile_version: Mapped[str] = mapped_column(String(32), default="1.0", nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), default="QUEUED", nullable=False, index=True
    )  # QUEUED, AUTHORIZING, RUNNING, PARSING, COMPLETED, PARTIAL, FAILED, CANCELLED, TIMED_OUT, REJECTED
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    evidence_id: Mapped[Optional[str]] = mapped_column(
        String(64), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True, index=True
    )
    error_category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cancellation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    command_summary: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Relationships
    hosts: Mapped[List["ScanFindingHostModel"]] = relationship(
        "ScanFindingHostModel", back_populates="job", cascade="all, delete-orphan"
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "requested_by": self.requested_by,
            "target": self.target,
            "resolved_ips": self.resolved_ips or [],
            "scan_profile": self.scan_profile,
            "scan_profile_version": self.scan_profile_version,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "evidence_id": self.evidence_id,
            "error_category": self.error_category,
            "error_message": self.error_message,
            "cancellation_reason": self.cancellation_reason,
            "command_summary": self.command_summary,
            "hosts_count": len(self.hosts) if self.hosts else 0,
        }


class ScanFindingHostModel(Base):
    """Normalized host discovered during an active network reconnaissance scan."""

    __tablename__ = "scan_hosts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    investigation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    job_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("active_scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    address: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    address_type: Mapped[str] = mapped_column(String(16), default="ipv4", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="up", nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    os_match: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    evidence_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    job: Mapped["ActiveScanJobModel"] = relationship("ActiveScanJobModel", back_populates="hosts")
    ports: Mapped[List["ScanFindingPortModel"]] = relationship(
        "ScanFindingPortModel", back_populates="host", cascade="all, delete-orphan"
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "job_id": self.job_id,
            "address": self.address,
            "address_type": self.address_type,
            "status": self.status,
            "hostname": self.hostname,
            "os_match": self.os_match,
            "evidence_id": self.evidence_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "ports": [p.to_dict() for p in self.ports] if self.ports else [],
        }


class ScanFindingPortModel(Base):
    """Normalized open/filtered port and service finding from active Nmap scans."""

    __tablename__ = "scan_ports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    host_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("scan_hosts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    job_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("active_scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    protocol: Mapped[str] = mapped_column(String(16), default="tcp", nullable=False)
    port_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # open, closed, filtered
    service_name: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    product: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    extra_info: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    cpe: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    method: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    confidence: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    host: Mapped["ScanFindingHostModel"] = relationship("ScanFindingHostModel", back_populates="ports")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "host_id": self.host_id,
            "job_id": self.job_id,
            "protocol": self.protocol,
            "port_number": self.port_number,
            "state": self.state,
            "service_name": self.service_name,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "cpe": self.cpe,
            "method": self.method,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
