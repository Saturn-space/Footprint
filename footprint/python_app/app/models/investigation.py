"""Investigation SQLAlchemy model representing authorized reconnaissance campaigns."""

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import Boolean, DateTime, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


def utc_now() -> datetime:
    """Returns current datetime in UTC timezone."""
    return datetime.now(timezone.utc)


class InvestigationModel(Base):
    """Core domain model tracking authorized digital footprint investigations."""

    __tablename__ = "investigations"

    # Identifiers & Primary Metadata
    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    organization_name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    lead_investigator: Mapped[str] = mapped_column(String(128), nullable=False)
    team_members: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False, index=True)

    # Authorized Target Scopes
    owned_domains: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    approved_ips: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    approved_cidrs: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    active_targets: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)

    # Active Scanning Authorization Boundary
    active_scanning_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorization_reference: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    authorization_expiry: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    def to_dict(self) -> dict:
        """Serializes investigation model into standard dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "organization_name": self.organization_name,
            "description": self.description,
            "lead_investigator": self.lead_investigator,
            "team_members": self.team_members or [],
            "status": self.status,
            "scope": {
                "owned_domains": self.owned_domains or [],
                "approved_ips": self.approved_ips or [],
                "approved_cidrs": self.approved_cidrs or [],
                "active_targets": self.active_targets or []
            },
            "active_scanning_enabled": self.active_scanning_enabled,
            "authorization_reference": self.authorization_reference,
            "authorization_expiry": self.authorization_expiry.isoformat() if self.authorization_expiry else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }
