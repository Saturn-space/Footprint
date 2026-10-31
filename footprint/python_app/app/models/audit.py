"""AuditLog SQLAlchemy model for recording security-critical events."""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import DateTime, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


def utc_now() -> datetime:
    """Returns current datetime in UTC timezone."""
    return datetime.now(timezone.utc)


class AuditLogModel(Base):
    """Immutable audit trail for authentication, authorization, and privilege events."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    target_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="SUCCESS")
    request_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    details: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    def to_dict(self) -> dict:
        """Serializes audit record for administrative inspection."""
        return {
            "id": self.id,
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "target_user_id": self.target_user_id,
            "outcome": self.outcome,
            "request_id": self.request_id,
            "ip_address": self.ip_address,
            "details": self.details or {},
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
