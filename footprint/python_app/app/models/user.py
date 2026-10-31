"""User and UserSession SQLAlchemy models."""

from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import Boolean, DateTime, Integer, String, ForeignKey
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


class UserModel(Base):
    """User account model enforcing role-based access control and account lifecycle."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="viewer", nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Throttling & Account Security
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    sessions: Mapped[List["UserSessionModel"]] = relationship(
        "UserSessionModel", back_populates="user", cascade="all, delete-orphan"
    )

    def is_locked(self) -> bool:
        """Checks if account is currently locked due to repeated failed logins."""
        if not self.locked_until:
            return False
        return datetime.now(timezone.utc) < ensure_utc(self.locked_until)

    def to_dict(self) -> dict:
        """Serializes user model to dictionary, strictly excluding password_hash."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "is_locked": self.is_locked(),
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class UserSessionModel(Base):
    """Server-side authenticated session tracking and revocation store."""

    __tablename__ = "user_sessions"

    # Store hashed session token as ID to prevent raw token extraction if database is compromised
    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_accessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Audit metadata
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Relationship
    user: Mapped["UserModel"] = relationship("UserModel", back_populates="sessions")

    def is_valid(self) -> bool:
        """Checks if session is active, not revoked, and not expired."""
        if self.is_revoked:
            return False
        return datetime.now(timezone.utc) < ensure_utc(self.expires_at)
