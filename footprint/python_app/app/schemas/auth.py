"""Pydantic schemas for authentication, users, roles, and audit trails."""

from datetime import datetime
from typing import Optional, Dict, Any, List, Literal
from pydantic import BaseModel, EmailStr, Field, field_validator
from app.core.security import normalize_identifier, VALID_ROLES


class LoginRequest(BaseModel):
    """Credentials payload for API and web authentication."""
    username_or_email: str = Field(..., min_length=1, max_length=128, description="Username or email address")
    password: str = Field(..., min_length=1, max_length=256, description="Plaintext user password")

    @field_validator("username_or_email")
    @classmethod
    def normalize_input(cls, v: str) -> str:
        return normalize_identifier(v)


class UserSummary(BaseModel):
    """Minimal user profile information returned on authentication."""
    id: str
    username: str
    email: str
    role: str
    is_active: bool


class TokenResponse(BaseModel):
    """Successful authentication response payload."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserSummary


class UserResponse(BaseModel):
    """Detailed user representation for administrative and self profile endpoints."""
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    is_locked: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class UserCreate(BaseModel):
    """Payload for provisioning a new user (restricted to administrator)."""
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_\-\.]+$")
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128, description="Minimum 12 characters")
    role: Literal["administrator", "analyst", "viewer"] = "viewer"

    @field_validator("username")
    @classmethod
    def normalize_user(cls, v: str) -> str:
        return normalize_identifier(v)

    @field_validator("email")
    @classmethod
    def normalize_mail(cls, v: str) -> str:
        return normalize_identifier(v)


class SignupRequest(BaseModel):
    """Payload for self-service investigator account registration."""
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_\-\.]+$")
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128, description="Minimum 12 characters")
    confirm_password: Optional[str] = None

    @field_validator("username")
    @classmethod
    def normalize_user(cls, v: str) -> str:
        return normalize_identifier(v)

    @field_validator("email")
    @classmethod
    def normalize_mail(cls, v: str) -> str:
        return normalize_identifier(v)



class UserUpdateRole(BaseModel):
    """Payload for updating user role (restricted to administrator)."""
    role: Literal["administrator", "analyst", "viewer"]


class UserUpdateStatus(BaseModel):
    """Payload for enabling or disabling user account (restricted to administrator)."""
    is_active: bool


class AuditLogResponse(BaseModel):
    """Audit log entry representation."""
    id: str
    event_type: str
    actor_id: Optional[str] = None
    target_user_id: Optional[str] = None
    outcome: str
    request_id: Optional[str] = None
    ip_address: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime
