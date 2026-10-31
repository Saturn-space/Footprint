"""Authentication, session management, and audit logging services."""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select
from fastapi import HTTPException, status

from app.models.user import UserModel, UserSessionModel
from app.models.audit import AuditLogModel
from app.core.security import (
    verify_password,
    generate_session_token,
    hash_session_token,
    normalize_identifier,
)
from app.config import get_settings


def log_audit_event(
    db: Session,
    event_type: str,
    outcome: str,
    actor_id: Optional[str] = None,
    target_user_id: Optional[str] = None,
    request_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> AuditLogModel:
    """Records an immutable security audit event. Secrets and passwords must never be passed in details."""
    sanitized_details = details.copy() if details else {}
    # Ensure accidental sensitive keys are removed
    for secret_key in ("password", "token", "secret", "cookie", "access_token"):
        sanitized_details.pop(secret_key, None)

    audit_entry = AuditLogModel(
        id=f"audit-{uuid.uuid4().hex[:16]}",
        event_type=event_type,
        actor_id=actor_id,
        target_user_id=target_user_id,
        outcome=outcome,
        request_id=request_id,
        ip_address=ip_address,
        details=sanitized_details,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry


def authenticate_user(
    db: Session,
    username_or_email: str,
    password: str,
    client_ip: Optional[str] = None,
    request_id: Optional[str] = None,
) -> UserModel:
    """Authenticates credentials against database with lockout throttling and audit logging."""
    settings = get_settings()
    normalized = normalize_identifier(username_or_email)

    stmt = select(UserModel).where(
        (UserModel.username == normalized) | (UserModel.email == normalized)
    )
    user = db.scalar(stmt)

    if not user:
        log_audit_event(
            db=db,
            event_type="LOGIN_FAILED",
            outcome="FAILURE",
            actor_id=None,
            request_id=request_id,
            ip_address=client_ip,
            details={"identifier": normalized, "reason": "user_not_found"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check lockout state
    if user.is_locked():
        log_audit_event(
            db=db,
            event_type="LOGIN_FAILED",
            outcome="FAILURE",
            actor_id=user.id,
            request_id=request_id,
            ip_address=client_ip,
            details={"reason": "account_temporarily_locked", "locked_until": user.locked_until.isoformat()},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check active status
    if not user.is_active:
        log_audit_event(
            db=db,
            event_type="LOGIN_FAILED",
            outcome="FAILURE",
            actor_id=user.id,
            request_id=request_id,
            ip_address=client_ip,
            details={"reason": "account_disabled"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify password hash
    if not verify_password(password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
            user.locked_until = datetime.now(timezone.utc) + timedelta(
                minutes=settings.LOCKOUT_DURATION_MINUTES
            )
        db.commit()

        log_audit_event(
            db=db,
            event_type="LOGIN_FAILED",
            outcome="FAILURE",
            actor_id=user.id,
            request_id=request_id,
            ip_address=client_ip,
            details={"reason": "invalid_password", "failed_attempts": user.failed_login_attempts},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Authentication succeeded: reset failure counter and record timestamp
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    log_audit_event(
        db=db,
        event_type="LOGIN_SUCCESS",
        outcome="SUCCESS",
        actor_id=user.id,
        request_id=request_id,
        ip_address=client_ip,
        details={"role": user.role},
    )

    return user


def create_user_session(
    db: Session,
    user: UserModel,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    max_age_seconds: int = 14400,
) -> Tuple[str, UserSessionModel]:
    """Issues a cryptographically secure session token and persists the hashed token in the database."""
    raw_token = generate_session_token()
    token_hash = hash_session_token(raw_token)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=max_age_seconds)

    session = UserSessionModel(
        id=token_hash,
        user_id=user.id,
        is_revoked=False,
        expires_at=expires_at,
        last_accessed_at=now,
        created_at=now,
        ip_address=ip_address,
        user_agent=user_agent[:255] if user_agent else None,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return raw_token, session


def invalidate_session(
    db: Session,
    raw_token: str,
    actor_id: Optional[str] = None,
    request_id: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> bool:
    """Revokes a session server-side."""
    if not raw_token:
        return False
    token_hash = hash_session_token(raw_token)
    session = db.get(UserSessionModel, token_hash)
    if session and not session.is_revoked:
        session.is_revoked = True
        db.commit()

        log_audit_event(
            db=db,
            event_type="LOGOUT",
            outcome="SUCCESS",
            actor_id=actor_id or session.user_id,
            request_id=request_id,
            ip_address=client_ip,
            details={"session_id_prefix": token_hash[:8]},
        )
        return True
    return False


def get_user_by_session_token(db: Session, raw_token: str) -> Optional[UserModel]:
    """Resolves an active, non-expired, unrevoked session token to its associated user."""
    if not raw_token:
        return None
    token_hash = hash_session_token(raw_token)
    session = db.get(UserSessionModel, token_hash)
    if not session or not session.is_valid():
        return None

    user = session.user
    if not user or not user.is_active or user.is_locked():
        return None

    # Update session activity touch
    session.last_accessed_at = datetime.now(timezone.utc)
    db.commit()
    return user
