"""User management API endpoints restricted to Administrators."""

import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.database import get_db
from app.models.user import UserModel, UserSessionModel
from app.schemas.auth import (
    UserResponse,
    UserCreate,
    UserUpdateRole,
    UserUpdateStatus,
)
from app.core.security import (
    hash_password,
    ROLE_ADMINISTRATOR,
    VALID_ROLES,
)
from app.core.auth import log_audit_event
from app.api.deps import require_role

router = APIRouter(prefix="/api/v1/users", tags=["User Management"])


@router.get("", response_model=List[UserResponse])
def list_users(
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    db: Session = Depends(get_db),
):
    """Lists all user accounts. Restricted to Administrator."""
    stmt = select(UserModel).order_by(UserModel.created_at.desc())
    users = db.scalars(stmt).all()
    return [user.to_dict() for user in users]


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    db: Session = Depends(get_db),
):
    """Provisions a new user account. Restricted to Administrator."""
    # Check username collision
    existing_username = db.scalar(select(UserModel).where(UserModel.username == payload.username))
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{payload.username}' is already registered",
        )

    # Check email collision
    existing_email = db.scalar(select(UserModel).where(UserModel.email == payload.email))
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Email '{payload.email}' is already registered",
        )

    user = UserModel(
        id=f"usr-{uuid.uuid4().hex[:12]}",
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    req_id = getattr(request.state, "request_id", None)
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        event_type="USER_CREATED",
        outcome="SUCCESS",
        actor_id=admin.id,
        target_user_id=user.id,
        request_id=req_id,
        ip_address=client_ip,
        details={"username": user.username, "role": user.role},
    )

    return user.to_dict()


@router.get("/{user_id}", response_model=UserResponse)
def get_user_by_id(
    user_id: str,
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    db: Session = Depends(get_db),
):
    """Retrieves user profile by ID. Restricted to Administrator."""
    user = db.get(UserModel, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user.to_dict()


@router.patch("/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: str,
    payload: UserUpdateRole,
    request: Request,
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    db: Session = Depends(get_db),
):
    """Updates user role. Restricted to Administrator."""
    user = db.get(UserModel, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    old_role = user.role
    user.role = payload.role
    db.commit()
    db.refresh(user)

    req_id = getattr(request.state, "request_id", None)
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        event_type="ROLE_CHANGED",
        outcome="SUCCESS",
        actor_id=admin.id,
        target_user_id=user.id,
        request_id=req_id,
        ip_address=client_ip,
        details={"old_role": old_role, "new_role": user.role},
    )

    return user.to_dict()


@router.patch("/{user_id}/status", response_model=UserResponse)
def update_user_status(
    user_id: str,
    payload: UserUpdateStatus,
    request: Request,
    admin: UserModel = Depends(require_role(ROLE_ADMINISTRATOR)),
    db: Session = Depends(get_db),
):
    """Enables or disables user account and revokes active sessions if disabled."""
    user = db.get(UserModel, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.is_active = payload.is_active
    if not payload.is_active:
        # Revoke all active sessions for this user
        for s in user.sessions:
            s.is_revoked = True

    db.commit()
    db.refresh(user)

    req_id = getattr(request.state, "request_id", None)
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        event_type="ACCOUNT_STATUS_CHANGED",
        outcome="SUCCESS",
        actor_id=admin.id,
        target_user_id=user.id,
        request_id=req_id,
        ip_address=client_ip,
        details={"is_active": user.is_active},
    )

    return user.to_dict()
