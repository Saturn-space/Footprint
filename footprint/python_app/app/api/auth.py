import uuid
from fastapi import APIRouter, Depends, Request, Response, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.database import get_db
from app.config import get_settings
from app.schemas.auth import LoginRequest, SignupRequest, TokenResponse, UserSummary, UserResponse
from app.core.auth import (
    authenticate_user,
    create_user_session,
    invalidate_session,
    log_audit_event,
)
from app.core.security import (
    generate_csrf_token,
    get_role_permissions,
    hash_password,
    validate_password_strength,
    ROLE_ADMINISTRATOR,
    ROLE_ANALYST,
)
from app.api.deps import (
    get_current_user,
    get_session_token_from_request,
    verify_csrf_token,
)
from app.models.user import UserModel

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
def login_api(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """Authenticates credentials, generates server-side session, and returns access token + session cookies."""
    settings = get_settings()
    client_ip = request.client.host if request.client else None
    req_id = getattr(request.state, "request_id", None)
    user_agent = request.headers.get("user-agent")

    user = authenticate_user(
        db=db,
        username_or_email=payload.username_or_email,
        password=payload.password,
        client_ip=client_ip,
        request_id=req_id,
    )

    raw_token, session = create_user_session(
        db=db,
        user=user,
        ip_address=client_ip,
        user_agent=user_agent,
        max_age_seconds=settings.SESSION_MAX_AGE_SECONDS,
    )

    # Attach session cookie
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=settings.SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        path="/",
    )

    # Attach CSRF cookie for browser usage
    csrf_token = generate_csrf_token()
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=settings.SESSION_MAX_AGE_SECONDS,
        httponly=False,  # Client JS / forms read this for double-submit
        secure=settings.cookie_secure,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        path="/",
    )

    return TokenResponse(
        access_token=raw_token,
        token_type="bearer",
        expires_in=settings.SESSION_MAX_AGE_SECONDS,
        user=UserSummary(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
        ),
    )


@router.post("/logout")
def logout_api(
    request: Request,
    response: Response,
    current_user: UserModel = Depends(get_current_user),
    raw_token: str = Depends(get_session_token_from_request),
    csrf_ok: None = Depends(verify_csrf_token),
    db: Session = Depends(get_db),
):
    """Revokes the current server session and clears authentication cookies."""
    settings = get_settings()
    req_id = getattr(request.state, "request_id", None)
    client_ip = request.client.host if request.client else None

    invalidate_session(
        db=db,
        raw_token=raw_token,
        actor_id=current_user.id,
        request_id=req_id,
        client_ip=client_ip,
    )

    # Clear cookies
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )
    response.delete_cookie(
        key=settings.CSRF_COOKIE_NAME,
        path="/",
        secure=settings.cookie_secure,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )

    return {"message": "Session invalidated and logged out successfully"}


@router.get("/me")
def get_current_user_profile(
    current_user: UserModel = Depends(get_current_user),
):
    """Returns profile and operational permissions for the authenticated user."""
    profile = current_user.to_dict()
    profile["permissions"] = sorted(list(get_role_permissions(current_user.role)))
    return profile


@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def signup_api(
    payload: SignupRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Self-service registration endpoint for new investigators.

    Enforces:
    - Public signup policy check (ALLOW_PUBLIC_SIGNUP)
    - Strict password complexity (Argon2id hashing)
    - Uniqueness of username and email
    - Least-privileged role assignment (never administrator)
    - Structured audit logging
    """
    settings = get_settings()
    if not settings.ALLOW_PUBLIC_SIGNUP:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public account registration is currently disabled by administrator policy.",
        )

    # Validate password match if confirmation provided
    if payload.confirm_password and payload.password != payload.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Passwords do not match.",
        )

    # Validate password complexity
    valid_pw, pw_reason = validate_password_strength(payload.password)
    if not valid_pw:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=pw_reason,
        )

    # Check for existing username or email
    existing_user = db.scalars(
        select(UserModel).where(UserModel.username == payload.username)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{payload.username}' is already registered.",
        )

    existing_email = db.scalars(
        select(UserModel).where(UserModel.email == payload.email)
    ).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Email address '{payload.email}' is already registered.",
        )

    # Enforce non-admin role
    assigned_role = settings.DEFAULT_SIGNUP_ROLE
    if assigned_role == ROLE_ADMINISTRATOR:
        assigned_role = ROLE_ANALYST

    new_user = UserModel(
        id=f"usr-{uuid.uuid4().hex[:12]}",
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=assigned_role,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_audit_event(
        db=db,
        event_type="USER_REGISTERED",
        actor_id=new_user.id,
        target_user_id=new_user.id,
        outcome="SUCCESS",
        request_id=getattr(request.state, "request_id", None),
        ip_address=request.client.host if request.client else None,
        details={"username": new_user.username, "role": new_user.role, "method": "self_service_api"},
    )

    data = new_user.to_dict()
    return UserResponse(
        id=data["id"],
        username=data["username"],
        email=data["email"],
        role=data["role"],
        is_active=data["is_active"],
        is_locked=data["is_locked"],
        last_login_at=new_user.last_login_at,
        created_at=new_user.created_at,
        updated_at=new_user.updated_at,
    )

