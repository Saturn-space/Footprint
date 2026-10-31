"""FastAPI route dependencies for authentication, RBAC, CSRF, and session resolution."""

import hmac
from typing import Optional, List, Callable
from fastapi import Request, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import UserModel
from app.core.auth import get_user_by_session_token, log_audit_event
from app.core.security import has_permission, VALID_ROLES
from app.config import get_settings

bearer_scheme = HTTPBearer(auto_error=False)


def extract_token_from_request(request: Request) -> Optional[str]:
    """Helper to safely extract raw session token from Bearer header or session cookie."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token_val = auth_header[7:].strip()
        if token_val:
            return token_val

    settings = get_settings()
    cookie_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if cookie_token and cookie_token.strip():
        return cookie_token.strip()

    return None


def get_session_token_from_request(
    request: Request,
    bearer_creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Optional[str]:
    """Extracts raw session token from Bearer header or session cookie."""
    if bearer_creds and bearer_creds.credentials:
        return bearer_creds.credentials.strip()
    return extract_token_from_request(request)


def get_current_user_optional(
    request: Request,
    token: Optional[str] = None,
    db: Session = Depends(get_db),
) -> Optional[UserModel]:
    """Resolves authenticated user from token if available, returning None otherwise."""
    raw_token = token if isinstance(token, str) else extract_token_from_request(request)
    if not raw_token:
        return None
    return get_user_by_session_token(db=db, raw_token=raw_token)


def get_current_user(
    request: Request,
    current_user: Optional[UserModel] = Depends(get_current_user_optional),
) -> UserModel:
    """Enforces authentication. Rejects unauthenticated requests with HTTP 401."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user


def require_role(*allowed_roles: str) -> Callable:
    """Factory creating an authorization dependency restricting endpoints to specific roles."""
    for r in allowed_roles:
        if r not in VALID_ROLES:
            raise ValueError(f"Unknown role declared in dependency: {r}")

    def role_checker(
        request: Request,
        user: UserModel = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> UserModel:
        if user.role not in allowed_roles:
            req_id = getattr(request.state, "request_id", None)
            client_ip = request.client.host if request.client else None
            log_audit_event(
                db=db,
                event_type="PERMISSION_DENIED",
                outcome="FAILURE",
                actor_id=user.id,
                request_id=req_id,
                ip_address=client_ip,
                details={
                    "required_roles": list(allowed_roles),
                    "user_role": user.role,
                    "path": request.url.path,
                    "method": request.method,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires one of roles: {', '.join(allowed_roles)}",
            )
        return user

    return role_checker


def require_permission(permission_name: str) -> Callable:
    """Factory creating an authorization dependency enforcing specific operational permissions."""
    def permission_checker(
        request: Request,
        user: UserModel = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> UserModel:
        if not has_permission(user.role, permission_name):
            req_id = getattr(request.state, "request_id", None)
            client_ip = request.client.host if request.client else None
            log_audit_event(
                db=db,
                event_type="PERMISSION_DENIED",
                outcome="FAILURE",
                actor_id=user.id,
                request_id=req_id,
                ip_address=client_ip,
                details={
                    "required_permission": permission_name,
                    "user_role": user.role,
                    "path": request.url.path,
                    "method": request.method,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires permission: {permission_name}",
            )
        return user

    return permission_checker


async def verify_csrf_token(
    request: Request,
    db: Session = Depends(get_db),
) -> None:
    """Verifies CSRF token for state-changing browser cookie requests.

    API clients presenting Authorization: Bearer tokens are exempt from CSRF
    because browser ambient credentials are not used.
    """
    # Safe methods do not mutate state
    if request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
        return

    # Check if request is authenticated via Bearer token in header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer ") and len(auth_header) > 10:
        return

    # If authenticated via cookie, enforce CSRF
    settings = get_settings()
    cookie_token = request.cookies.get(settings.CSRF_COOKIE_NAME)
    if not cookie_token:
        req_id = getattr(request.state, "request_id", None)
        client_ip = request.client.host if request.client else None
        log_audit_event(
            db=db,
            event_type="PERMISSION_DENIED",
            outcome="FAILURE",
            request_id=req_id,
            ip_address=client_ip,
            details={"reason": "missing_csrf_cookie", "path": request.url.path},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed: missing CSRF cookie",
        )

    # Check token from header or form body
    header_token = request.headers.get("X-CSRF-Token")
    form_token = None

    content_type = request.headers.get("Content-Type", "")
    if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        try:
            form = await request.form()
            form_token = form.get("csrf_token")
        except Exception:
            pass

    submitted_token = header_token or form_token
    if not submitted_token or not hmac.compare_digest(submitted_token.strip(), cookie_token.strip()):
        req_id = getattr(request.state, "request_id", None)
        client_ip = request.client.host if request.client else None
        log_audit_event(
            db=db,
            event_type="PERMISSION_DENIED",
            outcome="FAILURE",
            request_id=req_id,
            ip_address=client_ip,
            details={"reason": "invalid_csrf_token", "path": request.url.path},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed: invalid CSRF token",
        )
