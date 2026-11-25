"""
FootprintIQ - FastAPI Dependencies
Handles JWT authentication, current user resolution, strict RBAC authorization
with default-deny semantics and security audit logging, and database repository injection.
"""

from typing import Dict, Any, Optional
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from src.db.session import get_db
from src.services.auth_service import AuthService, decode_access_token
from src.db.repository import FootprintIQRepository
from src.services.rbac_service import (
    ROLE_ADMIN,
    ROLE_INVESTIGATOR,
    check_user_active_and_valid,
    ensure_roles,
    normalize_role,
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)
SESSION_COOKIE_NAME = "fiq_session"
CSRF_COOKIE_NAME = "fiq_csrf"
CSRF_HEADER_NAME = "x-csrf-token"


class UIAuthRedirectException(Exception):
    """Signals unauthenticated UI HTML request requiring redirect to /login."""
    def __init__(self, target_url: str = "/login"):
        self.target_url = target_url
        super().__init__(target_url)


class UIAccessDeniedException(Exception):
    """Signals authenticated UI HTML request blocked due to insufficient role or ownership."""
    def __init__(self, detail: str = "You do not have permission to view this page.", user: Optional[Dict[str, Any]] = None):
        self.detail = detail
        self.user = user
        super().__init__(detail)


def get_repository(db: Optional[Session] = Depends(get_db)) -> FootprintIQRepository:
    """Dependency for data access repository bound to current transactional session."""
    return FootprintIQRepository(db=db)


def get_auth_service(repo: FootprintIQRepository = Depends(get_repository)) -> AuthService:
    """Dependency for authentication service."""
    return AuthService(repo=repo)


def _resolve_authenticated_user(
    request: Request,
    token: Optional[str],
    repo: FootprintIQRepository
) -> Optional[Dict[str, Any]]:
    """Resolves verified active user record from Bearer JWT or fiq_session cookie, else None."""
    cookie_token = request.cookies.get(SESSION_COOKIE_NAME) if request else None
    effective_token = token or cookie_token
    if not effective_token:
        return None

    payload = decode_access_token(effective_token)
    if not payload:
        return None

    username = payload.get("sub")
    if not username:
        return None

    user = repo.get_user_by_username(username)
    if not user:
        return None
    token_tv = payload.get("tv")
    if token_tv is not None and int(token_tv) != int(user.get("token_version", 1) or 1):
        return None
    # Strip password hash before passing user dictionary around dependencies
    safe_user = {k: v for k, v in user.items() if k != "hashed_password"}
    safe_user["csrf_token"] = payload.get("csrf")
    return safe_user


def get_optional_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    repo: FootprintIQRepository = Depends(get_repository)
) -> Optional[Dict[str, Any]]:
    """Returns active, valid authenticated user if session/token is valid, otherwise None."""
    user = _resolve_authenticated_user(request, token, repo)
    if not user:
        return None
    if not user.get("is_active", False) or not user.get("is_approved", False) or normalize_role(user.get("role")) is None:
        return None
    return user


def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    repo: FootprintIQRepository = Depends(get_repository)
) -> Dict[str, Any]:
    """
    Strictly validates Bearer JWT token or HTTP-only session cookie.
    Enforces default-deny against inactive, unapproved, or unknown-role accounts.
    """
    user = _resolve_authenticated_user(request, token, repo)
    check_user_active_and_valid(user)
    return user


def _is_html_request(request: Request) -> bool:
    accept = (request.headers.get("accept") or "").lower()
    return "text/html" in accept or "*/*" in accept or not accept


def get_current_user_ui(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    repo: FootprintIQRepository = Depends(get_repository)
) -> Dict[str, Any]:
    """
    Validates operator session for HTML UI routes.
    Redirects unauthenticated browser sessions cleanly to /login without leaking data.
    """
    user = _resolve_authenticated_user(request, token, repo)
    if not user:
        if _is_html_request(request):
            raise UIAuthRedirectException("/login")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required."
        )
    try:
        check_user_active_and_valid(user)
    except HTTPException as exc:
        if _is_html_request(request):
            raise UIAccessDeniedException(exc.detail, user=user)
        raise
    return user


def require_admin(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository),
) -> Dict[str, Any]:
    """Ensures current user strictly possesses Administrator role."""
    return ensure_roles(
        current_user,
        [ROLE_ADMIN],
        repo=repo,
        request=request,
        action="PERMISSION_DENIED",
        detail="Administrator privileges required.",
    )


def require_investigator(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository),
) -> Dict[str, Any]:
    """
    Ensures current user strictly possesses Investigator role for execution endpoints.
    Administrators have full read oversight and are intentionally blocked from execution.
    """
    return ensure_roles(
        current_user,
        [ROLE_INVESTIGATOR],
        repo=repo,
        request=request,
        action="PERMISSION_DENIED",
        detail="Investigator execution privileges required. Administrators are restricted to read-only oversight for investigations and scans.",
    )


def require_admin_ui(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
) -> Dict[str, Any]:
    """UI route guard requiring Admin role; renders branded 403 HTML page on violation."""
    try:
        return ensure_roles(
            current_user,
            [ROLE_ADMIN],
            repo=repo,
            request=request,
            action="PERMISSION_DENIED",
            detail="Administrator privileges required to access this administration view.",
        )
    except HTTPException as exc:
        if _is_html_request(request):
            raise UIAccessDeniedException(exc.detail, user=current_user)
        raise


def require_investigator_ui(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
) -> Dict[str, Any]:
    """UI route guard requiring Investigator role for campaign creation/configuration pages."""
    try:
        return ensure_roles(
            current_user,
            [ROLE_INVESTIGATOR],
            repo=repo,
            request=request,
            action="PERMISSION_DENIED",
            detail="Investigator privileges required. Administrators cannot create or reconfigure investigation campaigns.",
        )
    except HTTPException as exc:
        if _is_html_request(request):
            raise UIAccessDeniedException(exc.detail, user=current_user)
        raise
