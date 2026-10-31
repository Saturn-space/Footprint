"""FastAPI application factory, middleware, routing, and centralized exception handling."""

import os
import uuid
import time
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any
from pathlib import Path
from fastapi import FastAPI, Request, status, Depends, Form
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from urllib.parse import quote
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.config import get_settings, Settings
from app.logging_config import setup_logging, get_logger, request_id_ctx
from app.database import engine, get_db, check_database_connection, SessionLocal
from app.models.investigation import InvestigationModel
from app.models.user import UserModel
from app.api.health import router as health_router
from app.api.investigations import router as investigations_router
from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.api.audit import router as audit_router
from app.api.recon import router as recon_router
from app.api.authorizations import router as authorizations_router
from app.api.nmap_scans import router as nmap_scans_router
from app.api.vulnerability import router as vulnerability_router
from app.api.web_dashboard import router as web_dashboard_router
from app.api.deps import (

    get_current_user_optional,
    get_session_token_from_request,
)
from app.core.auth import (
    authenticate_user,
    create_user_session,
    invalidate_session,
    log_audit_event,
)
from app.core.security import (
    generate_csrf_token,
    is_safe_redirect_url,
    validate_password_strength,
    hash_password,
    ROLE_ANALYST,
    ROLE_ADMINISTRATOR,
    has_permission,
)
import hmac

logger = get_logger("footprintiq.app")

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle management."""
    settings = app.state.settings
    setup_logging(log_level=settings.LOG_LEVEL, log_format=settings.LOG_FORMAT)
    logger.info(
        f"Starting {settings.APP_NAME} v{settings.APP_VERSION} [env={settings.APP_ENV}, debug={settings.DEBUG}]"
    )

    # Startup validation: verify database probe
    is_ok, msg = check_database_connection()
    if is_ok:
        logger.info(f"Database connectivity confirmed ({settings.DATABASE_URL.split('://')[0]}).")
    else:
        logger.warning(f"Database startup probe warning: {msg}")

    yield

    logger.info(f"Shutting down {settings.APP_NAME} runtime.")


def create_app(settings: Settings = None) -> FastAPI:
    """Application factory providing configurable settings for testing and deployment."""
    app_settings = settings or get_settings()

    app = FastAPI(
        title=app_settings.APP_NAME,
        version=app_settings.APP_VERSION,
        description="Authorized cybersecurity reconnaissance and digital footprint investigation platform.",
        docs_url="/docs" if not app_settings.is_production else None,
        redoc_url="/redoc" if not app_settings.is_production else None,
        lifespan=lifespan
    )

    # Store settings on app state
    app.state.settings = app_settings

    # Mount static assets
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Configure Jinja2 templates
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    # =========================================================================
    # Request Correlation & Timing Middleware
    # =========================================================================
    @app.middleware("http")
    async def correlation_id_middleware(request: Request, call_next):
        req_id = request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:12]}"
        token = request_id_ctx.set(req_id)
        request.state.request_id = req_id

        # Enforce the browser access boundary before dashboard handlers can
        # query or render operational data. API handlers retain their finer
        # grained permission checks.
        path = request.url.path
        public_paths = {
            "/", "/login", "/signup", "/auth/login", "/auth/signup",
            "/auth/logout", "/access-denied", "/health/badge",
            "/api/v1/health", "/api/v1/auth/login", "/api/v1/auth/signup",
        }
        is_api = path.startswith("/api/v1/")
        is_operational_page = path == "/dashboard" or path.startswith((
            "/investigations", "/findings", "/scans", "/evidence",
            "/audit", "/admin/",
        ))
        is_protected = (
            is_api and path not in public_paths
        ) or (
            not is_api and is_operational_page and path not in public_paths
        )
        if is_protected:
            override = request.app.dependency_overrides.get(get_db)
            db_generator = override() if override else None
            db = next(db_generator) if db_generator else SessionLocal()
            try:
                current_user = get_current_user_optional(request, db=db)
            finally:
                if db_generator is None:
                    db.close()
            if not current_user:
                if is_api:
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content={"error": {"status_code": 401, "message": "Authentication required", "request_id": req_id}},
                        headers={"WWW-Authenticate": "Bearer", "X-Request-ID": req_id},
                    )
                target = request.url.path + ("?" + request.url.query if request.url.query else "")
                return RedirectResponse(
                    url=f"/login?next={quote(target, safe='/')}",
                    status_code=status.HTTP_303_SEE_OTHER,
                    headers={"X-Request-ID": req_id},
                )
            role_restricted = path.startswith(("/admin/", "/audit"))
            if role_restricted and current_user.role != ROLE_ADMINISTRATOR:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"error": {"status_code": 403, "message": "Administrator role required", "request_id": req_id}},
                    headers={"X-Request-ID": req_id},
                )
            required_permission = None
            if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not is_api:
                if path == "/investigations":
                    required_permission = "investigation.create"
                elif "/scans/nmap" in path:
                    required_permission = "recon.active"
                elif "/scans/vuln" in path:
                    required_permission = "vulnerability.scan"
                elif "/recon/passive" in path:
                    required_permission = "recon.passive"
                elif "/authorizations" in path:
                    required_permission = "scope.manage"
                elif path.startswith("/investigations/"):
                    required_permission = "investigation.create"
            if required_permission and not has_permission(current_user.role, required_permission):
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"error": {"status_code": 403, "message": f"Operation requires permission: {required_permission}", "request_id": req_id}},
                    headers={"X-Request-ID": req_id},
                )

        start_time = time.perf_counter()
        try:
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start_time) * 1000

            response.headers["X-Request-ID"] = req_id
            response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"

            # Browser security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            if app_settings.is_production:
                response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

            # Avoid logging static asset requests at INFO level
            if not request.url.path.startswith("/static"):
                logger.info(
                    f"{request.method} {request.url.path} -> {response.status_code} ({duration_ms:.1f}ms)"
                )
            return response
        finally:
            request_id_ctx.reset(token)

    # =========================================================================
    # Centralized Exception Handlers (Sanitized, No Stack Leaks)
    # =========================================================================
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        req_id = getattr(request.state, "request_id", "unknown")
        detail = exc.detail

        # If 403 Forbidden for browser HTML requests, render access denied page
        accept_header = request.headers.get("Accept", "")
        if exc.status_code == 403 and "text/html" in accept_header and not request.url.path.startswith("/api/"):
            current_user = get_current_user_optional(request, db=next(get_db()))
            return templates.TemplateResponse(
                request=request,
                name="access_denied.html",
                status_code=403,
                context={
                    "app_name": app_settings.APP_NAME,
                    "app_version": app_settings.APP_VERSION,
                    "app_env": app_settings.APP_ENV,
                    "current_user": current_user,
                    "csrf_token": request.cookies.get(app_settings.CSRF_COOKIE_NAME, ""),
                }
            )

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "status_code": exc.status_code,
                    "message": detail if isinstance(detail, (str, dict)) else str(detail),
                    "request_id": req_id
                }
            },
            headers={"X-Request-ID": req_id}
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        req_id = getattr(request.state, "request_id", "unknown")
        logger.info(f"Validation failure on {request.method} {request.url.path}: {exc.errors()}")
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "status_code": 422,
                    "message": "Request validation failed",
                    "details": exc.errors(),
                    "request_id": req_id
                }
            },
            headers={"X-Request-ID": req_id}
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        req_id = getattr(request.state, "request_id", "unknown")
        logger.error(f"Unhandled server error on {request.method} {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "status_code": 500,
                    "message": "An internal server error occurred. Please contact the administrator with the request ID.",
                    "request_id": req_id
                }
            },
            headers={"X-Request-ID": req_id}
        )

    # =========================================================================
    # Routers Mount
    # =========================================================================
    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(users_router)
    app.include_router(audit_router)
    app.include_router(investigations_router)
    app.include_router(recon_router)
    app.include_router(authorizations_router)
    app.include_router(nmap_scans_router)
    app.include_router(vulnerability_router)
    app.include_router(web_dashboard_router)


    # =========================================================================
    # Dashboard HTML & Web Authentication Routes (Jinja2 + HTMX)
    # =========================================================================
    @app.get("/login", response_class=HTMLResponse, include_in_schema=False)
    def render_login(
        request: Request,
        next: str = "/",
        logged_out: Optional[str] = None,
        registered: Optional[str] = None,
        db: Session = Depends(get_db),
    ):
        """Renders login page or redirects if already authenticated."""
        safe_next = next if is_safe_redirect_url(next) else "/"
        current_user = get_current_user_optional(request, db=db)
        if current_user:
            return RedirectResponse(url=safe_next, status_code=status.HTTP_303_SEE_OTHER)

        csrf_token = request.cookies.get(app_settings.CSRF_COOKIE_NAME) or generate_csrf_token()
        message = None
        if logged_out:
            message = "You have been logged out safely."
        elif registered:
            message = "Account successfully registered! Please sign in with your credentials."

        response = templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "app_name": app_settings.APP_NAME,
                "app_version": app_settings.APP_VERSION,
                "app_env": app_settings.APP_ENV,
                "current_user": None,
                "csrf_token": csrf_token,
                "next_url": safe_next,
                "message": message,
                "error": None,
                "allow_public_signup": app_settings.ALLOW_PUBLIC_SIGNUP,
            }
        )
        # Ensure CSRF cookie is set
        if not request.cookies.get(app_settings.CSRF_COOKIE_NAME):
            response.set_cookie(
                key=app_settings.CSRF_COOKIE_NAME,
                value=csrf_token,
                max_age=app_settings.SESSION_MAX_AGE_SECONDS,
                secure=app_settings.cookie_secure,
                samesite=app_settings.SESSION_COOKIE_SAMESITE,
                path="/",
            )
        return response

    @app.post("/auth/login", include_in_schema=False)
    async def handle_login(
        request: Request,
        username_or_email: str = Form(...),
        password: str = Form(...),
        csrf_token: str = Form(...),
        next: str = Form("/"),
        db: Session = Depends(get_db),
    ):
        """Handles web browser login form submission with CSRF check and session issuance."""
        client_ip = request.client.host if request.client else None
        req_id = getattr(request.state, "request_id", None)
        user_agent = request.headers.get("user-agent")
        safe_next = next if is_safe_redirect_url(next) else "/"

        # 1. CSRF validation
        expected_csrf = request.cookies.get(app_settings.CSRF_COOKIE_NAME)
        if not expected_csrf or not hmac.compare_digest(csrf_token.strip(), expected_csrf.strip()):
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                status_code=403,
                context={
                    "app_name": app_settings.APP_NAME,
                    "app_version": app_settings.APP_VERSION,
                    "app_env": app_settings.APP_ENV,
                    "current_user": None,
                    "csrf_token": expected_csrf or generate_csrf_token(),
                    "next_url": safe_next,
                    "error": "Security validation failed (CSRF mismatch). Please reload the page.",
                    "allow_public_signup": app_settings.ALLOW_PUBLIC_SIGNUP,
                }
            )

        # 2. Authenticate user
        try:
            user = authenticate_user(
                db=db,
                username_or_email=username_or_email,
                password=password,
                client_ip=client_ip,
                request_id=req_id,
            )
        except StarletteHTTPException:
            new_csrf = generate_csrf_token()
            res = templates.TemplateResponse(
                request=request,
                name="login.html",
                status_code=401,
                context={
                    "app_name": app_settings.APP_NAME,
                    "app_version": app_settings.APP_VERSION,
                    "app_env": app_settings.APP_ENV,
                    "current_user": None,
                    "csrf_token": new_csrf,
                    "next_url": safe_next,
                    "error": "Invalid username or password. Please verify your credentials.",
                    "allow_public_signup": app_settings.ALLOW_PUBLIC_SIGNUP,
                }
            )
            res.set_cookie(
                key=app_settings.CSRF_COOKIE_NAME,
                value=new_csrf,
                max_age=app_settings.SESSION_MAX_AGE_SECONDS,
                secure=app_settings.cookie_secure,
                samesite=app_settings.SESSION_COOKIE_SAMESITE,
                path="/",
            )
            return res

        # 3. Create authenticated session
        raw_token, session = create_user_session(
            db=db,
            user=user,
            ip_address=client_ip,
            user_agent=user_agent,
            max_age_seconds=app_settings.SESSION_MAX_AGE_SECONDS,
        )

        redirect_res = RedirectResponse(url=safe_next, status_code=status.HTTP_303_SEE_OTHER)

        # Attach session and CSRF cookies
        redirect_res.set_cookie(
            key=app_settings.SESSION_COOKIE_NAME,
            value=raw_token,
            max_age=app_settings.SESSION_MAX_AGE_SECONDS,
            httponly=True,
            secure=app_settings.cookie_secure,
            samesite=app_settings.SESSION_COOKIE_SAMESITE,
            path="/",
        )
        fresh_csrf = generate_csrf_token()
        redirect_res.set_cookie(
            key=app_settings.CSRF_COOKIE_NAME,
            value=fresh_csrf,
            max_age=app_settings.SESSION_MAX_AGE_SECONDS,
            secure=app_settings.cookie_secure,
            samesite=app_settings.SESSION_COOKIE_SAMESITE,
            path="/",
        )
        return redirect_res

    @app.get("/signup", response_class=HTMLResponse, include_in_schema=False)
    def render_signup(
        request: Request,
        db: Session = Depends(get_db),
    ):
        """Renders self-service signup page or redirects if already authenticated."""
        current_user = get_current_user_optional(request, db=db)
        if current_user:
            return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

        csrf_token = request.cookies.get(app_settings.CSRF_COOKIE_NAME) or generate_csrf_token()

        response = templates.TemplateResponse(
            request=request,
            name="signup.html",
            context={
                "app_name": app_settings.APP_NAME,
                "app_version": app_settings.APP_VERSION,
                "app_env": app_settings.APP_ENV,
                "current_user": None,
                "csrf_token": csrf_token,
                "error": None,
                "allow_public_signup": app_settings.ALLOW_PUBLIC_SIGNUP,
            }
        )
        if not request.cookies.get(app_settings.CSRF_COOKIE_NAME):
            response.set_cookie(
                key=app_settings.CSRF_COOKIE_NAME,
                value=csrf_token,
                max_age=app_settings.SESSION_MAX_AGE_SECONDS,
                secure=app_settings.cookie_secure,
                samesite=app_settings.SESSION_COOKIE_SAMESITE,
                path="/",
            )
        return response

    @app.post("/auth/signup", include_in_schema=False)
    async def handle_signup(
        request: Request,
        username: str = Form(...),
        email: str = Form(...),
        full_name: Optional[str] = Form(None),
        password: str = Form(...),
        confirm_password: str = Form(...),
        csrf_token: str = Form(...),
        db: Session = Depends(get_db),
    ):
        """Processes self-service registration form submission with strict server-side validation."""
        client_ip = request.client.host if request.client else None
        req_id = getattr(request.state, "request_id", None)

        expected_csrf = request.cookies.get(app_settings.CSRF_COOKIE_NAME)
        if not expected_csrf or not hmac.compare_digest(csrf_token.strip(), expected_csrf.strip()):
            return templates.TemplateResponse(
                request=request,
                name="signup.html",
                status_code=403,
                context={
                    "app_name": app_settings.APP_NAME,
                    "app_version": app_settings.APP_VERSION,
                    "app_env": app_settings.APP_ENV,
                    "current_user": None,
                    "csrf_token": expected_csrf or generate_csrf_token(),
                    "error": "Security validation failed (CSRF mismatch). Please reload the page.",
                    "allow_public_signup": app_settings.ALLOW_PUBLIC_SIGNUP,
                }
            )

        if not app_settings.ALLOW_PUBLIC_SIGNUP:
            return templates.TemplateResponse(
                request=request,
                name="signup.html",
                status_code=403,
                context={
                    "app_name": app_settings.APP_NAME,
                    "app_version": app_settings.APP_VERSION,
                    "app_env": app_settings.APP_ENV,
                    "current_user": None,
                    "csrf_token": expected_csrf,
                    "error": "Public registration is currently disabled by administrator policy.",
                    "allow_public_signup": False,
                }
            )

        clean_username = username.strip()
        clean_email = email.strip().lower()

        if password != confirm_password:
            return templates.TemplateResponse(
                request=request,
                name="signup.html",
                status_code=400,
                context={
                    "app_name": app_settings.APP_NAME,
                    "app_version": app_settings.APP_VERSION,
                    "app_env": app_settings.APP_ENV,
                    "current_user": None,
                    "csrf_token": expected_csrf,
                    "error": "Passwords do not match.",
                    "allow_public_signup": True,
                }
            )

        is_valid_pwd, pwd_error = validate_password_strength(password)
        if not is_valid_pwd:
            return templates.TemplateResponse(
                request=request,
                name="signup.html",
                status_code=400,
                context={
                    "app_name": app_settings.APP_NAME,
                    "app_version": app_settings.APP_VERSION,
                    "app_env": app_settings.APP_ENV,
                    "current_user": None,
                    "csrf_token": expected_csrf,
                    "error": f"Password policy violation: {pwd_error}",
                    "allow_public_signup": True,
                }
            )

        # Check existing username or email
        existing = db.execute(
            select(UserModel).where(
                (UserModel.username == clean_username) | (UserModel.email == clean_email)
            )
        ).scalars().first()
        if existing:
            return templates.TemplateResponse(
                request=request,
                name="signup.html",
                status_code=409,
                context={
                    "app_name": app_settings.APP_NAME,
                    "app_version": app_settings.APP_VERSION,
                    "app_env": app_settings.APP_ENV,
                    "current_user": None,
                    "csrf_token": expected_csrf,
                    "error": "An account with that username or email address already exists.",
                    "allow_public_signup": True,
                }
            )

        # Create new user with least-privileged role (ROLE_ANALYST, never administrator)
        new_user = UserModel(
            id=str(uuid.uuid4()),
            username=clean_username,
            email=clean_email,
            password_hash=hash_password(password),
            role=ROLE_ANALYST,
            is_active=True,
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        log_audit_event(
            db=db,
            event_type="USER_REGISTERED",
            outcome="SUCCESS",
            actor_id=new_user.id,
            target_user_id=new_user.id,
            request_id=req_id,
            ip_address=client_ip,
            details={"username": new_user.username, "role": new_user.role, "registration_type": "web_self_service"},
        )

        return RedirectResponse(url="/login?registered=1", status_code=status.HTTP_303_SEE_OTHER)

        # Attach session and CSRF cookies
        redirect_res.set_cookie(
            key=app_settings.SESSION_COOKIE_NAME,
            value=raw_token,
            max_age=app_settings.SESSION_MAX_AGE_SECONDS,
            httponly=True,
            secure=app_settings.cookie_secure,
            samesite=app_settings.SESSION_COOKIE_SAMESITE,
            path="/",
        )
        fresh_csrf = generate_csrf_token()
        redirect_res.set_cookie(
            key=app_settings.CSRF_COOKIE_NAME,
            value=fresh_csrf,
            max_age=app_settings.SESSION_MAX_AGE_SECONDS,
            secure=app_settings.cookie_secure,
            samesite=app_settings.SESSION_COOKIE_SAMESITE,
            path="/",
        )
        return redirect_res

    @app.post("/auth/logout", include_in_schema=False)
    async def handle_logout(
        request: Request,
        csrf_token: str = Form(...),
        db: Session = Depends(get_db),
    ):
        """Revokes browser session and clears cookies with CSRF defense."""
        expected_csrf = request.cookies.get(app_settings.CSRF_COOKIE_NAME)
        if not expected_csrf or not hmac.compare_digest(csrf_token.strip(), expected_csrf.strip()):
            raise StarletteHTTPException(status_code=403, detail="CSRF validation failed on logout")

        raw_token = request.cookies.get(app_settings.SESSION_COOKIE_NAME)
        if raw_token:
            invalidate_session(
                db=db,
                raw_token=raw_token,
                request_id=getattr(request.state, "request_id", None),
                client_ip=request.client.host if request.client else None,
            )

        res = RedirectResponse(url="/login?logged_out=1", status_code=status.HTTP_303_SEE_OTHER)
        res.delete_cookie(
            key=app_settings.SESSION_COOKIE_NAME,
            path="/",
            httponly=True,
            secure=app_settings.cookie_secure,
            samesite=app_settings.SESSION_COOKIE_SAMESITE,
        )
        res.delete_cookie(
            key=app_settings.CSRF_COOKIE_NAME,
            path="/",
            secure=app_settings.cookie_secure,
            samesite=app_settings.SESSION_COOKIE_SAMESITE,
        )
        return res

    @app.get("/access-denied", response_class=HTMLResponse, include_in_schema=False)
    def render_access_denied(request: Request, db: Session = Depends(get_db)):
        current_user = get_current_user_optional(request, db=db)
        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={
                "app_name": app_settings.APP_NAME,
                "app_version": app_settings.APP_VERSION,
                "app_env": app_settings.APP_ENV,
                "current_user": current_user,
                "csrf_token": request.cookies.get(app_settings.CSRF_COOKIE_NAME, ""),
            }
        )



    @app.get("/health/badge", response_class=HTMLResponse, include_in_schema=False)
    def render_health_badge(request: Request, db: Session = Depends(get_db)):
        """HTMX component returning dynamic database status badge."""
        is_connected, _ = check_database_connection(db)
        return templates.TemplateResponse(
            request=request,
            name="components/health_badge.html",
            context={"status": "ready" if is_connected else "disconnected"}
        )

    return app


# Application entry point for Uvicorn
app = create_app()
