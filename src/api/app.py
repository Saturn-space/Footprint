"""
FootprintIQ - Enterprise FastAPI Application Entry Point
Integrates OSINT reconnaissance (theHarvester, WHOIS/RDAP/DNS), Nmap network scanning,
Nmap NSE scripts, ProjectDiscovery Nuclei, Tenable Nessus, Investigation Entity Graph
correlation, SQL Server 2022 Express, and SeaweedFS object storage.
"""

import os
import sys
import hmac
import logging
from urllib.parse import urlparse
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Load environment configuration (.env)
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(PROJECT_ROOT, ".env"))
except ImportError:
    pass

from src.api.routers import (
    auth, investigations, targets, scans, findings, evidence, reports, health, ui, recon, nessus, nuclei, graph, admin
)
from src.db.session import init_engine
from src.db.repository import FootprintIQRepository
from src.services.auth_service import AuthService, decode_access_token
from src.api.dependencies import (
    UIAuthRedirectException,
    UIAccessDeniedException,
    SESSION_COOKIE_NAME,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("FootprintIQ")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup & shutdown lifecycle handler.
    Initializes DB engine, default admin, initial investigation, and authorized target.
    """
    logger.info("Initializing FootprintIQ platform...")
    init_engine()

    repo = FootprintIQRepository()
    # Initialize default demo accounts (1 admin, 2 investigators) without fabricating campaigns or targets
    AuthService(repo=repo)

    # Execute Post-Restart Recovery & Scan Reconciliation (ACID Durability)
    try:
        reconciled = repo.reconcile_interrupted_scans()
        if reconciled.get("reconciled_scans") or reconciled.get("reconciled_campaigns"):
            logger.info(
                f"[Durability Recovery] Reconciled interrupted executions on restart: "
                f"{len(reconciled.get('reconciled_scans', []))} scans, "
                f"{len(reconciled.get('reconciled_campaigns', []))} campaigns."
            )
    except Exception as e:
        logger.warning(f"Startup scan durability recovery notice: {e}")

    # Seed high-fidelity combined scanning demo investigations
    try:
        from src.services.demo_seeder import seed_demo_investigations
        seeded = seed_demo_investigations(repo=repo)
        if seeded:
            logger.info(f"[DemoSeeder] {len(seeded)} demo combined investigations verified/ready.")
    except Exception as e:
        logger.warning(f"Demo investigation seeder notice: {e}")

    yield
    logger.info("FootprintIQ platform shutdown complete.")


# Initialize FastAPI app
_enable_public_docs = os.getenv("ENABLE_PUBLIC_API_DOCS", "false").lower() == "true"

app = FastAPI(
    title="FootprintIQ API",
    description="Digital Footprint Investigation, OSINT Reconnaissance & Vulnerability Assessment Platform",
    version="2.0-Enterprise",
    docs_url="/docs" if _enable_public_docs else None,
    redoc_url="/redoc" if _enable_public_docs else None,
    openapi_url="/openapi.json" if _enable_public_docs else None,
    lifespan=lifespan
)

# Trusted Localhost & Enterprise Origins
TRUSTED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=TRUSTED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
)

# Static files mount
static_dir = os.path.join(PROJECT_ROOT, "src", "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")


_templates_dir = os.path.join(PROJECT_ROOT, "src", "templates")
_error_templates = Jinja2Templates(directory=_templates_dir)


@app.exception_handler(UIAuthRedirectException)
async def ui_auth_redirect_handler(request: Request, exc: UIAuthRedirectException):
    return RedirectResponse(url=exc.target_url, status_code=303)


@app.exception_handler(UIAccessDeniedException)
async def ui_access_denied_handler(request: Request, exc: UIAccessDeniedException):
    user = exc.user
    role = (user or {}).get("role")
    return _error_templates.TemplateResponse(
        request=request,
        name="access_denied.html",
        context={
            "active_page": "error",
            "current_user": user,
            "is_admin": role == "admin",
            "is_investigator": role == "investigator",
            "csrf_token": (user or {}).get("csrf_token") or request.cookies.get(CSRF_COOKIE_NAME, ""),
            "detail": exc.detail,
        },
        status_code=403,
    )


def _is_same_origin(request: Request) -> bool:
    origin = request.headers.get("origin") or request.headers.get("referer")
    if not origin:
        return True
    parsed = urlparse(origin)
    req_host = (request.headers.get("host") or "").split(":")[0].lower()
    origin_host = (parsed.hostname or "").lower()
    if not origin_host:
        return True
    if req_host and origin_host == req_host:
        return True
    return any(urlparse(allowed).hostname == origin_host for allowed in TRUSTED_ORIGINS)


# Security Headers & Cookie-Session CSRF Protection Middleware
@app.middleware("http")
async def add_security_headers_and_csrf(request: Request, call_next):
    csrf_exempt_paths = {"/api/v1/auth/login", "/api/v1/auth/register"}
    method = request.method.upper()
    has_bearer = (request.headers.get("authorization") or "").lower().startswith("bearer ")
    session_cookie = request.cookies.get(SESSION_COOKIE_NAME)

    if method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path not in csrf_exempt_paths:
        if not _is_same_origin(request):
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF validation failed: cross-origin state-changing request rejected."},
            )
        if session_cookie and not has_bearer:
            payload = decode_access_token(session_cookie)
            if payload and payload.get("csrf"):
                expected_csrf = str(payload["csrf"])
                cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME) or ""
                header_csrf = request.headers.get(CSRF_HEADER_NAME) or ""
                if (
                    not cookie_csrf
                    or not header_csrf
                    or not hmac.compare_digest(cookie_csrf, expected_csrf)
                    or not hmac.compare_digest(header_csrf, expected_csrf)
                ):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF token missing or invalid."},
                    )

    response = await call_next(request)
    if (
        method == "GET"
        and session_cookie
        and not request.cookies.get(CSRF_COOKIE_NAME)
    ):
        payload = decode_access_token(session_cookie)
        if payload and payload.get("csrf"):
            response.set_cookie(
                key=CSRF_COOKIE_NAME,
                value=str(payload["csrf"]),
                httponly=False,
                samesite="lax",
                max_age=28800,
            )

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Server"] = "FootprintIQ-Engine"
    return response

# Include all API routers
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(recon.router)
app.include_router(investigations.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(evidence.router)
app.include_router(reports.router)
app.include_router(health.router)
app.include_router(nessus.router)
app.include_router(nuclei.router)
app.include_router(graph.router)

# Include UI Dashboard router
app.include_router(ui.router)

