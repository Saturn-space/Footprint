"""Web dashboard routes for FootprintIQ serving Jinja2 templates and HTMX components."""

import os
import uuid
import hmac
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Request, Depends, Form, status, Response
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select, func, or_

from app.config import get_settings
from app.database import get_db, check_database_connection
from app.models.investigation import InvestigationModel
from app.models.user import UserModel
from app.models.recon import TargetAuthorizationModel, CollectionJobModel, EvidenceModel, EntityModel
from app.models.scan import ActiveScanJobModel, ScanFindingPortModel, ScanFindingHostModel
from app.models.vulnerability import VulnerabilityScanJobModel, VulnerabilityFindingModel
from app.models.audit import AuditLogModel
from app.api.deps import get_current_user_optional, get_current_user
from app.core.security import generate_csrf_token, is_safe_redirect_url
from app.core.auth import log_audit_event
from app.services.scoring.calculator import ExposureScorer
from app.services.reporting.pdf_generator import InvestigationReportGenerator
from app.services.reporting.graphml_generator import GraphMLExporter
from app.services.active.nmap_detector import NmapDetector
from app.integrations.greenbone_client import GreenboneClient
from app.services.passive.orchestrator import PassiveReconOrchestrator
from app.services.active.runner import NmapRunner
from app.services.active.profiles import get_scan_profile
from app.services.vuln.orchestrator import get_vuln_orchestrator
from app.services.vuln.profiles import get_vuln_profile

import fastapi

settings = get_settings()
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

router = APIRouter(include_in_schema=False)


def _validate_csrf(request: Request, submitted_csrf: str):
    """Verifies CSRF token from form matches cookie."""
    expected = request.cookies.get(settings.CSRF_COOKIE_NAME)
    if not expected or not submitted_csrf or not hmac.compare_digest(submitted_csrf.strip(), expected.strip()):
        raise StarletteHTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security validation failed (CSRF token mismatch or expired). Please reload the page."
        )


def _base_context(request: Request, db: Session, active_nav: str = "") -> Dict[str, Any]:
    """Returns standard template context parameters."""
    current_user = get_current_user_optional(request, db=db)
    is_connected, _ = check_database_connection(db)
    csrf_token = request.cookies.get(settings.CSRF_COOKIE_NAME) or generate_csrf_token()

    return {
        "request": request,
        "app_name": settings.APP_NAME,
        "app_version": settings.APP_VERSION,
        "app_env": settings.APP_ENV,
        "db_dialect": "SQLite" if settings.is_sqlite else "PostgreSQL",
        "fastapi_version": fastapi.__version__,
        "is_db_connected": is_connected,
        "current_user": current_user,
        "csrf_token": csrf_token,
        "active_nav": active_nav,
    }


# =============================================================================
# Public Landing Page & Executive Dashboard
# =============================================================================
@router.get("/", response_class=HTMLResponse)
def render_landing(request: Request, db: Session = Depends(get_db)):
    """Renders the public landing page for visitors without requiring authentication."""
    ctx = _base_context(request, db=db, active_nav="home")
    ctx.update({
        "allow_public_signup": settings.ALLOW_PUBLIC_SIGNUP,
    })
    res = templates.TemplateResponse(request=request, name="landing.html", context=ctx)
    if not request.cookies.get(settings.CSRF_COOKIE_NAME):
        res.set_cookie(
            key=settings.CSRF_COOKIE_NAME,
            value=ctx["csrf_token"],
            max_age=settings.SESSION_MAX_AGE_SECONDS,
            secure=settings.cookie_secure,
            samesite=settings.SESSION_COOKIE_SAMESITE,
            path="/",
        )
    return res


@router.get("/dashboard", response_class=HTMLResponse)
def render_dashboard(request: Request, db: Session = Depends(get_db)):
    """Renders the primary executive dashboard with genuine metrics. Requires authentication."""
    current_user = get_current_user_optional(request, db=db)
    if not current_user:
        return RedirectResponse(url="/login?next=/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    ctx = _base_context(request, db=db, active_nav="dashboard")

    # Genuine counts from database
    total_invs = db.scalar(select(func.count(InvestigationModel.id))) or 0
    active_invs = db.scalar(select(func.count(InvestigationModel.id)).where(InvestigationModel.status == "active")) or 0
    completed_invs = db.scalar(select(func.count(InvestigationModel.id)).where(InvestigationModel.status == "completed")) or 0

    total_entities = db.scalar(select(func.count(EntityModel.id))) or 0
    total_evidence = db.scalar(select(func.count(EvidenceModel.id))) or 0
    total_scans = db.scalar(select(func.count(ActiveScanJobModel.id))) or 0
    total_open_ports = db.scalar(select(func.count(ScanFindingPortModel.id))) or 0
    total_vuln_scans = db.scalar(select(func.count(VulnerabilityScanJobModel.id))) or 0
    total_vulns = db.scalar(select(func.count(VulnerabilityFindingModel.id))) or 0

    # Recent investigations
    recent_invs = db.scalars(
        select(InvestigationModel).order_by(InvestigationModel.created_at.desc()).limit(10)
    ).all()

    # Tool readiness diagnostics
    nmap_diag = NmapDetector().check_availability()
    gvm_diag = GreenboneClient().check_status()

    ctx.update({
        "total_investigations": total_invs,
        "active_investigations": active_invs,
        "completed_investigations": completed_invs,
        "total_entities": total_entities,
        "total_evidence": total_evidence,
        "total_scans": total_scans,
        "total_open_ports": total_open_ports,
        "total_vuln_scans": total_vuln_scans,
        "total_vulns": total_vulns,
        "investigations": recent_invs,
        "nmap_status": "READY" if nmap_diag.get("is_available") else "UNAVAILABLE",
        "greenbone_status": gvm_diag.get("status", "NOT_CONFIGURED"),
    })

    res = templates.TemplateResponse(request=request, name="dashboard.html", context=ctx)
    if not request.cookies.get(settings.CSRF_COOKIE_NAME):
        res.set_cookie(
            key=settings.CSRF_COOKIE_NAME,
            value=ctx["csrf_token"],
            max_age=settings.SESSION_MAX_AGE_SECONDS,
            secure=settings.cookie_secure,
            samesite=settings.SESSION_COOKIE_SAMESITE,
            path="/",
        )
    return res


# =============================================================================
# Investigations Listing & Creation
# =============================================================================
@router.get("/investigations", response_class=HTMLResponse)
def render_investigations(
    request: Request,
    q: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Lists investigations with optional search query and status filter."""
    ctx = _base_context(request, db=db, active_nav="investigations")

    query = select(InvestigationModel)
    if q and q.strip():
        search_term = f"%{q.strip()}%"
        query = query.where(
            or_(
                InvestigationModel.id.ilike(search_term),
                InvestigationModel.name.ilike(search_term),
                InvestigationModel.organization_name.ilike(search_term),
                InvestigationModel.lead_investigator.ilike(search_term),
            )
        )
    if status and status.strip():
        query = query.where(InvestigationModel.status == status.strip().lower())

    investigations = db.scalars(query.order_by(InvestigationModel.created_at.desc())).all()

    ctx.update({
        "investigations": investigations,
        "search_query": q,
        "status_filter": status,
    })
    return templates.TemplateResponse(request=request, name="investigations.html", context=ctx)


@router.post("/investigations")
def handle_create_investigation(
    request: Request,
    name: str = Form(...),
    organization_name: str = Form(...),
    description: str = Form(...),
    lead_investigator: str = Form(...),
    authorization_reference: Optional[str] = Form(None),
    owned_domains: Optional[str] = Form(None),
    approved_ips: Optional[str] = Form(None),
    approved_cidrs: Optional[str] = Form(None),
    active_targets: Optional[str] = Form(None),
    active_scanning_enabled: Optional[str] = Form(None),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """Registers a new investigation campaign from the web UI."""
    _validate_csrf(request, csrf_token)
    current_user = get_current_user_optional(request, db=db)
    actor_id = current_user.id if current_user else "web-anonymous"

    # Parse comma-separated fields
    domains_list = [d.strip() for d in (owned_domains or "").split(",") if d.strip()]
    ips_list = [ip.strip() for ip in (approved_ips or "").split(",") if ip.strip()]
    cidrs_list = [c.strip() for c in (approved_cidrs or "").split(",") if c.strip()]
    active_list = [t.strip() for t in (active_targets or "").split(",") if t.strip()]
    active_bool = bool(active_scanning_enabled and active_scanning_enabled.lower() in ("true", "1", "yes", "on"))

    inv_id = f"inv-{uuid.uuid4().hex[:10]}"
    inv = InvestigationModel(
        id=inv_id,
        name=name.strip(),
        organization_name=organization_name.strip(),
        description=description.strip(),
        lead_investigator=lead_investigator.strip(),
        team_members=[],
        status="active",
        owned_domains=domains_list,
        approved_ips=ips_list,
        approved_cidrs=cidrs_list,
        active_targets=active_list,
        active_scanning_enabled=active_bool,
        authorization_reference=authorization_reference.strip() if authorization_reference else None,
    )
    db.add(inv)
    db.commit()

    log_audit_event(
        db=db,
        event_type="INVESTIGATION_CREATED",
        actor_id=actor_id,
        outcome="SUCCESS",
        details={"investigation_id": inv_id, "name": name, "organization": organization_name},
    )

    return RedirectResponse(url=f"/investigations/{inv_id}", status_code=status.HTTP_303_SEE_OTHER)


# =============================================================================
# Investigation Detail Workspace
# =============================================================================
@router.get("/investigations/{investigation_id}", response_class=HTMLResponse)
def render_investigation_detail(
    investigation_id: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """Renders the comprehensive 8-tab investigation workspace."""
    ctx = _base_context(request, db=db, active_nav="investigations")

    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise StarletteHTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")

    authorizations = db.scalars(
        select(TargetAuthorizationModel).where(TargetAuthorizationModel.investigation_id == investigation_id)
    ).all()

    entities = db.scalars(
        select(EntityModel).where(EntityModel.investigation_id == investigation_id).order_by(EntityModel.first_seen.desc())
    ).all()

    evidence_list = db.scalars(
        select(EvidenceModel).where(EvidenceModel.investigation_id == investigation_id).order_by(EvidenceModel.collected_at.desc())
    ).all()

    scan_ports = db.scalars(
        select(ScanFindingPortModel)
        .join(ScanFindingHostModel, ScanFindingPortModel.host_id == ScanFindingHostModel.id)
        .where(ScanFindingHostModel.investigation_id == investigation_id)
    ).all()

    vuln_findings = db.scalars(
        select(VulnerabilityFindingModel).where(VulnerabilityFindingModel.investigation_id == investigation_id).order_by(VulnerabilityFindingModel.cvss_score.desc().nullslast())
    ).all()

    collection_jobs = db.scalars(
        select(CollectionJobModel).where(CollectionJobModel.investigation_id == investigation_id).order_by(CollectionJobModel.started_at.desc())
    ).all()

    nmap_jobs = db.scalars(
        select(ActiveScanJobModel).where(ActiveScanJobModel.investigation_id == investigation_id).order_by(ActiveScanJobModel.started_at.desc())
    ).all()

    vuln_jobs = db.scalars(
        select(VulnerabilityScanJobModel).where(VulnerabilityScanJobModel.investigation_id == investigation_id).order_by(VulnerabilityScanJobModel.started_at.desc())
    ).all()

    # Calculate genuine 5-factor Exposure Score
    score = ExposureScorer.calculate_for_investigation(investigation_id, db=db)

    ctx.update({
        "inv": inv,
        "authorizations": authorizations,
        "entities": entities,
        "evidence_list": evidence_list,
        "scan_ports": scan_ports,
        "vuln_findings": vuln_findings,
        "collection_jobs": collection_jobs,
        "nmap_jobs": nmap_jobs,
        "vuln_jobs": vuln_jobs,
        "score": score,
    })
    return templates.TemplateResponse(request=request, name="investigation_detail.html", context=ctx)


# =============================================================================
# Target Authorization Creation from Web UI
# =============================================================================
@router.post("/investigations/{investigation_id}/authorizations")
def handle_create_authorization(
    investigation_id: str,
    request: Request,
    target: str = Form(...),
    target_type: str = Form("IP"),
    approved_by: str = Form(...),
    authorization_reference: str = Form(...),
    operations: List[str] = Form(["SCAN_PORTS", "SCAN_VULN"]),
    valid_days: int = Form(30),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """Adds an explicit target authorization record for active reconnaissance."""
    _validate_csrf(request, csrf_token)
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise StarletteHTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")

    now = datetime.now(timezone.utc)
    valid_to = now + timedelta(days=valid_days)

    authz = TargetAuthorizationModel(
        id=f"authz-{uuid.uuid4().hex[:10]}",
        investigation_id=investigation_id,
        target=target.strip(),
        target_type=target_type.strip().upper(),
        allowed_operations=operations,
        authorization_reference=authorization_reference.strip(),
        approved_by=approved_by.strip(),
        valid_from=now,
        valid_to=valid_to,
        is_revoked=False,
    )
    db.add(authz)
    db.commit()

    log_audit_event(
        db=db,
        event_type="TARGET_AUTHORIZATION_GRANTED",
        actor_id=approved_by.strip(),
        outcome="SUCCESS",
        details={
            "investigation_id": investigation_id,
            "target": target.strip(),
            "operations": operations,
            "valid_to": valid_to.isoformat(),
        },
    )

    return RedirectResponse(
        url=f"/investigations/{investigation_id}#tab-authorizations",
        status_code=status.HTTP_303_SEE_OTHER
    )


# =============================================================================
# Tool Invocations from Web UI
# =============================================================================
@router.post("/investigations/{investigation_id}/recon/passive")
async def handle_trigger_passive_recon(
    investigation_id: str,
    request: Request,
    target: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """Triggers passive reconnaissance collectors via form submission."""
    _validate_csrf(request, csrf_token)
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise StarletteHTTPException(status_code=404, detail="Investigation not found")

    current_user = get_current_user_optional(request, db=db)
    if not current_user:
        current_user = db.scalars(select(UserModel).where(UserModel.role == "administrator")).first()
    actor_id = current_user.id if current_user else "web-admin"
    orchestrator = PassiveReconOrchestrator(
        db=db,
        investigation_id=investigation_id,
        actor_user=current_user,
    )
    try:
        await orchestrator.run(target=target.strip())
    except Exception as e:
        log_audit_event(
            db=db,
            event_type="PASSIVE_RECON_LAUNCH_FAILED",
            actor_id=actor_id,
            outcome="FAILURE",
            details={"investigation_id": investigation_id, "target": target, "error": str(e)},
        )

    return RedirectResponse(
        url=f"/investigations/{investigation_id}#tab-passive",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/investigations/{investigation_id}/scans/nmap")
async def handle_trigger_nmap_scan(
    investigation_id: str,
    request: Request,
    target: str = Form(...),
    profile_id: str = Form("nmap-service-detect"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """Triggers active Nmap scan via form submission."""
    _validate_csrf(request, csrf_token)
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise StarletteHTTPException(status_code=404, detail="Investigation not found")

    current_user = get_current_user_optional(request, db=db)
    actor_id = current_user.id if current_user else "web-admin"

    profile = get_scan_profile(profile_id)
    if not profile:
        raise StarletteHTTPException(status_code=400, detail=f"Invalid scan profile '{profile_id}'")

    runner = NmapRunner()
    try:
        await runner.execute_scan(
            investigation_id=investigation_id,
            target=target.strip(),
            profile=profile,
            requested_by=actor_id,
        )
    except Exception as e:
        log_audit_event(
            db=db,
            event_type="ACTIVE_SCAN_LAUNCH_FAILED",
            actor_id=actor_id,
            outcome="FAILURE",
            details={"investigation_id": investigation_id, "target": target, "error": str(e)},
        )

    return RedirectResponse(
        url=f"/investigations/{investigation_id}#tab-active",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/investigations/{investigation_id}/scans/vuln")
async def handle_trigger_vuln_scan(
    investigation_id: str,
    request: Request,
    target: str = Form(...),
    profile_id: str = Form("openvas-basic"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """Triggers Greenbone vulnerability assessment via form submission."""
    _validate_csrf(request, csrf_token)
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise StarletteHTTPException(status_code=404, detail="Investigation not found")

    current_user = get_current_user_optional(request, db=db)
    actor_id = current_user.id if current_user else "web-admin"

    profile = get_vuln_profile(profile_id)
    if not profile:
        raise StarletteHTTPException(status_code=400, detail=f"Invalid profile '{profile_id}'")

    orchestrator = get_vuln_orchestrator()
    try:
        job = orchestrator.create_assessment_job(
            db=db,
            investigation_id=investigation_id,
            target=target.strip(),
            profile_id=profile_id,
            requested_by=actor_id,
        )
    except Exception as e:
        raise StarletteHTTPException(status_code=400, detail=str(e))

    import asyncio
    asyncio.create_task(
        orchestrator.execute_assessment_job(
            job_id=job.id,
            investigation_id=investigation_id,
            target=job.target,
            profile_id=job.profile_id,
            requested_by=actor_id,
        )
    )

    return RedirectResponse(
        url=f"/investigations/{investigation_id}#tab-vulns",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/scans/vuln/{job_id}/cancel")
def handle_cancel_vuln_scan(
    job_id: str,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """Requests cooperative cancellation of a Greenbone task."""
    _validate_csrf(request, csrf_token)
    orchestrator = get_vuln_orchestrator()
    try:
        orchestrator.cancel_job(db=db, job_id=job_id, reason="Cancelled by user via dashboard.")
    except Exception:
        pass

    return RedirectResponse(url="/scans", status_code=status.HTTP_303_SEE_OTHER)


# =============================================================================
# Consolidated PDF Report Download
# =============================================================================
@router.get("/investigations/{investigation_id}/report/pdf")
def download_investigation_pdf(
    investigation_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Generates and streams a professional ReportLab PDF dossier from persisted records."""
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise StarletteHTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")

    current_user = get_current_user_optional(request, db=db)
    actor_name = current_user.username if current_user else "Lead Analyst"

    try:
        pdf_bytes = InvestigationReportGenerator.generate_pdf(
            investigation_id=investigation_id,
            db=db,
            generated_by=actor_name,
            dossier_title="FootprintIQ Comprehensive Reconnaissance Dossier",
        )
    except Exception as e:
        raise StarletteHTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

    log_audit_event(
        db=db,
        event_type="REPORT_DOWNLOADED",
        actor_id=actor_name,
        outcome="SUCCESS",
        details={"investigation_id": investigation_id, "format": "PDF"},
    )

    filename = f"FootprintIQ-Dossier-{inv.id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        }
    )


@router.get("/investigations/{investigation_id}/report/graphml")
def download_investigation_graphml(
    investigation_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Generates and streams a standard GraphML XML export for Gephi, Cytoscape, and Maltego."""
    inv = db.get(InvestigationModel, investigation_id)
    if not inv:
        raise StarletteHTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")

    current_user = get_current_user_optional(request, db=db)
    actor_name = current_user.username if current_user else "Lead Analyst"

    try:
        xml_content = GraphMLExporter.generate_graphml(investigation_id=investigation_id, db=db)
    except Exception as e:
        raise StarletteHTTPException(status_code=500, detail=f"Failed to generate GraphML export: {str(e)}")

    log_audit_event(
        db=db,
        event_type="REPORT_DOWNLOADED",
        actor_id=actor_name,
        outcome="SUCCESS",
        details={"investigation_id": investigation_id, "format": "GRAPHML"},
    )

    filename = f"FootprintIQ-KnowledgeGraph-{inv.id}.graphml"
    return Response(
        content=xml_content,
        media_type="application/xml",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        }
    )



# =============================================================================
# Standalone Pages: Findings, Scans, Evidence, Audit, Admin
# =============================================================================
@router.get("/findings", response_class=HTMLResponse)
def render_findings(
    request: Request,
    q: Optional[str] = None,
    severity: Optional[str] = None,
    investigation_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Unified matrix of all vulnerability and exposure findings."""
    ctx = _base_context(request, db=db, active_nav="findings")

    query = select(VulnerabilityFindingModel)
    if q and q.strip():
        term = f"%{q.strip()}%"
        query = query.where(
            or_(
                VulnerabilityFindingModel.name.ilike(term),
                VulnerabilityFindingModel.host.ilike(term),
            )
        )
    if severity and severity.strip():
        query = query.where(VulnerabilityFindingModel.severity == severity.strip().lower())
    if investigation_id and investigation_id.strip():
        query = query.where(VulnerabilityFindingModel.investigation_id == investigation_id.strip())

    findings = db.scalars(query.order_by(VulnerabilityFindingModel.cvss_score.desc().nullslast())).all()
    investigations = db.scalars(select(InvestigationModel).order_by(InvestigationModel.name.asc())).all()

    ctx.update({
        "findings": findings,
        "investigations": investigations,
        "search_query": q,
        "severity_filter": severity,
        "inv_filter": investigation_id,
    })
    return templates.TemplateResponse(request=request, name="findings.html", context=ctx)


@router.get("/scans", response_class=HTMLResponse)
def render_scans(request: Request, db: Session = Depends(get_db)):
    """Live scan execution monitor for passive, Nmap, and Greenbone jobs."""
    ctx = _base_context(request, db=db, active_nav="scans")

    vuln_jobs = db.scalars(select(VulnerabilityScanJobModel).order_by(VulnerabilityScanJobModel.started_at.desc()).limit(25)).all()
    nmap_jobs = db.scalars(select(ActiveScanJobModel).order_by(ActiveScanJobModel.started_at.desc()).limit(25)).all()
    collection_jobs = db.scalars(select(CollectionJobModel).order_by(CollectionJobModel.started_at.desc()).limit(25)).all()

    ctx.update({
        "vuln_jobs": vuln_jobs,
        "nmap_jobs": nmap_jobs,
        "collection_jobs": collection_jobs,
    })
    return templates.TemplateResponse(request=request, name="scans.html", context=ctx)


@router.get("/evidence", response_class=HTMLResponse)
def render_evidence(request: Request, db: Session = Depends(get_db)):
    """Forensic evidence ledger with SHA-256 hashes."""
    ctx = _base_context(request, db=db, active_nav="evidence")

    evidence_list = db.scalars(select(EvidenceModel).order_by(EvidenceModel.collected_at.desc()).limit(50)).all()
    ctx.update({"evidence_list": evidence_list})
    return templates.TemplateResponse(request=request, name="evidence.html", context=ctx)


@router.get("/audit", response_class=HTMLResponse)
def render_audit(request: Request, db: Session = Depends(get_db)):
    """Security audit trail browser."""
    ctx = _base_context(request, db=db, active_nav="audit")

    audit_logs = db.scalars(select(AuditLogModel).order_by(AuditLogModel.timestamp.desc()).limit(50)).all()
    ctx.update({"audit_logs": audit_logs})
    return templates.TemplateResponse(request=request, name="audit.html", context=ctx)


@router.get("/admin/authorizations", response_class=HTMLResponse)
def render_admin_authorizations(request: Request, db: Session = Depends(get_db)):
    """Administrative target allowlist management."""
    ctx = _base_context(request, db=db, active_nav="admin")

    authorizations = db.scalars(select(TargetAuthorizationModel).order_by(TargetAuthorizationModel.created_at.desc())).all()
    ctx.update({"authorizations": authorizations})
    return templates.TemplateResponse(request=request, name="admin_authorizations.html", context=ctx)


@router.post("/admin/authorizations/{authorization_id}/revoke")
def handle_revoke_authorization(
    authorization_id: str,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """Revokes a target authorization record."""
    _validate_csrf(request, csrf_token)
    authz = db.get(TargetAuthorizationModel, authorization_id)
    if not authz:
        raise StarletteHTTPException(status_code=404, detail=f"Authorization '{authorization_id}' not found.")

    authz.is_revoked = True
    db.commit()

    current_user = get_current_user_optional(request, db=db)
    actor_id = current_user.username if current_user else "admin"

    log_audit_event(
        db=db,
        event_type="TARGET_AUTHORIZATION_REVOKED",
        actor_id=actor_id,
        outcome="SUCCESS",
        details={"authorization_id": authorization_id, "target": authz.target},
    )

    return RedirectResponse(url="/admin/authorizations", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/admin/tools", response_class=HTMLResponse)
def render_admin_tools(request: Request, db: Session = Depends(get_db)):
    """Scanner availability and diagnostic inspection."""
    ctx = _base_context(request, db=db, active_nav="admin")

    nmap_diag = NmapDetector().check_availability()
    greenbone_diag = GreenboneClient().check_status()

    ctx.update({
        "nmap_diag": nmap_diag,
        "greenbone_diag": greenbone_diag,
    })
    return templates.TemplateResponse(request=request, name="admin_tools.html", context=ctx)
