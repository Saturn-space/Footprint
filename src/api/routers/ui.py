"""
FootprintIQ - UI Web Dashboard Router
Renders RBAC-scoped Jinja2 HTML templates with server-side ownership enforcement:
- / (Main Dashboard)
- /recon, /recon/new, /recon/{recon_id}/workspace, /recon/{recon_id}/live, /recon/{recon_id}/results, /recon/{recon_id}/pdf
- /investigations, /scans, /findings, /evidence
- /reports, /reports/{report_id} (Integrated Report Details & Analyse Report)
- /settings, /login
- /admin/users, /admin/scanners, /admin/system, /admin/audit-logs
"""

import os
import re
import json
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any, List, Set

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse

from src.db.repository import FootprintIQRepository
from src.services.exposure_scoring import ExposureScoringEngine
from src.services.scan_options_service import ScanOptionsService
from src.services.recon_results_helper import load_campaign_results_bundle, enrich_findings_with_explanations
from src.services.report_analysis_service import (
    REPORTS_DIR as ANALYSIS_REPORTS_DIR,
    build_investigation_report_filename,
    build_report_analysis,
    extract_report_file_metadata,
    normalize_report_type_tag,
    resolve_report_record,
)
from src.services.rbac_service import (
    ROLE_ADMIN,
    ROLE_INVESTIGATOR,
    enforce_investigation_access,
    filter_accessible_investigation_ids,
    is_admin_user,
    is_investigator_user,
    normalize_role,
    record_security_audit,
)
from src.authorization.target_authorizer import TargetAuthorizer
from src.orchestration.execution_manager import ExecutionManager
from src.utils.timezone import (
    duration_human,
    format_ist,
    format_ist_date,
    format_ist_short,
)
from src.api.dependencies import (
    CSRF_COOKIE_NAME,
    UIAccessDeniedException,
    get_current_user_ui,
    get_optional_current_user,
    get_repository,
    require_admin_ui,
    require_investigator_ui,
)

TEMPLATES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "templates"))
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
REPORTS_DIR = ANALYSIS_REPORTS_DIR
templates = Jinja2Templates(directory=TEMPLATES_DIR)
templates.env.filters["ist"] = format_ist
templates.env.filters["ist_short"] = format_ist_short
templates.env.filters["ist_date"] = format_ist_date
templates.env.filters["duration_fmt"] = lambda s: duration_human(None, None, s)
templates.env.filters["basename"] = lambda p: os.path.basename(str(p or ""))

router = APIRouter(include_in_schema=False)


def _filter_scoped_list(
    items: List[Dict[str, Any]],
    accessible_ids: Optional[Set[str]],
    *id_keys: str,
) -> List[Dict[str, Any]]:
    """Filters list of records against allowed investigation/recon IDs (None = Admin unfiltered)."""
    if accessible_ids is None:
        return items
    keys = id_keys or ("investigation_id", "recon_id")
    filtered: List[Dict[str, Any]] = []
    for item in items:
        if any(item.get(k) in accessible_ids for k in keys if item.get(k)):
            filtered.append(item)
    return filtered


def _enforce_ui_investigation_access(
    repo: FootprintIQRepository,
    current_user: Dict[str, Any],
    investigation_id: str,
    request: Request,
    *,
    require_execution: bool = False,
    action_label: str = "UI_INVESTIGATION_VIEW",
) -> Dict[str, Any]:
    """Converts RBAC 403 HTTPExceptions into branded HTML Access Denied responses for browser UI."""
    try:
        return enforce_investigation_access(
            repo,
            current_user,
            investigation_id,
            require_execution=require_execution,
            request=request,
            action_label=action_label,
        )
    except HTTPException as exc:
        if exc.status_code == 403:
            raise UIAccessDeniedException(str(exc.detail), user=current_user)
        raise


def _get_existing_reports(
    repo: Optional[FootprintIQRepository] = None,
    accessible_ids: Optional[Set[str]] = None,
    scan_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    db_by_file: Dict[str, Dict[str, Any]] = {}
    if repo is not None:
        try:
            for r in repo.list_report_records(scan_id=scan_id):
                db_by_file[r["file_name"]] = r
        except Exception:
            pass

    inv_name_cache: Dict[str, str] = {}
    reports: List[Dict[str, Any]] = []
    if os.path.exists(REPORTS_DIR):
        files_sorted = sorted(
            [fn for fn in os.listdir(REPORTS_DIR) if fn.endswith(".pdf")],
            key=lambda fn: os.path.getmtime(os.path.join(REPORTS_DIR, fn)),
            reverse=True,
        )
        for f in files_sorted:
            full_path = os.path.join(REPORTS_DIR, f)
            if not os.path.isfile(full_path):
                continue
            stat = os.stat(full_path)
            meta = extract_report_file_metadata(f)
            db_rec = db_by_file.get(f)
            if scan_id and (not db_rec or db_rec.get("scan_id") != scan_id):
                continue
            fmt = (db_rec.get("report_type") if db_rec else None) or meta["report_format"]
            inv_id = (
                (db_rec.get("recon_id") if db_rec else None)
                or (db_rec.get("investigation_id") if db_rec else None)
                or meta["investigation_id"]
            )
            if accessible_ids is not None and inv_id not in accessible_ids:
                continue

            inv_name = (db_rec.get("investigation_name") if db_rec else None)
            if not inv_name and repo is not None and inv_id and inv_id != "UNKNOWN":
                if inv_id not in inv_name_cache:
                    c = repo.get_recon_campaign(inv_id)
                    i = repo.get_investigation(inv_id) if not c else None
                    inv_name_cache[inv_id] = (c.get("name") if c else None) or (i.get("title") if i else None) or inv_id
                inv_name = inv_name_cache[inv_id]

            report_key = (db_rec.get("report_id") if db_rec else None) or f
            run_num = db_rec.get("run_number") if db_rec else None
            run_label = f"Run {int(run_num):03d}" if run_num is not None else ((db_rec.get("scan_id") if db_rec else None) or "Legacy / Full Scope")
            created_iso = (db_rec.get("generated_at") if db_rec else None) or datetime.fromtimestamp(stat.st_mtime).isoformat()
            reports.append({
                "report_id": db_rec.get("report_id") if db_rec else None,
                "report_key": report_key,
                "report_name": f,
                "file_name": f,
                "investigation_id": inv_id,
                "investigation_name": inv_name or inv_id,
                "scan_id": db_rec.get("scan_id") if db_rec else None,
                "run_number": int(run_num) if run_num is not None else None,
                "run_label": run_label,
                "scan_type": (db_rec.get("scan_type") if db_rec else None) or fmt.lower(),
                "report_status": (db_rec.get("report_status") if db_rec else None) or "completed",
                "report_format": fmt.lower(),
                "file_size": stat.st_size,
                "sha256_hash": db_rec.get("sha256_hash") if db_rec else None,
                "generated_by_username": db_rec.get("generated_by_username") if db_rec else None,
                "created_at": created_iso,
                "created_at_ist": format_ist(created_iso),
                "analysis_url": f"/reports/{report_key}",
                "download_url": f"/api/v1/reports/{report_key}/download?investigation_id={inv_id}",
            })
    return reports


def _ui_ctx(
    active_page: str,
    current_user: Optional[Dict[str, Any]],
    request: Optional[Request] = None,
    **extra,
) -> Dict[str, Any]:
    role = normalize_role((current_user or {}).get("role"))
    csrf_token = (
        (request.cookies.get(CSRF_COOKIE_NAME) if request else None)
        or (current_user or {}).get("csrf_token")
        or ""
    )
    user_theme = (current_user or {}).get("theme_preference") or "light"
    display_tz = (current_user or {}).get("timezone_preference") or "Asia/Kolkata"
    return {
        "active_page": active_page,
        "current_user": current_user,
        "is_admin": role == ROLE_ADMIN,
        "is_investigator": role == ROLE_INVESTIGATOR,
        "csrf_token": csrf_token,
        "user_theme": user_theme,
        "display_timezone": display_tz,
        **extra,
    }


@router.get("/", response_class=HTMLResponse)
def view_dashboard(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    accessible = filter_accessible_investigation_ids(repo, current_user)
    investigations = _filter_scoped_list(repo.list_investigations(), accessible, "investigation_id")
    scans = _filter_scoped_list(repo.list_scans(), accessible, "investigation_id", "recon_id")
    findings = _filter_scoped_list(repo.list_findings(), accessible, "investigation_id", "recon_id")
    evidence = _filter_scoped_list(repo.list_evidence(), accessible, "investigation_id", "recon_id")
    targets = _filter_scoped_list(repo.list_authorized_targets(), accessible, "investigation_id", "recon_id")
    recon_campaigns = _filter_scoped_list(repo.list_recon_campaigns(), accessible, "recon_id", "investigation_id")
    options_catalog = ScanOptionsService.get_full_catalog()

    exposure_summary = ExposureScoringEngine.calculate_investigation_exposure(findings)

    running_campaigns = [c for c in recon_campaigns if c.get("status") in ("Running", "in_progress", "Queued")]
    completed_campaigns = [c for c in recon_campaigns if c.get("status") in ("Completed", "completed")]
    failed_campaigns = [c for c in recon_campaigns if c.get("status") in ("Failed", "failed", "Partially Completed")]

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context=_ui_ctx(
            "dashboard",
            current_user,
            request=request,
            exposure=exposure_summary,
            options_catalog=options_catalog,
            total_investigations=len(investigations),
            total_scans=len(scans),
            total_findings=len(findings),
            total_evidence=len(evidence),
            total_targets=len(targets),
            total_campaigns=len(recon_campaigns),
            running_campaigns_count=len(running_campaigns),
            completed_campaigns_count=len(completed_campaigns),
            failed_campaigns_count=len(failed_campaigns),
            investigations=investigations,
            recon_campaigns=recon_campaigns,
            targets=targets,
            findings=findings,
            scans=list(reversed(scans)),
        ),
    )


# =========================================================================
# RECONNAISSANCE CAMPAIGN PLATFORM UI ROUTES
# =========================================================================

@router.get("/recon", response_class=HTMLResponse)
def view_recon_campaigns(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    accessible = filter_accessible_investigation_ids(repo, current_user)
    campaigns = _filter_scoped_list(repo.list_recon_campaigns(), accessible, "recon_id", "investigation_id")
    targets = _filter_scoped_list(repo.list_authorized_targets(), accessible, "investigation_id", "recon_id")
    findings = _filter_scoped_list(repo.list_findings(), accessible, "investigation_id", "recon_id")
    all_reports = _get_existing_reports(repo, accessible_ids=accessible)
    reports_by_recon: Dict[str, Any] = {}
    for rep in all_reports:
        rid = rep.get("investigation_id")
        if rid and rid not in reports_by_recon:
            reports_by_recon[rid] = rep

    total = len(campaigns)
    running = sum(1 for c in campaigns if c.get("status") in ("Running", "in_progress", "Queued"))
    completed = sum(1 for c in campaigns if c.get("status") in ("Completed", "completed"))
    failed = sum(1 for c in campaigns if c.get("status") in ("Failed", "failed", "Partially Completed"))

    return templates.TemplateResponse(
        request=request,
        name="recon_list.html",
        context=_ui_ctx(
            "recon_list",
            current_user,
            request=request,
            campaigns=campaigns,
            reports_by_recon=reports_by_recon,
            total_campaigns=total,
            running_count=running,
            completed_count=completed,
            failed_count=failed,
            total_targets=len(targets),
            total_findings=len(findings),
        ),
    )


@router.get("/recon/new", response_class=HTMLResponse)
def view_recon_create(
    request: Request,
    edit: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_investigator_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    if edit:
        edit_campaign = _enforce_ui_investigation_access(
            repo, current_user, edit, request, require_execution=True, action_label="UI_RECON_EDIT"
        )
        if not repo.get_recon_campaign(edit):
            raise HTTPException(status_code=404, detail=f"Recon Campaign '{edit}' not found.")
        profiles = repo.list_saved_scan_profiles()
        options_catalog = ScanOptionsService.get_full_catalog()
        return templates.TemplateResponse(
            request=request,
            name="recon_workspace.html",
            context=_ui_ctx(
                "recon_new",
                current_user,
                request=request,
                campaign=edit_campaign,
                recon_id=edit,
                profiles=profiles,
                options_catalog=options_catalog,
                created=False,
            ),
        )

    return templates.TemplateResponse(
        request=request,
        name="recon_create.html",
        context=_ui_ctx(
            "recon_new",
            current_user,
            request=request,
            default_target="",
        ),
    )


@router.get("/recon/{recon_id}/workspace", response_class=HTMLResponse)
def view_recon_workspace(
    recon_id: str,
    request: Request,
    created: Optional[str] = None,
    run_new: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_investigator_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    campaign = _enforce_ui_investigation_access(
        repo, current_user, recon_id, request, require_execution=True, action_label="UI_RECON_WORKSPACE"
    )
    if not repo.get_recon_campaign(recon_id):
        raise HTTPException(status_code=404, detail=f"Recon Campaign '{recon_id}' not found.")

    runs = repo.list_scans(investigation_id=recon_id)
    next_run_num = max([int(r.get("run_number") or 0) for r in runs], default=0) + 1
    profiles = repo.list_saved_scan_profiles()
    options_catalog = ScanOptionsService.get_full_catalog()
    return templates.TemplateResponse(
        request=request,
        name="recon_workspace.html",
        context=_ui_ctx(
            "recon_list",
            current_user,
            request=request,
            campaign=campaign,
            recon_id=recon_id,
            runs=runs,
            next_run_number=next_run_num,
            run_new=(run_new == "1" or run_new == "true" or bool(runs)),
            profiles=profiles,
            options_catalog=options_catalog,
            created=(created == "1" or created == "true"),
        ),
    )


@router.get("/recon/{recon_id}", response_class=HTMLResponse)
def view_recon_detail(
    recon_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    campaign = _enforce_ui_investigation_access(repo, current_user, recon_id, request)
    if not repo.get_recon_campaign(recon_id):
        raise HTTPException(status_code=404, detail=f"Recon Campaign '{recon_id}' not found.")

    if campaign.get("status") in ("Running", "in_progress", "Queued"):
        return RedirectResponse(url=f"/recon/{recon_id}/live", status_code=303)
    if campaign.get("status") in ("Draft", "Authorized", "Pending"):
        if is_investigator_user(current_user):
            return RedirectResponse(url=f"/recon/{recon_id}/workspace", status_code=303)
        return RedirectResponse(url=f"/recon/{recon_id}/results", status_code=303)
    return RedirectResponse(url=f"/recon/{recon_id}/results", status_code=303)


@router.get("/recon/{recon_id}/live", response_class=HTMLResponse)
def view_recon_live(
    recon_id: str,
    request: Request,
    scan_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    campaign = _enforce_ui_investigation_access(repo, current_user, recon_id, request)
    if not repo.get_recon_campaign(recon_id):
        raise HTTPException(status_code=404, detail=f"Recon Campaign '{recon_id}' not found.")

    scans = repo.list_scans(investigation_id=recon_id)
    selected_scan = None
    if scan_id:
        cand = repo.get_scan(scan_id)
        if cand and (cand.get("recon_id") == recon_id or cand.get("investigation_id") == recon_id):
            selected_scan = cand
    if not selected_scan and scans:
        selected_scan = sorted(scans, key=lambda s: (int(s.get("run_number") or 0), s.get("created_at") or ""), reverse=True)[0]
    eff_scan_id = selected_scan.get("scan_id") if selected_scan else None

    findings = repo.list_findings(investigation_id=recon_id, scan_id=eff_scan_id)
    latest_scan = selected_scan or (scans[0] if scans else None)
    bundle = load_campaign_results_bundle(recon_id, repo, scan_id=eff_scan_id)
    evidence = repo.list_evidence(investigation_id=recon_id, scan_id=eff_scan_id)

    nessus_status = "Unavailable"
    try:
        from src.collectors.nessus_collector import NessusCollector
        n_res = NessusCollector().test_connection()
        if n_res.get("connected") and n_res.get("scan_api_enabled", True):
            nessus_status = "Operational"
        elif n_res.get("connected"):
            nessus_status = "Connected (Read-Only)"
        else:
            nessus_status = n_res.get("status") or "Unavailable"
    except Exception:
        pass

    nuclei_status = "Unavailable"
    try:
        from src.collectors.nuclei_collector import NucleiCollector
        nuc_res = NucleiCollector().check_readiness()
        nuclei_status = "Operational" if nuc_res.get("ready") else "Unavailable"
    except Exception:
        pass

    live_ctx = ExecutionManager(repo=repo).build_live_snapshot(recon_id, campaign, scans, bundle, scan_id=eff_scan_id)
    try:
        raw_cfg = (selected_scan.get("scan_config_json") if selected_scan and selected_scan.get("scan_config_json") else None) or campaign.get("scan_config_json") or "{}"
        parsed_cfg = json.loads(raw_cfg) if isinstance(raw_cfg, str) else (raw_cfg or {})
    except Exception:
        parsed_cfg = {}
    selected_cats = parsed_cfg.get("selected_categories") or ([campaign.get("selected_scan_types")] if campaign.get("selected_scan_types") else [])

    return templates.TemplateResponse(
        request=request,
        name="recon_live.html",
        context=_ui_ctx(
            "recon_list",
            current_user,
            request=request,
            campaign=campaign,
            recon_id=recon_id,
            scans=scans,
            latest_scan=latest_scan,
            selected_scan=selected_scan,
            findings=findings,
            findings_count=len(findings),
            initial_events=bundle["events"],
            passive_results=bundle["passive_results"],
            active_hosts=bundle["active_hosts"],
            discovered_ports=bundle["discovered_ports"],
            scanner_statuses=bundle["scanner_statuses"],
            evidence=evidence,
            nessus_status=nessus_status,
            nuclei_status=nuclei_status,
            scan_categories=selected_cats,
            live_ctx=live_ctx,
        ),
    )


@router.get("/recon/{recon_id}/results", response_class=HTMLResponse)
def view_recon_results(
    recon_id: str,
    request: Request,
    scan_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    campaign = _enforce_ui_investigation_access(repo, current_user, recon_id, request)
    if not repo.get_recon_campaign(recon_id):
        raise HTTPException(status_code=404, detail=f"Recon Campaign '{recon_id}' not found.")

    accessible = filter_accessible_investigation_ids(repo, current_user)
    raw_scans = repo.list_scans(investigation_id=recon_id)
    ordered_scans = sorted(
        raw_scans,
        key=lambda s: (int(s.get("run_number") or 0), s.get("created_at") or ""),
        reverse=True,
    )
    all_inv_findings = repo.list_findings(investigation_id=recon_id)
    all_inv_evidence = repo.list_evidence(investigation_id=recon_id)
    all_inv_reports = _get_existing_reports(repo, accessible_ids={recon_id})

    selected_scan = None
    eff_scan_id: Optional[str] = None
    if scan_id and scan_id != "all":
        cand = repo.get_scan(scan_id)
        if cand and (cand.get("recon_id") == recon_id or cand.get("investigation_id") == recon_id):
            selected_scan = cand
            eff_scan_id = cand.get("scan_id")

    # Annotate each run with per-run counts & IST timings for Scan History table
    users_by_id = {u.get("id"): u.get("username") for u in repo.list_users() if u.get("id") is not None}
    enriched_scans: List[Dict[str, Any]] = []
    for s in ordered_scans:
        sid = s.get("scan_id")
        s_findings = [f for f in all_inv_findings if f.get("scan_id") == sid]
        s_ev = [e for e in all_inv_evidence if e.get("scan_id") == sid]
        s_rep = [r for r in all_inv_reports if r.get("scan_id") == sid]
        s_copy = dict(s)
        s_copy["findings_count"] = len(s_findings)
        s_copy["evidence_count"] = len(s_ev)
        s_copy["reports_count"] = len(s_rep)
        s_copy["initiator_username"] = users_by_id.get(s.get("initiated_by")) or "investigator"
        s_copy["started_at_ist"] = s.get("started_at_ist") or format_ist(s.get("started_at") or s.get("created_at"))
        s_copy["completed_at_ist"] = s.get("completed_at_ist") or (format_ist(s.get("completed_at")) if s.get("completed_at") else None)
        s_copy["duration_display"] = duration_human(s.get("started_at"), s.get("completed_at"), s.get("duration_seconds"))
        enriched_scans.append(s_copy)

    findings = repo.list_findings(investigation_id=recon_id, scan_id=eff_scan_id)
    explained_findings = enrich_findings_with_explanations(findings)
    exposure_summary = ExposureScoringEngine.calculate_investigation_exposure(findings)
    all_campaigns = _filter_scoped_list(repo.list_recon_campaigns(), accessible, "recon_id", "investigation_id")
    bundle = load_campaign_results_bundle(recon_id, repo, scan_id=eff_scan_id)
    campaign_reports = [r for r in all_inv_reports if not eff_scan_id or r.get("scan_id") == eff_scan_id]

    return templates.TemplateResponse(
        request=request,
        name="recon_results.html",
        context=_ui_ctx(
            "recon_list",
            current_user,
            request=request,
            campaign=campaign,
            recon_id=recon_id,
            findings=findings,
            explained_findings=explained_findings,
            scans=enriched_scans,
            selected_scan=selected_scan,
            selected_scan_id=eff_scan_id or "all",
            exposure=exposure_summary,
            all_campaigns=all_campaigns,
            passive_results=bundle["passive_results"],
            active_hosts=bundle["active_hosts"],
            discovered_ports=bundle["discovered_ports"],
            scanner_statuses=bundle["scanner_statuses"],
            failed_stages=bundle["failed_stages"],
            reports=campaign_reports,
            all_campaign_reports=all_inv_reports,
        ),
    )


@router.get("/recon/{recon_id}/pdf")
def download_recon_pdf(
    recon_id: str,
    request: Request,
    format: str = "technical",
    scan_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    """
    One-click download for investigation-named PDFs.
    - Investigators (owner/shared): compile & persist fresh PDF scoped cleanly to selected scan run (or latest).
    - Administrators (read-only): download latest existing PDF for the campaign/run if present; blocked (403) from generating new ones.
    """
    from src.reporting.unified_report import UnifiedReportGenerator

    campaign = _enforce_ui_investigation_access(
        repo,
        current_user,
        recon_id,
        request,
        require_execution=False,
        action_label="UI_REPORT_PDF",
    )
    if not repo.get_recon_campaign(recon_id):
        raise HTTPException(status_code=404, detail=f"Recon Campaign '{recon_id}' not found.")

    norm_fmt = normalize_report_type_tag(format)
    if is_admin_user(current_user):
        existing = _get_existing_reports(repo, accessible_ids={recon_id}, scan_id=scan_id)
        fmt_matches = [r for r in existing if (r.get("report_format") or "").lower() == norm_fmt]
        target_rec = fmt_matches[0] if fmt_matches else (existing[0] if existing else None)
        if not target_rec:
            record_security_audit(
                repo,
                user=current_user,
                action="PERMISSION_DENIED",
                target_resource=recon_id,
                details={"reason": "admin_report_generation_blocked"},
                outcome="DENIED",
                request=request,
            )
            raise UIAccessDeniedException(
                "Administrators cannot generate new PDF reports. Download an existing investigator-generated report from the Reports archive once available.",
                user=current_user,
            )
        pdf_path = os.path.realpath(os.path.join(REPORTS_DIR, os.path.basename(target_rec["file_name"])))
        real_dir = os.path.realpath(REPORTS_DIR)
        if not pdf_path.startswith(real_dir + os.sep) or not os.path.isfile(pdf_path):
            raise HTTPException(status_code=404, detail="Existing report file not found.")
        record_security_audit(
            repo,
            user=current_user,
            action="REPORT_DOWNLOADED",
            target_resource=str(target_rec.get("report_id") or target_rec["file_name"]),
            details={"investigation_id": recon_id, "scan_id": scan_id},
            outcome="SUCCESS",
            request=request,
        )
        return FileResponse(path=pdf_path, media_type="application/pdf", filename=os.path.basename(pdf_path))

    # Investigator execution path
    all_scans = repo.list_scans(investigation_id=recon_id)
    selected_scan = None
    if scan_id:
        cand = repo.get_scan(scan_id)
        if cand and (cand.get("recon_id") == recon_id or cand.get("investigation_id") == recon_id):
            selected_scan = cand
    elif all_scans:
        selected_scan = sorted(
            all_scans,
            key=lambda s: (int(s.get("run_number") or 0), s.get("created_at") or ""),
            reverse=True,
        )[0]
    eff_scan_id = selected_scan.get("scan_id") if selected_scan else None

    inv = {
        "investigation_id": campaign["recon_id"],
        "recon_id": campaign["recon_id"],
        "title": campaign["name"],
        "name": campaign["name"],
        "purpose": campaign.get("purpose", "Security Assessment"),
        "description": campaign.get("description", ""),
        "status": (selected_scan.get("status") if selected_scan else None) or campaign.get("status", "Completed"),
        "target_value": campaign.get("target_value", ""),
        "target_type": campaign.get("target_type", "ipv4"),
        "scope_description": campaign.get("scope_description", ""),
        "excluded_targets": campaign.get("excluded_targets", ""),
        "selected_scan_types": (selected_scan.get("scan_type") if selected_scan else None) or campaign.get("selected_scan_types", ""),
        "scan_config_json": (selected_scan.get("scan_config_json") if selected_scan else None) or campaign.get("scan_config_json", "{}"),
        "created_at": campaign.get("created_at"),
    }
    targets = repo.list_authorized_targets(recon_id)
    if not targets:
        targets = [{
            "target": campaign["target_value"],
            "target_type": campaign.get("target_type", "ipv4"),
            "name": campaign["name"],
            "scope": campaign.get("scope_description") or "Authorized Scope",
            "permitted_profiles": "lab-basic",
        }]
    findings = repo.list_findings(recon_id, scan_id=eff_scan_id)
    evidence = repo.list_evidence(recon_id, scan_id=eff_scan_id)
    bundle = load_campaign_results_bundle(recon_id, repo, scan_id=eff_scan_id)
    analysis = build_report_analysis(
        recon_id,
        repo,
        report_meta={
            "investigation_id": recon_id,
            "recon_id": recon_id,
            "investigation_name": campaign["name"],
            "scan_id": eff_scan_id,
            "run_number": selected_scan.get("run_number") if selected_scan else None,
            "report_format": norm_fmt,
        },
        findings_override=findings,
        targets_override=targets,
        evidence_override=evidence,
        results_bundle_override=bundle,
        scan_id=eff_scan_id,
    )

    out_name = build_investigation_report_filename(
        campaign["name"],
        norm_fmt,
        reports_dir=REPORTS_DIR,
        run_number=selected_scan.get("run_number") if selected_scan else None,
    )
    out_path = os.path.join(REPORTS_DIR, out_name)

    generator = UnifiedReportGenerator()
    pdf_path = generator.generate_pdf_report(
        investigation=inv,
        targets=targets,
        findings=findings,
        evidence=evidence,
        output_path=out_path,
        report_format=norm_fmt,
        results_bundle=bundle,
        analysis=analysis,
        generated_by=current_user.get("username"),
        scan_run=selected_scan,
    )

    try:
        fsize = os.path.getsize(pdf_path)
        with open(pdf_path, "rb") as pf:
            sha = hashlib.sha256(pf.read()).hexdigest()
        is_complete = (analysis.get("assessment_limitations") or {}).get("is_complete", True)
        rep_status = "completed" if is_complete else "partial"
        if not findings and not (bundle.get("passive_results") or bundle.get("discovered_ports")):
            rep_status = "empty" if is_complete else "partial"
        rec = repo.add_report_record(
            investigation_id=recon_id,
            recon_id=recon_id,
            file_name=os.path.basename(pdf_path),
            file_size=fsize,
            sha256_hash=sha,
            report_type=norm_fmt,
            generated_by_user_id=current_user.get("id"),
            generated_by_username=current_user.get("username"),
            scan_id=eff_scan_id,
            run_number=selected_scan.get("run_number") if selected_scan else None,
            scan_type=(selected_scan.get("scan_type") if selected_scan else None) or campaign.get("selected_scan_types") or norm_fmt,
            investigation_name=campaign["name"],
            report_status=rep_status,
        )
        record_security_audit(
            repo,
            user=current_user,
            action="REPORT_GENERATED",
            target_resource=str(rec.get("report_id") or os.path.basename(pdf_path)),
            details={"investigation_id": recon_id, "scan_id": eff_scan_id, "report_format": norm_fmt},
            outcome="SUCCESS",
            request=request,
        )
    except Exception:
        pass

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=os.path.basename(pdf_path),
    )


@router.get("/investigations", response_class=HTMLResponse)
def view_investigations(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    accessible = filter_accessible_investigation_ids(repo, current_user)
    investigations = _filter_scoped_list(repo.list_investigations(), accessible, "investigation_id")
    targets = _filter_scoped_list(repo.list_authorized_targets(), accessible, "investigation_id", "recon_id")
    return templates.TemplateResponse(
        request=request,
        name="investigations.html",
        context=_ui_ctx(
            "investigations",
            current_user,
            request=request,
            investigations=list(reversed(investigations)),
            targets=targets,
        ),
    )


@router.get("/scans", response_class=HTMLResponse)
def view_scans(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    accessible = filter_accessible_investigation_ids(repo, current_user)
    scans = _filter_scoped_list(repo.list_scans(), accessible, "investigation_id", "recon_id")
    investigations = _filter_scoped_list(repo.list_investigations(), accessible, "investigation_id")
    targets = _filter_scoped_list(repo.list_authorized_targets(), accessible, "investigation_id", "recon_id")
    return templates.TemplateResponse(
        request=request,
        name="scans.html",
        context=_ui_ctx(
            "scans",
            current_user,
            request=request,
            scans=list(reversed(scans)),
            investigations=investigations,
            targets=targets,
        ),
    )


@router.get("/findings", response_class=HTMLResponse)
def view_findings(
    request: Request,
    severity: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    accessible = filter_accessible_investigation_ids(repo, current_user)
    findings = _filter_scoped_list(repo.list_findings(severity=severity), accessible, "investigation_id", "recon_id")
    all_findings = _filter_scoped_list(repo.list_findings(), accessible, "investigation_id", "recon_id")
    exposure_summary = ExposureScoringEngine.calculate_investigation_exposure(all_findings)
    return templates.TemplateResponse(
        request=request,
        name="findings.html",
        context=_ui_ctx(
            "findings",
            current_user,
            request=request,
            findings=findings,
            total_findings=len(all_findings),
            exposure=exposure_summary,
            selected_severity=severity,
        ),
    )


@router.get("/evidence", response_class=HTMLResponse)
def view_evidence(
    request: Request,
    investigation_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    accessible = filter_accessible_investigation_ids(repo, current_user)
    raw_evidence = repo.list_evidence(investigation_id=investigation_id, scan_id=scan_id)
    evidence = _filter_scoped_list(raw_evidence, accessible, "investigation_id", "recon_id")
    campaigns = _filter_scoped_list(repo.list_recon_campaigns(), accessible, "recon_id", "investigation_id")
    scans = _filter_scoped_list(repo.list_scans(), accessible, "investigation_id", "recon_id")

    inv_names = {c.get("recon_id"): c.get("name") for c in campaigns if c.get("recon_id")}
    for inv in _filter_scoped_list(repo.list_investigations(), accessible, "investigation_id"):
        inv_names.setdefault(inv.get("investigation_id"), inv.get("title"))
    scan_map = {s.get("scan_id"): s for s in scans if s.get("scan_id")}

    enriched_evidence: List[Dict[str, Any]] = []
    for e in reversed(evidence):
        item = dict(e)
        iid = e.get("investigation_id")
        sid = e.get("scan_id")
        s_info = scan_map.get(sid) or {}
        r_num = s_info.get("run_number")
        item["investigation_name"] = inv_names.get(iid) or iid or "Unknown"
        item["run_label"] = f"Run {int(r_num):03d}" if r_num is not None else (sid or "Unlinked")
        item["created_at_ist"] = e.get("created_at_ist") or format_ist(e.get("created_at"))
        fid = str(e.get("seaweed_fid") or "")
        lpath = str(e.get("local_path") or "")
        has_local = bool(lpath and os.path.isfile(lpath))
        has_remote = bool(fid and not fid.startswith("local-"))
        item["storage_status"] = (
            "SeaweedFS + Local" if (has_remote and has_local)
            else "SeaweedFS Archived" if has_remote
            else "Local Vault" if has_local
            else "Archived Reference" if fid
            else "Missing"
        )
        enriched_evidence.append(item)

    return templates.TemplateResponse(
        request=request,
        name="evidence.html",
        context=_ui_ctx(
            "evidence",
            current_user,
            request=request,
            evidence=enriched_evidence,
            total_evidence=len(enriched_evidence),
            campaigns=campaigns,
            scans=scans,
            preselect_inv=investigation_id or "",
            preselect_scan=scan_id or "",
        ),
    )


@router.get("/reports", response_class=HTMLResponse)
def view_reports(
    request: Request,
    investigation_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    accessible = filter_accessible_investigation_ids(repo, current_user)
    investigations = _filter_scoped_list(repo.list_investigations(), accessible, "investigation_id")
    campaigns = _filter_scoped_list(repo.list_recon_campaigns(), accessible, "recon_id", "investigation_id")
    reports = _get_existing_reports(repo, accessible_ids=accessible)
    findings = _filter_scoped_list(repo.list_findings(), accessible, "investigation_id", "recon_id")
    all_scans = _filter_scoped_list(repo.list_scans(), accessible, "investigation_id", "recon_id")

    scans_by_recon: Dict[str, List[Dict[str, Any]]] = {}
    for s in sorted(all_scans, key=lambda x: (int(x.get("run_number") or 0), x.get("created_at") or ""), reverse=True):
        rk = s.get("recon_id") or s.get("investigation_id")
        if not rk:
            continue
        r_num = int(s.get("run_number") or 1)
        s_findings = [f for f in findings if f.get("scan_id") == s.get("scan_id")]
        scans_by_recon.setdefault(rk, []).append({
            "scan_id": s.get("scan_id"),
            "run_number": r_num,
            "run_label": s.get("run_label") or f"Run {r_num:03d}",
            "scan_type": s.get("scan_type") or "Security Scan",
            "status": s.get("status") or "Unknown",
            "findings_count": len(s_findings),
            "started_at_ist": s.get("started_at_ist") or format_ist(s.get("started_at") or s.get("created_at")),
        })

    return templates.TemplateResponse(
        request=request,
        name="reports.html",
        context=_ui_ctx(
            "reports",
            current_user,
            request=request,
            investigations=investigations,
            campaigns=campaigns,
            reports=reports,
            total_findings=len(findings),
            scans_by_recon=scans_by_recon,
            preselect_inv=investigation_id or "",
            preselect_scan=scan_id or "",
        ),
    )


@router.get("/reports/{report_id}", response_class=HTMLResponse)
def view_report_detail_analysis(
    report_id: str,
    request: Request,
    scan_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    """Integrated Report Details & Interactive Analyse Report view (RBAC & ownership enforced)."""
    report_meta = resolve_report_record(report_id, repo)
    if not report_meta:
        raise HTTPException(status_code=404, detail=f"Report '{os.path.basename(report_id)}' not found.")

    inv_id = report_meta.get("investigation_id")
    if inv_id and inv_id != "UNKNOWN":
        _enforce_ui_investigation_access(repo, current_user, inv_id, request, action_label="UI_REPORT_ANALYZE")
    elif not is_admin_user(current_user):
        raise UIAccessDeniedException("Access denied to legacy unowned report.", user=current_user)

    eff_scan_id = scan_id or report_meta.get("scan_id")
    analysis = build_report_analysis(inv_id, repo, report_meta=report_meta, scan_id=eff_scan_id)
    record_security_audit(
        repo,
        user=current_user,
        action="REPORT_ANALYZED",
        target_resource=str(report_meta.get("report_id") or report_meta.get("file_name")),
        details={"investigation_id": inv_id, "scan_id": eff_scan_id, "source": "ui"},
        outcome="SUCCESS",
        request=request,
    )

    return templates.TemplateResponse(
        request=request,
        name="report_detail.html",
        context=_ui_ctx(
            "reports",
            current_user,
            request=request,
            report=report_meta,
            analysis=analysis,
        ),
    )


@router.get("/login", response_class=HTMLResponse)
def view_login(
    request: Request,
    current_user: Optional[Dict[str, Any]] = Depends(get_optional_current_user),
):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context=_ui_ctx("login", current_user, request=request),
    )


@router.get("/settings", response_class=HTMLResponse)
def view_settings(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    raw_scope = TargetAuthorizer().get_scope_summary()
    sanitized_scope = {
        "policy_mode": "Fail-Closed Scope Enforcement",
        "authorized_targets_count": len(raw_scope.get("authorized_targets") or []),
        "approved_ranges_count": len(raw_scope.get("approved_lab_ranges") or []),
        "authorized_domains_count": len(raw_scope.get("authorized_domains") or []),
        "public_ips_restricted": not raw_scope.get("allow_public_ips", False),
    }
    activity_logs = repo.list_user_activity_logs(user_id=current_user.get("id"), limit=50)
    accessible = filter_accessible_investigation_ids(repo, current_user)
    my_investigations = _filter_scoped_list(repo.list_recon_campaigns(), accessible, "recon_id", "investigation_id")
    my_reports = _get_existing_reports(repo, accessible_ids=accessible)

    user_profile = {
        "user_id": current_user.get("id"),
        "username": current_user.get("username"),
        "full_name": current_user.get("full_name") or current_user.get("username"),
        "email": current_user.get("email"),
        "role": current_user.get("role"),
        "is_active": current_user.get("is_active", True),
        "is_approved": current_user.get("is_approved", True),
        "theme_preference": current_user.get("theme_preference") or "light",
        "timezone_preference": current_user.get("timezone_preference") or "Asia/Kolkata",
        "notification_preferences": current_user.get("notification_preferences") or {},
        "created_at_ist": current_user.get("created_at_ist") or format_ist(current_user.get("created_at")),
        "last_login_ist": current_user.get("last_login_ist") or format_ist(current_user.get("last_login_at")),
        "investigations_count": len(my_investigations),
        "reports_count": len(my_reports),
    }
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context=_ui_ctx(
            "settings",
            current_user,
            request=request,
            scope_summary=sanitized_scope,
            user_profile=user_profile,
            activity_logs=activity_logs,
        ),
    )


@router.get("/admin/users", response_class=HTMLResponse)
def view_admin_users(
    request: Request,
    current_user: Dict[str, Any] = Depends(require_admin_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    users = [{k: v for k, v in u.items() if k != "hashed_password"} for u in repo.list_users()]
    investigations = repo.list_recon_campaigns()
    return templates.TemplateResponse(
        request=request,
        name="admin_users.html",
        context=_ui_ctx("admin_users", current_user, request=request, users=users, campaigns=investigations),
    )


@router.get("/admin/scanners", response_class=HTMLResponse)
def view_admin_scanners(
    request: Request,
    current_user: Dict[str, Any] = Depends(require_admin_ui),
):
    catalog = ScanOptionsService.get_full_catalog()
    return templates.TemplateResponse(
        request=request,
        name="admin_scanners.html",
        context=_ui_ctx("admin_scanners", current_user, request=request, catalog=catalog),
    )


@router.get("/admin/system", response_class=HTMLResponse)
def view_admin_system(
    request: Request,
    current_user: Dict[str, Any] = Depends(require_admin_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    from src.storage.seaweedfs_client import SeaweedFSClient
    scope = TargetAuthorizer().get_scope_summary()
    storage = SeaweedFSClient().check_health()
    db_ok = getattr(repo, "db", None) is not None
    docs_enabled = os.getenv("ENABLE_PUBLIC_API_DOCS", "false").lower() == "true"
    return templates.TemplateResponse(
        request=request,
        name="admin_system.html",
        context=_ui_ctx(
            "admin_system",
            current_user,
            request=request,
            scope_summary=scope,
            storage=storage,
            db_available=db_ok,
            docs_enabled=docs_enabled,
        ),
    )


@router.get("/admin/audit-logs", response_class=HTMLResponse)
def view_admin_audit_logs(
    request: Request,
    action: Optional[str] = None,
    outcome: Optional[str] = None,
    limit: int = 200,
    current_user: Dict[str, Any] = Depends(require_admin_ui),
    repo: FootprintIQRepository = Depends(get_repository),
):
    safe_limit = max(1, min(int(limit), 500))
    logs = repo.list_audit_logs(limit=safe_limit, action=action or None, outcome=outcome or None)
    return templates.TemplateResponse(
        request=request,
        name="admin_audit_logs.html",
        context=_ui_ctx(
            "admin_audit_logs",
            current_user,
            request=request,
            audit_logs=logs,
            filter_action=action or "",
            filter_outcome=outcome or "",
        ),
    )
