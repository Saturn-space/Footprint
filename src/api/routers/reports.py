"""
FootprintIQ - Reports & Integrated Analysis Router
Endpoints:
- GET  /api/v1/reports (List generated reports - Admin all, Investigator owner/shared)
- GET  /api/v1/reports/{report_id}/analysis (Detailed non-fabricated report analysis - Admin & permitted Investigator)
- POST /api/v1/reports/generate (Generate Executive/Technical PDF - Investigator owner/shared only)
- GET  /api/v1/reports/download (Download latest accessible report or scoped by investigation_id)
- GET  /api/v1/reports/{report_id}/download (Download specific report file cleanly with ownership & traversal check)
"""

import hashlib
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from src.db.repository import FootprintIQRepository
from src.reporting.unified_report import UnifiedReportGenerator
from src.services.recon_results_helper import load_campaign_results_bundle
from src.services.report_analysis_service import (
    REPORTS_DIR,
    build_investigation_report_filename,
    build_report_analysis,
    compare_investigation_runs,
    extract_report_file_metadata,
    normalize_report_type_tag,
    resolve_report_record,
)
from src.services.rbac_service import (
    enforce_investigation_access,
    filter_accessible_investigation_ids,
    is_admin_user,
    record_security_audit,
)
from src.api.dependencies import get_repository, get_current_user, require_investigator
from src.utils.timezone import format_ist, to_ist

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])


class GenerateReportRequest(BaseModel):
    investigation_id: str = Field(..., example="INV-20261110-001")
    scan_id: Optional[str] = Field(None, description="Specific scan execution ID (e.g. Run 001 / Run 002)")
    report_format: Optional[str] = Field(
        "executive",
        example="executive",
        description="executive, technical, active, passive, combined, nmap, nse, nuclei, or nessus",
    )
    include_comparison: Optional[bool] = Field(
        False,
        description="Include run-to-run baseline comparison summary in PDF when prior runs exist",
    )


def _sanitize_filename(filename: str) -> str:
    """Ensure filename has no path traversal components."""
    clean = os.path.basename(filename)
    if ".." in clean or "/" in clean or "\\" in clean:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid report filename.")
    return clean


def _safe_resolve_report(filepath: str) -> str:
    """Ensure resolved file path is strictly within the reports directory."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    real_reports = os.path.realpath(REPORTS_DIR)
    real_file = os.path.realpath(filepath)
    if not (real_file == real_reports or real_file.startswith(real_reports + os.sep)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: path traversal attempt.")
    if not os.path.isfile(real_file):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file not found.")
    return real_file


def _collect_scoped_reports(
    repo: FootprintIQRepository,
    current_user: Dict[str, Any],
    investigation_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    report_type: Optional[str] = None,
    scanner: Optional[str] = None,
    search: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> list:
    db_reports = repo.list_report_records(investigation_id=investigation_id, scan_id=scan_id)
    db_by_file = {r["file_name"]: r for r in db_reports}
    accessible = filter_accessible_investigation_ids(repo, current_user)
    inv_name_cache: Dict[str, str] = {}

    def _lookup_inv_name(inv_key: str) -> str:
        if not inv_key or inv_key == "UNKNOWN":
            return "Unknown Investigation"
        if inv_key in inv_name_cache:
            return inv_name_cache[inv_key]
        camp = repo.get_recon_campaign(inv_key)
        inv = repo.get_investigation(inv_key) if not camp else None
        nm = (camp.get("name") if camp else None) or (inv.get("title") if inv else None) or inv_key
        inv_name_cache[inv_key] = nm
        return nm

    reports: List[Dict[str, Any]] = []
    seen_files = set()

    candidate_files: List[str] = []
    if os.path.exists(REPORTS_DIR):
        candidate_files = sorted(
            [f for f in os.listdir(REPORTS_DIR) if f.endswith(".pdf")],
            key=lambda fn: os.path.getmtime(os.path.join(REPORTS_DIR, fn)),
            reverse=True,
        )

    for f in candidate_files:
        seen_files.add(f)
        full_path = os.path.join(REPORTS_DIR, f)
        stat = os.stat(full_path)
        meta = extract_report_file_metadata(f)
        db_rec = db_by_file.get(f)
        inv_id = (
            (db_rec.get("recon_id") if db_rec else None)
            or (db_rec.get("investigation_id") if db_rec else None)
            or meta["investigation_id"]
        )
        if investigation_id and inv_id != investigation_id:
            continue
        if scan_id and (not db_rec or db_rec.get("scan_id") != scan_id):
            continue
        if accessible is not None and inv_id not in accessible:
            continue

        rid = (db_rec.get("report_id") if db_rec else None) or f
        r_fmt = ((db_rec.get("report_type") if db_rec else None) or meta["report_format"]).lower()
        s_type = (db_rec.get("scan_type") if db_rec else None) or r_fmt
        run_num = db_rec.get("run_number") if db_rec else None
        run_label = f"Run {int(run_num):03d}" if run_num is not None else ((db_rec.get("scan_id") if db_rec else None) or "Legacy / Full Scope")
        inv_name = (db_rec.get("investigation_name") if db_rec else None) or _lookup_inv_name(inv_id)
        created_iso = (
            (db_rec.get("generated_at") if db_rec else None)
            or datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
        )
        created_ist = format_ist(created_iso)

        if report_type and report_type.lower() not in (r_fmt, (s_type or "").lower()):
            continue
        if scanner and scanner.lower() not in f"{s_type} {r_fmt} {f}".lower():
            continue
        if date_from or date_to:
            ist_dt = to_ist(created_iso)
            ist_day = ist_dt.strftime("%Y-%m-%d") if ist_dt else ""
            if date_from and ist_day and ist_day < date_from:
                continue
            if date_to and ist_day and ist_day > date_to:
                continue
        if search:
            q = search.strip().lower()
            hay = " ".join([
                str(rid or ""),
                f,
                str(inv_id or ""),
                str(inv_name or ""),
                str(db_rec.get("scan_id") if db_rec else ""),
                run_label,
                str(s_type or ""),
                r_fmt,
                str((db_rec.get("generated_by_username") if db_rec else "") or ""),
            ]).lower()
            if q not in hay:
                continue

        reports.append({
            "report_id": db_rec.get("report_id") if db_rec else None,
            "report_key": rid,
            "report_name": f,
            "file_name": f,
            "investigation_id": inv_id,
            "recon_id": inv_id,
            "investigation_name": inv_name,
            "scan_id": db_rec.get("scan_id") if db_rec else None,
            "run_number": int(run_num) if run_num is not None else None,
            "run_label": run_label,
            "scan_type": s_type,
            "report_format": r_fmt,
            "report_status": (db_rec.get("report_status") if db_rec else None) or "completed",
            "file_size": stat.st_size,
            "sha256_hash": db_rec.get("sha256_hash") if db_rec else None,
            "generated_by_username": db_rec.get("generated_by_username") if db_rec else None,
            "created_at": created_iso,
            "created_at_ist": created_ist,
            "analysis_url": f"/reports/{rid}",
            "download_url": f"/api/v1/reports/{rid}/download?investigation_id={inv_id}",
        })
    return reports


@router.get("")
@router.get("/", include_in_schema=False)
def list_reports(
    request: Request,
    investigation_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    report_type: Optional[str] = None,
    scanner: Optional[str] = None,
    search: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    """Lists generated PDF reports with strict RBAC, scan-run metadata, IST timestamps, and multi-facet filtering."""
    if investigation_id:
        enforce_investigation_access(repo, current_user, investigation_id, request=request, action_label="REPORTS_LIST")
    return _collect_scoped_reports(
        repo,
        current_user,
        investigation_id=investigation_id,
        scan_id=scan_id,
        report_type=report_type,
        scanner=scanner,
        search=search,
        date_from=date_from,
        date_to=date_to,
    )


@router.get("/compare")
def compare_reports_or_runs(
    investigation_id: str,
    base_scan_id: str,
    target_scan_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository),
):
    """Compares two scan runs under the same investigation honestly without fabricating resolved states."""
    enforce_investigation_access(
        repo,
        current_user,
        investigation_id,
        request=request,
        action_label="REPORT_RUN_COMPARE",
    )
    try:
        comparison = compare_investigation_runs(investigation_id, base_scan_id, target_scan_id, repo)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    record_security_audit(
        repo,
        user=current_user,
        action="REPORT_RUN_COMPARED",
        target_resource=f"{investigation_id}:{base_scan_id}->{target_scan_id}",
        details={"investigation_id": investigation_id, "base_scan_id": base_scan_id, "target_scan_id": target_scan_id},
        outcome="SUCCESS",
        request=request,
    )
    return comparison


@router.get("/{report_id}/analysis")
def get_report_analysis(
    report_id: str,
    request: Request,
    scan_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    """Returns integrated multi-section analytical breakdown & chart datasets for an exact report."""
    clean_id = _sanitize_filename(report_id)
    report_meta = resolve_report_record(clean_id, repo)
    if not report_meta:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{clean_id}' not found.")

    inv_id = report_meta.get("investigation_id")
    if inv_id and inv_id != "UNKNOWN":
        enforce_investigation_access(repo, current_user, inv_id, request=request, action_label="REPORT_ANALYZE")
    elif not is_admin_user(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to legacy unowned report.")

    effective_scan_id = scan_id or report_meta.get("scan_id")
    analysis = build_report_analysis(inv_id, repo, report_meta=report_meta, scan_id=effective_scan_id)
    record_security_audit(
        repo,
        user=current_user,
        action="REPORT_ANALYZED",
        target_resource=str(report_meta.get("report_id") or report_meta.get("file_name")),
        details={"investigation_id": inv_id, "scan_id": effective_scan_id},
        outcome="SUCCESS",
        request=request,
    )
    return analysis


@router.post("/generate", status_code=status.HTTP_201_CREATED)
def generate_report(
    req: GenerateReportRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository)
):
    enforce_investigation_access(
        repo,
        current_user,
        req.investigation_id,
        require_execution=True,
        request=request,
        action_label="REPORT_GENERATE",
    )
    inv = repo.get_investigation(req.investigation_id)
    camp = repo.get_recon_campaign(req.investigation_id)
    if camp:
        inv = {
            "investigation_id": camp["recon_id"],
            "recon_id": camp["recon_id"],
            "title": camp["name"],
            "name": camp["name"],
            "description": camp.get("description", ""),
            "purpose": camp.get("purpose", ""),
            "status": camp.get("status", "Completed"),
            "target_value": camp.get("target_value", ""),
            "target_type": camp.get("target_type", "ipv4"),
            "scope_description": camp.get("scope_description", ""),
            "excluded_targets": camp.get("excluded_targets", ""),
            "selected_scan_types": camp.get("selected_scan_types", ""),
            "scan_config_json": camp.get("scan_config_json", "{}"),
            "created_at": camp.get("created_at", "")
        }
    elif not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation or Recon Campaign '{req.investigation_id}' not found. Cannot generate report."
        )

    all_scans = repo.list_scans(req.investigation_id)
    selected_scan: Optional[Dict[str, Any]] = None
    if req.scan_id:
        cand = repo.get_scan(req.scan_id)
        if not cand or (cand.get("recon_id") != req.investigation_id and cand.get("investigation_id") != req.investigation_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan Run '{req.scan_id}' not found under investigation '{req.investigation_id}'.",
            )
        selected_scan = cand
    elif all_scans:
        selected_scan = sorted(
            all_scans,
            key=lambda s: (int(s.get("run_number") or 0), s.get("created_at") or ""),
            reverse=True,
        )[0]

    effective_scan_id = selected_scan.get("scan_id") if selected_scan else None
    report_type_tag = normalize_report_type_tag(req.report_format)

    targets = repo.list_authorized_targets(req.investigation_id)
    findings = repo.list_findings(req.investigation_id, scan_id=effective_scan_id)
    evidence = repo.list_evidence(req.investigation_id, scan_id=effective_scan_id)
    results_bundle = load_campaign_results_bundle(req.investigation_id, repo, scan_id=effective_scan_id)

    prelim_meta = {
        "investigation_id": req.investigation_id,
        "recon_id": req.investigation_id,
        "investigation_name": inv.get("name") or inv.get("title"),
        "report_format": report_type_tag,
        "scan_id": effective_scan_id,
        "run_number": selected_scan.get("run_number") if selected_scan else None,
        "run_label": selected_scan.get("run_label") if selected_scan else None,
        "generated_by_username": current_user.get("username"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    analysis = build_report_analysis(
        req.investigation_id,
        repo,
        report_meta=prelim_meta,
        findings_override=findings,
        targets_override=targets,
        evidence_override=evidence,
        results_bundle_override=results_bundle,
        scan_id=effective_scan_id,
    )

    comparison_data: Optional[Dict[str, Any]] = None
    if req.include_comparison and effective_scan_id and len(all_scans) >= 2:
        ordered = sorted(all_scans, key=lambda s: (int(s.get("run_number") or 0), s.get("created_at") or ""))
        prev_candidates = [s for s in ordered if s.get("scan_id") != effective_scan_id]
        if prev_candidates:
            try:
                comparison_data = compare_investigation_runs(
                    req.investigation_id,
                    prev_candidates[-1]["scan_id"],
                    effective_scan_id,
                    repo,
                )
            except Exception:
                comparison_data = None

    output_filename = build_investigation_report_filename(
        inv.get("name") or inv.get("title"),
        report_type_tag,
        reports_dir=REPORTS_DIR,
        run_number=selected_scan.get("run_number") if selected_scan else None,
    )
    output_path = os.path.join(REPORTS_DIR, output_filename)

    generator = UnifiedReportGenerator()
    pdf_path = generator.generate_pdf_report(
        investigation=inv,
        targets=targets,
        findings=findings,
        evidence=evidence,
        output_path=output_path,
        report_format=report_type_tag,
        results_bundle=results_bundle,
        analysis=analysis,
        generated_by=current_user.get("username"),
        scan_run=selected_scan,
        comparison_data=comparison_data,
    )

    file_size = os.path.getsize(pdf_path) if os.path.exists(pdf_path) else 0
    sha256 = ""
    if os.path.exists(pdf_path):
        with open(pdf_path, "rb") as pf:
            sha256 = hashlib.sha256(pf.read()).hexdigest()

    is_complete = (analysis.get("assessment_limitations") or {}).get("is_complete", True)
    if not findings and not (results_bundle.get("passive_results") or results_bundle.get("discovered_ports")):
        report_status = "empty" if is_complete else "partial"
    elif not is_complete:
        report_status = "partial"
    else:
        report_status = "completed"

    inv_name = inv.get("name") or inv.get("title") or req.investigation_id
    scan_type_label = (
        (selected_scan.get("scan_type") if selected_scan else None)
        or inv.get("selected_scan_types")
        or report_type_tag
    )
    fname = os.path.basename(pdf_path)
    rec = repo.add_report_record(
        investigation_id=req.investigation_id,
        recon_id=req.investigation_id,
        file_name=fname,
        file_size=file_size,
        sha256_hash=sha256,
        report_type=report_type_tag,
        generated_by_user_id=current_user.get("id"),
        generated_by_username=current_user.get("username"),
        scan_id=effective_scan_id,
        run_number=selected_scan.get("run_number") if selected_scan else None,
        scan_type=scan_type_label,
        investigation_name=inv_name,
        report_status=report_status,
    )

    record_security_audit(
        repo,
        user=current_user,
        action="REPORT_GENERATED",
        target_resource=str(rec.get("report_id") or fname),
        details={
            "investigation_id": req.investigation_id,
            "scan_id": effective_scan_id,
            "report_format": report_type_tag,
            "file_name": fname,
            "report_status": report_status,
        },
        outcome="SUCCESS",
        request=request,
    )

    rid = rec.get("report_id") or fname
    return {
        "status": "SUCCESS",
        "report_id": rec.get("report_id"),
        "report_key": rid,
        "investigation_id": req.investigation_id,
        "recon_id": req.investigation_id,
        "investigation_name": inv_name,
        "scan_id": effective_scan_id,
        "run_number": selected_scan.get("run_number") if selected_scan else None,
        "run_label": selected_scan.get("run_label") if selected_scan else None,
        "report_format": report_type_tag,
        "report_status": report_status,
        "pdf_report_path": pdf_path,
        "file_name": fname,
        "created_at": rec.get("generated_at"),
        "created_at_ist": rec.get("generated_at_ist") or format_ist(rec.get("generated_at")),
        "analysis_url": f"/reports/{rid}",
        "download_url": f"/api/v1/reports/{rid}/download?investigation_id={req.investigation_id}",
        "findings_included": len(findings),
        "evidence_included": len(evidence),
    }


@router.get("/download")
def download_latest_report(
    request: Request,
    investigation_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    report_format: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository),
):
    if investigation_id:
        enforce_investigation_access(repo, current_user, investigation_id, request=request, action_label="REPORT_DOWNLOAD")

    scoped = _collect_scoped_reports(repo, current_user, investigation_id=investigation_id, scan_id=scan_id)
    if report_format:
        rf = normalize_report_type_tag(report_format)
        fmt_filtered = [r for r in scoped if (r.get("report_format") or "").lower() == rf]
        if fmt_filtered:
            scoped = fmt_filtered

    if not scoped:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No accessible PDF report found{f' for {investigation_id}' if investigation_id else ''}."
        )

    latest_rec = max(scoped, key=lambda r: os.path.getctime(os.path.join(REPORTS_DIR, r["file_name"])))
    safe_path = _safe_resolve_report(os.path.join(REPORTS_DIR, latest_rec["file_name"]))

    with open(safe_path, "rb") as f:
        content = f.read()

    record_security_audit(
        repo,
        user=current_user,
        action="REPORT_DOWNLOADED",
        target_resource=latest_rec.get("report_id") or latest_rec["file_name"],
        details={"investigation_id": latest_rec.get("investigation_id"), "scan_id": latest_rec.get("scan_id")},
        outcome="SUCCESS",
        request=request,
    )

    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{os.path.basename(safe_path)}"'}
    )


@router.get("/{report_id}/download")
def download_specific_report(
    report_id: str,
    request: Request,
    investigation_id: Optional[str] = None,
    inline: bool = False,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    clean_id = _sanitize_filename(report_id)
    resolved = resolve_report_record(clean_id, repo)
    if clean_id.startswith("REP-"):
        if not resolved:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{clean_id}' not found in requested campaign scope.")
        clean_id = resolved["file_name"]

    if not clean_id.endswith(".pdf"):
        clean_id += ".pdf"

    # Cross-campaign isolation enforcement
    meta_inv = extract_report_file_metadata(clean_id)["investigation_id"]
    db_rec = repo.get_report_record(clean_id)
    owner_inv = (
        (resolved.get("investigation_id") if resolved else None)
        or (db_rec.get("recon_id") if db_rec else None)
        or (db_rec.get("investigation_id") if db_rec else None)
        or meta_inv
    )

    if investigation_id:
        db_recs = repo.list_report_records(investigation_id=investigation_id)
        db_match = any(r.get("file_name") == clean_id for r in db_recs)
        if meta_inv != investigation_id and owner_inv != investigation_id and not db_match:
            record_security_audit(
                repo,
                user=current_user,
                action="PERMISSION_DENIED",
                target_resource=clean_id,
                details={"reason": "cross_campaign_report_download", "requested_inv": investigation_id, "owner_inv": owner_inv},
                outcome="DENIED",
                request=request,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Report '{clean_id}' does not belong to campaign '{investigation_id}'."
            )

    if owner_inv and owner_inv != "UNKNOWN":
        enforce_investigation_access(repo, current_user, owner_inv, request=request, action_label="REPORT_DOWNLOAD")
    elif not is_admin_user(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to legacy unowned report.")

    target_file = os.path.join(REPORTS_DIR, clean_id)
    safe_path = _safe_resolve_report(target_file)

    with open(safe_path, "rb") as f:
        content = f.read()

    record_security_audit(
        repo,
        user=current_user,
        action="REPORT_DOWNLOADED",
        target_resource=(db_rec.get("report_id") if db_rec else None) or clean_id,
        details={"investigation_id": owner_inv, "inline": inline},
        outcome="SUCCESS",
        request=request,
    )

    disposition = "inline" if inline else "attachment"
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'{disposition}; filename="{os.path.basename(safe_path)}"'}
    )
