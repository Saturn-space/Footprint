"""
FootprintIQ - Tenable Nessus Scanner Management Router
Endpoints:
- GET  /api/v1/scanners/nessus/status          (Scanner availability & version)
- POST /api/v1/scanners/nessus/test            (Administrator live connection test)
- GET  /api/v1/scanners/nessus/templates       (Discovered scan templates)
- GET  /api/v1/scanners/nessus/capabilities    (Live API capability matrix)
- GET  /api/v1/scanners/nessus/scanners        (Connected scanner list)
- GET  /api/v1/scanners/nessus/scans           (Read-only scan listing)
- GET  /api/v1/scanners/nessus/scans/{scan_id} (Read-only scan details & findings)
- POST /api/v1/scanners/nessus/scans/{scan_id}/import (Import real Nessus scan results into investigation)
"""

from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from src.collectors.nessus_collector import NessusCollector
from src.db.repository import FootprintIQRepository
from src.api.dependencies import get_current_user, get_repository, require_admin, require_investigator
from src.services.rbac_service import enforce_investigation_access, record_security_audit

router = APIRouter(prefix="/api/v1/scanners/nessus", tags=["Tenable Nessus Scanner"])


@router.get("/status")
def get_nessus_status(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns sanitized status of the Tenable Nessus vulnerability scanner.
    Never exposes internal credentials or raw API tokens.
    """
    collector = NessusCollector()
    res = collector.check_status()
    res.pop("server_url", None)
    return res


@router.post("/test")
def test_nessus_connection(current_user: Dict[str, Any] = Depends(require_admin)):
    """
    Administrator-only endpoint to test live connectivity and authentication with Nessus API.
    """
    collector = NessusCollector()
    result = collector.test_connection()
    return result


@router.get("/templates")
def list_nessus_templates(
    refresh: bool = Query(False, description="Force refresh template cache from Nessus API"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Discovers and returns available scan templates from the Nessus installation.
    Filters out subscription-restricted templates that are unusable by the current license.
    """
    collector = NessusCollector()
    templates = collector.get_scan_templates(refresh=refresh)
    return {
        "count": len(templates),
        "available_count": sum(1 for t in templates if t.get("is_available")),
        "templates": templates
    }


@router.get("/capabilities")
def get_nessus_capabilities(
    _current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Returns truthful live API capability audit for the configured Tenable Nessus instance."""
    return NessusCollector().get_api_capabilities()


@router.get("/scanners")
def list_nessus_scanners(
    _current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Lists connected Nessus scanners cleanly via GET /scanners."""
    return NessusCollector().get_scanners()


@router.get("/scans")
def list_existing_nessus_scans(
    _current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Lists existing Nessus scans available for read-only inspection and import."""
    return NessusCollector().list_scans()


@router.get("/scans/{scan_id}")
def get_existing_nessus_scan(
    scan_id: int,
    _current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieves read-only status, hosts, and normalized findings from an existing Nessus scan."""
    details = NessusCollector().get_scan_details(scan_id)
    if not details.get("available"):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=details.get("error") or f"Failed to read Nessus scan {scan_id}.",
        )
    return details


@router.get("/scans/{scan_id}/export")
def export_existing_nessus_scan(
    scan_id: int,
    fmt: str = Query("nessus", pattern="^(nessus|csv|html)$"),
    _current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Downloads a read-only exported report (.nessus, .csv, or .html) from Nessus."""
    collector = NessusCollector()
    details = collector.get_scan_details(scan_id)
    if not details.get("available"):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=details.get("error") or f"Unable to inspect Nessus scan {scan_id}.",
        )
    if str(details.get("status") or "").lower() == "empty":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Nessus scan {scan_id} has status 'empty' and contains no executed report data to export.",
        )
    raw = collector.export_scan_report(scan_id, export_format=fmt)
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Nessus failed to export scan {scan_id} in '{fmt}' format.",
        )
    media = "text/csv" if fmt == "csv" else ("text/html" if fmt == "html" else "application/xml")
    return Response(
        content=raw,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="nessus_scan_{scan_id}.{fmt}"'},
    )


@router.post("/scans/{scan_id}/import")
def import_existing_nessus_scan(
    scan_id: int,
    request: Request,
    investigation_id: str = Query(..., description="Authorized investigation/campaign ID"),
    export_format: str = Query("nessus", pattern="^(nessus|csv|html|none)$"),
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository),
):
    """
    Imports genuine findings and optional report evidence from an existing Nessus scan
    into an authorized investigation without fabricating missing findings.
    """
    import json
    from src.authorization.target_authorizer import TargetAuthorizer, TargetAuthorizationError
    from src.storage.seaweedfs_client import SeaweedFSClient

    enforce_investigation_access(
        repo,
        current_user,
        investigation_id,
        require_execution=True,
        request=request,
        action_label="NESSUS_RESULTS_IMPORT",
    )

    collector = NessusCollector()
    details = collector.get_scan_details(scan_id, investigation_id=investigation_id)
    if not details.get("available"):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=details.get("error") or f"Nessus scan {scan_id} could not be retrieved.",
        )

    campaign = repo.get_recon_campaign(investigation_id) or repo.get_investigation(investigation_id) or {}
    raw_target = str(details.get("targets") or campaign.get("target_value") or "").split(",")[0].strip()
    if raw_target:
        try:
            TargetAuthorizer().authorize_target(
                raw_target,
                profile="lab-basic",
                investigation_id=investigation_id,
                repo=repo,
            )
        except TargetAuthorizationError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))

    created_scan = repo.create_scan_execution(
        investigation_id=investigation_id,
        scan_type="nessus_import",
        target=raw_target or campaign.get("target_value") or "unknown",
        profile="read-only-import",
        recon_id=investigation_id,
    )
    local_scan_id = (created_scan or {}).get("scan_id") or f"SCAN-NESSUS-{scan_id}"
    repo.update_scan_execution(
        scan_id=local_scan_id,
        status="completed",
        result_summary_json=json.dumps({
            "scanner_statuses": [{
                "scanner": "Tenable Nessus (Read-Only Import)",
                "target": raw_target or campaign.get("target_value") or "unknown",
                "status": "COMPLETED" if str(details.get("status") or "").lower() == "completed" else str(details.get("status") or "IMPORTED").upper(),
                "detail": f"Imported Nessus scan #{scan_id} ({details.get('name', 'scan')}).",
            }]
        }),
    )

    raw_status = collector.get_scan_status(scan_id)
    findings = collector.normalize_findings(
        raw_status if isinstance(raw_status, dict) else {"vulnerabilities": []},
        target=raw_target or campaign.get("target_value") or "127.0.0.1",
        investigation_id=investigation_id,
        scan_id=local_scan_id,
    )
    imported_count = 0
    for f in findings:
        f["evidence_reference"] = f"nessus_scan:{scan_id}"
        repo.add_vulnerability_finding(investigation_id, f, scan_id=local_scan_id)
        imported_count += 1

    evidence_file = None
    clean_fmt = (export_format or "nessus").strip().lower()
    if clean_fmt in ("nessus", "csv", "html") and str(details.get("status") or "").lower() != "empty":
        raw_report = collector.export_scan_report(scan_id, export_format=clean_fmt)
        if raw_report:
            ev = SeaweedFSClient().upload_content(
                content=raw_report,
                file_name=f"nessus_scan_{scan_id}.{clean_fmt}",
                investigation_id=investigation_id,
                evidence_type="nessus_report",
                content_type="application/octet-stream",
            )
            repo.add_evidence_record(
                investigation_id=investigation_id,
                evidence_type="nessus_report",
                file_name=ev["file_name"],
                file_size=ev["file_size"],
                sha256_hash=ev["sha256_hash"],
                seaweed_fid=ev.get("seaweed_fid"),
                seaweed_url=ev.get("seaweed_url"),
                local_path=ev.get("local_path"),
                scan_id=local_scan_id,
            )
            evidence_file = ev["file_name"]

    record_security_audit(
        repo,
        user=current_user,
        action="NESSUS_RESULTS_IMPORTED",
        target_resource=investigation_id,
        details={
            "nessus_scan_id": scan_id,
            "nessus_scan_status": details.get("status"),
            "findings_imported": imported_count,
            "evidence_file": evidence_file,
        },
        outcome="SUCCESS",
        request=request,
    )
    return {
        "status": "COMPLETED",
        "investigation_id": investigation_id,
        "local_scan_id": local_scan_id,
        "nessus_scan_id": scan_id,
        "nessus_scan_status": details.get("status"),
        "findings_imported": imported_count,
        "evidence_file": evidence_file,
    }

