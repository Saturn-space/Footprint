"""
FootprintIQ - Reconnaissance Campaign Platform API Router
Endpoints:
- POST /api/v1/recon (Create Recon Campaign)
- GET  /api/v1/recon (List all Recon Campaigns)
- GET  /api/v1/recon/profiles (List saved scan profiles)
- POST /api/v1/recon/profiles (Create custom scan profile)
- GET  /api/v1/recon/{recon_id} (Campaign details)
- POST /api/v1/recon/{recon_id}/targets (Add target to campaign)
- POST /api/v1/recon/{recon_id}/start (Launch background scan execution)
- POST /api/v1/recon/{recon_id}/cancel (Cancel active scan)
- GET  /api/v1/recon/{recon_id}/events (Get persisted terminal-style events)
- GET  /api/v1/recon/{recon_id}/stream (SSE live terminal log stream)
- GET  /api/v1/recon/{recon_id}/findings (List campaign findings)
- POST /api/v1/recon/{recon_id}/remediation (Update finding remediation status)
- GET  /api/v1/recon/{recon_id}/compare/{other_recon_id} (Compare two campaigns)
"""

import os
import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from src.db.repository import (
    FootprintIQRepository, DatabaseIntegrityError, ConcurrencyConflictError, EntityNotFoundError
)
from src.orchestration.execution_manager import ExecutionManager
from src.authorization.target_authorizer import TargetAuthorizer, TargetAuthorizationError, TargetSyntaxError
from src.collectors.nmap_collector import parse_and_validate_ports, NmapCollector
from src.services.scan_options_service import ScanOptionsService
from src.services.recon_results_helper import load_campaign_results_bundle, enrich_findings_with_explanations
from src.services.nse_policy_service import NSEPolicyService
from src.services.rbac_service import (
    enforce_investigation_access,
    filter_accessible_investigation_ids,
    is_admin_user,
    record_security_audit,
)
from src.security.privilege_detector import PrivilegeDetector
from src.security.psa_service import (
    PSAService,
    PSATicketExpiredOrInvalidError,
    PSAIdentityVerificationError,
)
from src.api.dependencies import get_repository, get_current_user, require_investigator

router = APIRouter(prefix="/api/v1/recon", tags=["Recon Campaigns"])


class CreateReconRequest(BaseModel):
    name: str = Field(..., example="External Security Assessment")
    target_value: str = Field(..., example="192.0.2.10")
    targets: Optional[List[str]] = Field(None, example=["192.0.2.10"])
    target_type: str = Field("ipv4", example="ipv4", description="'ipv4', 'range', 'domain', 'hostname'")
    description: Optional[str] = Field("", example="Authorized security reconnaissance campaign")
    purpose: Optional[str] = Field("Security Audit", example="Security Audit")
    scope_description: Optional[str] = Field("", example="Authorized target infrastructure scope")
    excluded_targets: Optional[str] = Field("", example="192.0.2.1")
    excluded_ports: Optional[str] = Field("", example="25,135")
    allowed_methods: Optional[str] = Field("all", example="all")
    allowed_ports: Optional[str] = Field("1-65535", example="1-65535")
    selected_scan_types: Optional[str] = Field("combined", example="draft")
    scan_config_json: Optional[str] = Field("{}", example="{}")
    authorization_confirmed: bool = Field(True, example=True)
    idempotency_key: Optional[str] = Field(None, example="IDEMP-20261111-001")


class UpdateReconRequest(BaseModel):
    name: Optional[str] = None
    target_value: Optional[str] = None
    targets: Optional[List[str]] = None
    target_type: Optional[str] = None
    description: Optional[str] = None
    purpose: Optional[str] = None
    scope_description: Optional[str] = None
    excluded_targets: Optional[str] = None
    excluded_ports: Optional[str] = None
    allowed_ports: Optional[str] = None
    selected_scan_types: Optional[str] = None
    scan_config_json: Optional[str] = None
    authorization_confirmed: bool = True
    version_id: Optional[int] = None


class StartReconRequest(BaseModel):
    scan_type: Optional[str] = Field(None, example="passive")
    profile: Optional[str] = Field("lab-basic", example="standard")
    custom_scripts: Optional[List[str]] = Field(None, example=["http-title", "ssl-cert"])
    selected_categories: Optional[List[str]] = None
    scan_config: Optional[Dict[str, Any]] = None
    scan_config_json: Optional[str] = None
    privilege_consent: Optional[bool] = Field(False, example=False)
    psa_ticket: Optional[str] = Field(None, example="psa_...")


class PSADetectRequest(BaseModel):
    scan_config: Optional[Dict[str, Any]] = None
    scan_config_json: Optional[str] = None
    scan_type: Optional[str] = "combined"


class PSAVerifyRequest(BaseModel):
    password: str = Field(..., description="Investigator FootprintIQ account password")
    scan_config: Optional[Dict[str, Any]] = None
    scan_config_json: Optional[str] = None
    scan_type: Optional[str] = "combined"


class RemediationUpdateRequest(BaseModel):
    finding_id: str = Field(..., example="VULN-20261110-001")
    status: str = Field(..., example="resolved", description="'open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive'")
    notes: Optional[str] = Field("", example="Backdoor FTP daemon replaced with patched vsftpd 3.0.5")
    expected_version: Optional[int] = Field(None, example=1)


class SaveProfileRequest(BaseModel):
    name: str = Field(..., example="Fast Web Audit")
    description: Optional[str] = Field("", example="Quick web ports and HTTP scripts")
    category: Optional[str] = Field("web", example="web")
    config_json: str = Field(..., example='{"ports": "80,443,8080", "service_detection": true}')


class ValidatePortsRequest(BaseModel):
    ports_spec: str = Field(..., example="22,80,443,3306,8080")


def _validate_campaign_configuration(
    target_value: str,
    targets_list: Optional[List[str]],
    excluded_targets: Optional[str],
    excluded_ports: Optional[str],
    selected_scan_types: Optional[str],
    scan_config_json: Optional[str],
    authorization_confirmed: bool,
    operator: str
) -> Dict[str, Any]:
    """Validates scope, targets, ports, NSE scripts, and scanner capability honesty."""
    try:
        cfg = json.loads(scan_config_json or "{}") if isinstance(scan_config_json, str) else (scan_config_json or {})
        if not isinstance(cfg, dict):
            raise ValueError("Invalid configuration object.")
    except json.JSONDecodeError:
        raise ValueError("Invalid configuration JSON formatting.")

    raw_targets = targets_list or cfg.get("targets") or [t.strip() for t in str(target_value or "").split(",") if t.strip()]
    selected_cats = [str(c).lower() for c in (cfg.get("selected_categories") or []) if str(c).strip().lower() in ("passive", "active", "vulnerability")]
    is_draft = (selected_scan_types or "").lower() == "draft" and not selected_cats

    if not authorization_confirmed and not is_draft:
        raise TargetAuthorizationError("Explicit authorization confirmation is required before configuring or starting a campaign.")

    if is_draft:
        scope_mode = "draft"
    elif selected_cats:
        scope_mode = "passive" if selected_cats == ["passive"] else "combined"
    elif (selected_scan_types or "").lower() == "passive":
        scope_mode = "passive"
    else:
        scope_mode = "combined"

    authorizer = TargetAuthorizer()
    auth_info = authorizer.authorize_campaign_targets(
        targets=raw_targets,
        scope_mode=scope_mode,
        excluded_targets=excluded_targets,
        explicit_authorization=authorization_confirmed,
        operator=operator
    )

    # Validate custom ports, port ranges, UDP ports & excluded ports strictly
    if excluded_ports and excluded_ports.strip():
        parse_and_validate_ports(excluded_ports.strip())

    active_cfg = cfg.get("active") or {}
    if isinstance(active_cfg, dict) and active_cfg:
        custom_ports = (active_cfg.get("custom_ports") or "").strip()
        if active_cfg.get("port_mode") == "custom" or custom_ports:
            active_cfg["custom_ports"] = parse_and_validate_ports(custom_ports)
        port_range = (active_cfg.get("port_range") or "").strip()
        if active_cfg.get("port_mode") == "port_range" or port_range:
            active_cfg["port_range"] = parse_and_validate_ports(port_range)
        udp_ports = (active_cfg.get("udp_ports") or "").strip()
        if active_cfg.get("udp_port_mode") == "udp_selected" or udp_ports:
            active_cfg["udp_ports"] = parse_and_validate_ports(udp_ports)
        ex_ports = (active_cfg.get("exclude_ports") or "").strip()
        if ex_ports:
            active_cfg["exclude_ports"] = parse_and_validate_ports(ex_ports)
        # Validate safe Nmap options against actual host capabilities
        NmapCollector().build_safe_custom_args(active_cfg)

    # Validate NSE scripts & normalize multi-engine list
    vuln_cfg = cfg.get("vulnerability") or {}
    if isinstance(vuln_cfg, dict):
        if vuln_cfg.get("nse_scripts"):
            approved, rejected = NSEPolicyService.validate_scripts(vuln_cfg["nse_scripts"], allow_vuln_checks=True)
            if rejected:
                raise ValueError(f"Unauthorized or unknown NSE script(s): {', '.join(rejected)}")
            vuln_cfg["nse_scripts"] = approved
        raw_engines = vuln_cfg.get("engines")
        if isinstance(raw_engines, list):
            lowered_engines = [str(e).lower() for e in raw_engines]
            if "greenbone" in lowered_engines:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Active Greenbone/OpenVAS scanning has been removed. Select 'nuclei' or 'nse' instead."
                )
            clean_engines = [e for e in lowered_engines if e in ("nse", "nuclei", "nessus")]
            vuln_cfg["engines"] = clean_engines
            if len(clean_engines) >= 2 and "nse" in clean_engines and "nuclei" in clean_engines:
                vuln_cfg.setdefault("engine", "combined")
            elif len(clean_engines) == 1:
                vuln_cfg.setdefault("engine", clean_engines[0])
        explicit_v_engine = str(vuln_cfg.get("engine") or "").lower()
        if explicit_v_engine in ("greenbone", "combined_nessus_greenbone"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Active Greenbone/OpenVAS engine has been removed. Select 'nuclei', 'nse', or 'combined' instead."
            )
        if vuln_cfg.get("nuclei_profile") or explicit_v_engine in ("nuclei", "combined") or "nuclei" in (vuln_cfg.get("engines") or []):
            from src.services.nuclei_policy_service import NucleiPolicyService
            try:
                vuln_cfg["nuclei_profile"] = NucleiPolicyService.validate_profile(vuln_cfg.get("nuclei_profile") or "http-security")
                if vuln_cfg.get("nuclei_severities"):
                    vuln_cfg["nuclei_severities"] = NucleiPolicyService.validate_severities(
                        vuln_cfg.get("nuclei_severities"),
                        vuln_cfg["nuclei_profile"],
                    )
                if vuln_cfg.get("nuclei_tags"):
                    vuln_cfg["nuclei_tags"] = NucleiPolicyService.validate_tags(vuln_cfg.get("nuclei_tags"))
            except ValueError as exc:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    cfg["targets"] = [t["target"] for t in auth_info["targets"]]
    if selected_cats:
        cfg["selected_categories"] = selected_cats

    return {
        "primary_target": auth_info["primary_target"],
        "primary_type": auth_info["primary_type"],
        "targets_meta": auth_info["targets"],
        "is_draft": is_draft,
        "selected_categories": selected_cats,
        "normalized_config_json": json.dumps(cfg)
    }


@router.get("/options")
def get_recon_options(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Returns real-time Passive, Active, and Vulnerability options catalog with scanner readiness."""
    return ScanOptionsService.get_full_catalog()


@router.post("/validate-ports")
def validate_ports_endpoint(
    req: ValidatePortsRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Validates custom port list / ranges without executing any network traffic."""
    try:
        normalized = parse_and_validate_ports(req.ports_spec)
        return {"valid": True, "normalized": normalized}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("", status_code=status.HTTP_201_CREATED)
@router.post("/", status_code=status.HTTP_201_CREATED, include_in_schema=False)
def create_recon_campaign(
    req: CreateReconRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository)
):
    if not (req.name or "").strip() or not (req.target_value or "").strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Recon Name and Target are required.")
    if req.purpose is not None and not req.purpose.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Purpose cannot be empty.")

    operator = current_user.get("username", "asip_ali")
    try:
        val = _validate_campaign_configuration(
            target_value=req.target_value,
            targets_list=req.targets,
            excluded_targets=req.excluded_targets,
            excluded_ports=req.excluded_ports,
            selected_scan_types=req.selected_scan_types,
            scan_config_json=req.scan_config_json,
            authorization_confirmed=req.authorization_confirmed,
            operator=operator
        )
    except TargetAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ConcurrencyConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except EntityNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    idemp_key = req.idempotency_key or request.headers.get("X-Idempotency-Key")
    is_draft = bool(val.get("is_draft"))

    try:
        campaign = repo.create_recon_campaign(
            name=req.name.strip(),
            target_value=val["primary_target"],
            target_type=val["primary_type"] or req.target_type,
            description=req.description or "",
            purpose=(req.purpose or "Security Audit").strip(),
            scope_description=req.scope_description or "",
            excluded_targets=req.excluded_targets or "",
            excluded_ports=req.excluded_ports or "",
            allowed_methods=req.allowed_methods or "all",
            allowed_ports=req.allowed_ports or "1-65535",
            authorized_by=operator,
            creator_id=current_user.get("id", current_user.get("user_id", 1)),
            selected_scan_types=req.selected_scan_types or "combined",
            scan_config_json=val["normalized_config_json"],
            initial_status="Draft" if is_draft else "Authorized",
            initial_stage="Initialized" if is_draft else "Configured",
            authorization_status=("Authorized" if req.authorization_confirmed else "Pending") if is_draft else "Authorized",
            idempotency_key=idemp_key
        )
        # Register any additional multi-targets in DB authorization scope
        for extra in val["targets_meta"][1:]:
            try:
                repo.add_authorized_target(
                    investigation_id=campaign["recon_id"],
                    target=extra["target"],
                    name=f"{req.name} ({extra['target']})",
                    scope=extra.get("scope_basis", "Authorized Campaign Scope"),
                    permitted_profiles="lab-basic,lab-safe-minimal,lab-common-services",
                    allowed_ports=req.allowed_ports or "1-65535",
                    authorized_by=operator
                )
            except Exception:
                pass
    except DatabaseIntegrityError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    record_security_audit(
        repo,
        user=current_user,
        action="RECON_CAMPAIGN_CREATED",
        target_resource=campaign["recon_id"],
        details={"target": campaign.get("target_value"), "status": campaign.get("status")},
        outcome="SUCCESS",
        request=request,
    )
    return campaign


@router.put("/{recon_id}")
def update_recon_campaign_config(
    recon_id: str,
    req: UpdateReconRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository)
):
    """Updates campaign configuration during Pre-Scan Review ('Edit Configuration')."""
    camp = enforce_investigation_access(
        repo,
        current_user,
        recon_id,
        require_execution=True,
        request=request,
        action_label="RECON_CONFIG_UPDATE",
    )
    if camp.get("status") in ("Running", "Queued"):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Cannot edit a campaign while scan execution is active.")

    operator = current_user.get("username", "asip_ali")
    eff_target = req.target_value or camp.get("target_value", "")
    eff_scan_types = req.selected_scan_types or camp.get("selected_scan_types", "combined")
    eff_cfg = req.scan_config_json if req.scan_config_json is not None else (camp.get("scan_config_json") or "{}")
    eff_excl_t = req.excluded_targets if req.excluded_targets is not None else camp.get("excluded_targets", "")
    eff_excl_p = req.excluded_ports if req.excluded_ports is not None else camp.get("excluded_ports", "")

    try:
        val = _validate_campaign_configuration(
            target_value=eff_target,
            targets_list=req.targets,
            excluded_targets=eff_excl_t,
            excluded_ports=eff_excl_p,
            selected_scan_types=eff_scan_types,
            scan_config_json=eff_cfg,
            authorization_confirmed=req.authorization_confirmed,
            operator=operator
        )
    except TargetAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    updates = {
        "name": req.name or camp["name"],
        "target_value": val["primary_target"],
        "target_type": val["primary_type"],
        "description": req.description if req.description is not None else camp.get("description", ""),
        "purpose": req.purpose or camp.get("purpose", "Security Audit"),
        "scope_description": req.scope_description if req.scope_description is not None else camp.get("scope_description", ""),
        "excluded_targets": eff_excl_t,
        "excluded_ports": eff_excl_p,
        "allowed_ports": req.allowed_ports or camp.get("allowed_ports", "1-65535"),
        "selected_scan_types": eff_scan_types,
        "scan_config_json": val["normalized_config_json"]
    }
    if not val.get("is_draft") and val.get("selected_categories"):
        updates["status"] = "Authorized"
        updates["current_stage"] = "Configured"
        if req.authorization_confirmed:
            updates["authorization_status"] = "Authorized"
    try:
        repo.update_recon_campaign(recon_id, expected_version=req.version_id, **updates)
        # Ensure all validated targets exist in DB authorized targets
        existing_targets = {t.get("target") for t in repo.list_authorized_targets(investigation_id=recon_id)}
        for extra in val["targets_meta"]:
            if extra["target"] not in existing_targets:
                try:
                    repo.add_authorized_target(
                        investigation_id=recon_id,
                        target=extra["target"],
                        name=f"{updates['name']} ({extra['target']})",
                        scope=extra.get("scope_basis", "Authorized Campaign Scope"),
                        permitted_profiles="lab-basic,lab-safe-minimal,lab-common-services",
                        allowed_ports=updates["allowed_ports"],
                        authorized_by=operator
                    )
                except Exception:
                    pass
    except ConcurrencyConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

    record_security_audit(
        repo,
        user=current_user,
        action="RECON_CONFIG_UPDATED",
        target_resource=recon_id,
        details={"selected_scan_types": updates.get("selected_scan_types")},
        outcome="SUCCESS",
        request=request,
    )
    return repo.get_recon_campaign(recon_id)


@router.get("")
@router.get("/", include_in_schema=False)
def list_recon_campaigns(
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    camps = repo.list_recon_campaigns()
    accessible = filter_accessible_investigation_ids(repo, current_user)
    if accessible is None:
        return camps
    return [c for c in camps if c.get("recon_id") in accessible or c.get("investigation_id") in accessible]


@router.get("/profiles")
def list_profiles(
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    profs = repo.list_saved_scan_profiles()
    if is_admin_user(current_user):
        return profs
    uname = current_user.get("username")
    return [p for p in profs if p.get("is_builtin", True) or p.get("created_by") == uname]


@router.post("/profiles", status_code=status.HTTP_201_CREATED)
def create_profile(
    req: SaveProfileRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository)
):
    prof = {
        "name": req.name,
        "description": req.description,
        "category": req.category,
        "config_json": req.config_json,
        "is_builtin": False,
        "created_by": current_user.get("username", "investigator"),
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    repo._mem_profiles[req.name] = prof
    record_security_audit(
        repo,
        user=current_user,
        action="SCAN_PROFILE_CREATED",
        target_resource=req.name,
        details={"category": req.category},
        outcome="SUCCESS",
        request=request,
    )
    return prof


@router.get("/{recon_id}/runs")
def list_recon_runs(
    recon_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    """Lists all independent ScanExecution runs (`Run 001`, `Run 002`, ...) under one Investigation."""
    campaign = enforce_investigation_access(
        repo,
        current_user,
        recon_id,
        request=request,
        action_label="RECON_RUNS_LIST",
    )
    if not campaign.get("recon_id"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Recon Campaign '{recon_id}' not found.")

    runs = repo.list_scans(investigation_id=recon_id)
    all_findings = repo.list_findings(investigation_id=recon_id)
    all_evidence = repo.list_evidence(investigation_id=recon_id)
    all_reports = repo.list_report_records(investigation_id=recon_id)

    enriched = []
    for r in runs:
        sid = r.get("scan_id")
        run_findings = [f for f in all_findings if f.get("scan_id") == sid]
        run_evidence = [e for e in all_evidence if e.get("scan_id") == sid]
        run_reports = [rep for rep in all_reports if rep.get("scan_id") == sid]
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in run_findings:
            sv = str(f.get("severity") or "Informational").title()
            if sv == "Info":
                sv = "Informational"
            if sv in sev_counts:
                sev_counts[sv] += 1
        item = dict(r)
        item["findings_count"] = len(run_findings)
        item["evidence_count"] = len(run_evidence)
        item["reports_count"] = len(run_reports)
        item["severity_counts"] = sev_counts
        enriched.append(item)
    return enriched


@router.get("/{recon_id}/runs/{scan_id}")
def get_recon_run_detail(
    recon_id: str,
    scan_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    """Returns full isolated telemetry, findings, evidence, and reports for one specific ScanExecution run."""
    campaign = enforce_investigation_access(
        repo,
        current_user,
        recon_id,
        request=request,
        action_label="RECON_RUN_VIEW",
    )
    if not campaign.get("recon_id"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Recon Campaign '{recon_id}' not found.")

    scan = repo.get_scan(scan_id)
    if not scan or (scan.get("recon_id") != recon_id and scan.get("investigation_id") != recon_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan Run '{scan_id}' not found under investigation '{recon_id}'.")

    findings = repo.list_findings(investigation_id=recon_id, scan_id=scan_id)
    evidence = repo.list_evidence(investigation_id=recon_id, scan_id=scan_id)
    reports = repo.list_report_records(investigation_id=recon_id, scan_id=scan_id)
    bundle = load_campaign_results_bundle(recon_id, repo, scan_id=scan_id)
    return {
        "campaign": campaign,
        "scan": scan,
        "findings_count": len(findings),
        "evidence_count": len(evidence),
        "reports_count": len(reports),
        "findings": findings,
        "explained_findings": enrich_findings_with_explanations(findings),
        "evidence": evidence,
        "reports": reports,
        "passive_results": bundle["passive_results"],
        "active_hosts": bundle["active_hosts"],
        "discovered_ports": bundle["discovered_ports"],
        "scanner_statuses": bundle["scanner_statuses"],
        "failed_stages": bundle["failed_stages"],
        "events": bundle["events"],
    }


@router.get("/{recon_id}")
def get_recon_campaign(
    recon_id: str,
    request: Request,
    scan_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    campaign = enforce_investigation_access(
        repo,
        current_user,
        recon_id,
        request=request,
        action_label="RECON_VIEW",
    )
    if not campaign.get("recon_id"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Recon Campaign '{recon_id}' not found.")

    targets = repo.list_authorized_targets(investigation_id=recon_id)
    scans = repo.list_scans(investigation_id=recon_id)
    findings = repo.list_findings(investigation_id=recon_id, scan_id=scan_id)
    evidence = repo.list_evidence(investigation_id=recon_id, scan_id=scan_id)
    bundle = load_campaign_results_bundle(recon_id, repo, scan_id=scan_id)
    reports = repo.list_report_records(investigation_id=recon_id, scan_id=scan_id)
    live_ctx = ExecutionManager(repo=repo).build_live_snapshot(recon_id, campaign, scans, bundle, scan_id=scan_id)

    return {
        **campaign,
        "targets": targets,
        "scans": scans,
        "findings_count": len(findings),
        "evidence_count": len(evidence),
        "findings": findings,
        "explained_findings": enrich_findings_with_explanations(findings),
        "passive_results": bundle["passive_results"],
        "active_hosts": bundle["active_hosts"],
        "discovered_ports": bundle["discovered_ports"],
        "scanner_statuses": bundle["scanner_statuses"],
        "failed_stages": bundle["failed_stages"],
        "events": bundle["events"],
        "reports": reports,
        "live_ctx": live_ctx,
    }


@router.post("/{recon_id}/psa/detect")
def detect_privilege_requirements(
    recon_id: str,
    req: PSADetectRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    campaign = enforce_investigation_access(
        repo,
        current_user,
        recon_id,
        request=request,
        action_label="PSA_DETECT",
    )
    if not campaign.get("recon_id"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Recon Campaign '{recon_id}' not found.")

    if isinstance(req.scan_config, dict) and req.scan_config:
        cfg = dict(req.scan_config)
    elif req.scan_config_json:
        try:
            cfg = json.loads(req.scan_config_json)
        except Exception:
            cfg = {}
    else:
        try:
            cfg = json.loads(campaign.get("scan_config_json") or "{}")
        except Exception:
            cfg = {}

    analysis = PrivilegeDetector.analyze_scan_config(cfg, scan_type=req.scan_type or "combined")
    return analysis.to_dict()


@router.post("/{recon_id}/psa/verify")
def verify_identity_for_privilege(
    recon_id: str,
    req: PSAVerifyRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository)
):
    campaign = enforce_investigation_access(
        repo,
        current_user,
        recon_id,
        require_execution=True,
        request=request,
        action_label="PSA_VERIFY",
    )
    if not campaign.get("recon_id"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Recon Campaign '{recon_id}' not found.")

    if not req.password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password is required for identity verification.")

    if isinstance(req.scan_config, dict) and req.scan_config:
        cfg = dict(req.scan_config)
    elif req.scan_config_json:
        try:
            cfg = json.loads(req.scan_config_json)
        except Exception:
            cfg = {}
    else:
        try:
            cfg = json.loads(campaign.get("scan_config_json") or "{}")
        except Exception:
            cfg = {}

    analysis = PrivilegeDetector.analyze_scan_config(cfg, scan_type=req.scan_type or "combined")
    psa_svc = PSAService(repo=repo)
    try:
        ticket = psa_svc.verify_identity_and_issue_ticket(
            current_user=current_user,
            plain_password=req.password,
            recon_id=recon_id,
            target=campaign.get("target_value", ""),
            approved_operations=analysis.privileged_operations
        )
        record_security_audit(
            repo,
            user=current_user,
            action="PSA_IDENTITY_VERIFIED",
            target_resource=recon_id,
            details={"approved_operations": analysis.privileged_operations},
            outcome="SUCCESS",
            request=request
        )
        return ticket
    except PSAIdentityVerificationError as e:
        record_security_audit(
            repo,
            user=current_user,
            action="PSA_IDENTITY_VERIFICATION_FAILED",
            target_resource=recon_id,
            details={"error": "Invalid credentials provided for privilege authorization"},
            outcome="DENIED",
            request=request
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


@router.post("/{recon_id}/start")
def start_recon_scan(
    recon_id: str,
    req: StartReconRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository)
):
    campaign = enforce_investigation_access(
        repo,
        current_user,
        recon_id,
        require_execution=True,
        request=request,
        action_label="RECON_SCAN_START",
    )
    if not campaign.get("recon_id"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Recon Campaign '{recon_id}' not found.")

    # Verify configuration completeness and explicit availability of requested vulnerability engines
    if isinstance(req.scan_config, dict) and req.scan_config:
        cfg = dict(req.scan_config)
        if req.selected_categories and not cfg.get("selected_categories"):
            cfg["selected_categories"] = req.selected_categories
    elif req.scan_config_json:
        try:
            cfg = json.loads(req.scan_config_json)
        except Exception:
            cfg = {}
    else:
        try:
            cfg = json.loads(campaign.get("scan_config_json") or "{}")
        except Exception:
            cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}
    if req.selected_categories and not cfg.get("selected_categories"):
        cfg["selected_categories"] = req.selected_categories

    selected_cats = [str(c).lower() for c in (cfg.get("selected_categories") or [])]
    eff_scan_type = req.scan_type or campaign.get("selected_scan_types") or "combined"
    if eff_scan_type.lower() == "draft" and not selected_cats:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Select at least one assessment category (Passive, Active, or Vulnerability) before starting execution."
        )

    # Enforce active/vulnerability target authorization before starting
    eff_mode = "passive" if (selected_cats == ["passive"] or eff_scan_type.lower() == "passive") else "combined"
    try:
        raw_t = cfg.get("targets") or [t.strip() for t in str(campaign.get("target_value") or "").split(",") if t.strip()]
        TargetAuthorizer().authorize_campaign_targets(
            targets=raw_t,
            scope_mode=eff_mode,
            excluded_targets=campaign.get("excluded_targets"),
            explicit_authorization=(campaign.get("authorization_status", "").lower() == "authorized"),
            operator=current_user.get("username", "asip_ali")
        )
    except TargetAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    vuln_cfg = cfg.get("vulnerability") or {}
    v_engine = str(vuln_cfg.get("engine") or "").lower()
    v_engines = [str(e).lower() for e in (vuln_cfg.get("engines") or [])]
    need_greenbone = v_engine in ("greenbone", "combined_nessus_greenbone") or "greenbone" in v_engines or req.scan_type == "greenbone"
    need_nuclei = v_engine in ("nuclei", "combined") or "nuclei" in v_engines or req.scan_type == "nuclei"
    need_nessus = v_engine in ("nessus",) or "nessus" in v_engines or req.scan_type == "nessus"

    if need_greenbone:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active Greenbone/OpenVAS execution has been removed from FootprintIQ. Configure ProjectDiscovery Nuclei or Nmap NSE instead."
        )
    if need_nuclei:
        from src.collectors.nuclei_collector import NucleiCollector
        nuc_ready = NucleiCollector().check_readiness()
        if not nuc_ready.get("ready"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot launch ProjectDiscovery Nuclei assessment: {nuc_ready.get('reason') or 'Nuclei is unavailable.'}"
            )
    if need_nessus:
        from src.collectors.nessus_collector import NessusCollector
        n_conn = NessusCollector().test_connection()
        if not n_conn.get("connected"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Tenable Nessus is unavailable: {n_conn.get('error') or n_conn.get('status')}")
        if n_conn.get("scan_api_enabled") is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=n_conn.get("limitations") or "Nessus Essentials disables programmatic API scan launch (scan_api=false). Import existing Nessus scan results instead."
            )

    manager = ExecutionManager(repo=repo)
    try:
        has_override = bool(req.scan_config or req.scan_config_json or req.selected_categories)
        job = manager.start_recon_scan(
            recon_id=recon_id,
            scan_type=eff_scan_type,
            profile=req.profile or "lab-basic",
            custom_scripts=req.custom_scripts,
            operator=current_user.get("username", "asip_ali"),
            initiating_user_id=current_user.get("id", current_user.get("user_id")),
            scan_config_override=cfg if has_override else None,
            privilege_consent=bool(req.privilege_consent),
            psa_ticket=req.psa_ticket,
        )

        record_security_audit(
            repo,
            user=current_user,
            action="RECON_SCAN_STARTED",
            target_resource=campaign["target_value"],
            details={
                "recon_id": recon_id,
                "scan_id": job["scan_id"],
                "run_number": job.get("run_number"),
                "scan_type": eff_scan_type,
                "privilege_status": job.get("privilege_status"),
                "privilege_consent_given": job.get("privilege_consent_given"),
                "privilege_elevation_required": job.get("privilege_elevation_required"),
            },
            outcome="SUCCESS",
            request=request,
        )
        return job
    except TargetAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except PSATicketExpiredOrInvalidError as e:
        record_security_audit(
            repo,
            user=current_user,
            action="PRIVILEGE_TICKET_REJECTED",
            target_resource=recon_id,
            details={"error": str(e)},
            outcome="DENIED",
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except PSAIdentityVerificationError as e:
        record_security_audit(
            repo,
            user=current_user,
            action="PRIVILEGE_VERIFICATION_FAILED",
            target_resource=recon_id,
            details={"error": str(e)},
            outcome="DENIED",
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except ConcurrencyConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except EntityNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{recon_id}/cancel")
def cancel_recon_scan(
    recon_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository)
):
    enforce_investigation_access(
        repo,
        current_user,
        recon_id,
        require_execution=True,
        request=request,
        action_label="RECON_SCAN_CANCEL",
    )
    manager = ExecutionManager(repo=repo)
    manager.cancel_recon_scan(recon_id)
    record_security_audit(
        repo,
        user=current_user,
        action="RECON_SCAN_CANCELLED",
        target_resource=recon_id,
        outcome="SUCCESS",
        request=request,
    )
    return {"status": "SUCCESS", "message": f"Scan for {recon_id} cancellation signaled."}


@router.get("/{recon_id}/events")
def get_recon_events(
    recon_id: str,
    request: Request,
    scan_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    enforce_investigation_access(repo, current_user, recon_id, request=request, action_label="RECON_EVENTS")
    scans = repo.list_scans(investigation_id=recon_id)
    if not scans:
        return []

    target_scan_id = scan_id or scans[0]["scan_id"]
    return repo.list_scan_execution_events(target_scan_id)


@router.get("/{recon_id}/stream")
async def stream_recon_events(
    recon_id: str,
    request: Request,
    scan_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    """Server-Sent Events (SSE) live execution stream for web-native monitoring."""
    campaign = enforce_investigation_access(repo, current_user, recon_id, request=request, action_label="RECON_STREAM")
    if not campaign.get("recon_id"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Recon Campaign '{recon_id}' not found.")

    manager = ExecutionManager(repo=repo)
    ctx = manager.get_scan_context(recon_id, scan_id=scan_id)

    async def event_generator():
        # 1. First yield all historical events from database
        scans = repo.list_scans(investigation_id=recon_id)
        sent_messages = set()

        if scans:
            latest_scan_id = scan_id or scans[0]["scan_id"]
            db_events = repo.list_scan_execution_events(latest_scan_id)
            for ev in db_events:
                msg_key = f"{ev.get('timestamp')}:{ev.get('message')}"
                sent_messages.add(msg_key)
                yield f"data: {json.dumps(ev)}\n\n"

        # 2. If no active running context, close stream
        if not ctx or ctx.is_completed:
            camp = repo.get_recon_campaign(recon_id)
            final_status = camp.get("status", "Completed") if camp else "Completed"
            final_prog = camp.get("progress", 0) if camp else 0
            yield f"data: {json.dumps({'event_type': 'done', 'status': final_status, 'progress': final_prog})}\n\n"
            return

        # 3. Stream live events as they occur
        queue = asyncio.Queue()
        ctx.subscribers.append(queue)

        try:
            while not ctx.is_completed:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    msg_key = f"{event.get('timestamp')}:{event.get('message')}"
                    if msg_key not in sent_messages:
                        sent_messages.add(msg_key)
                        yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    # Send keep-alive heartbeat
                    yield f": heartbeat\n\n"

            # Final completion event with accurate campaign status
            camp_end = repo.get_recon_campaign(recon_id)
            final_st = camp_end.get("status", "Completed") if camp_end else "Completed"
            final_prog = camp_end.get("progress", 0) if camp_end else 0
            yield f"data: {json.dumps({'event_type': 'done', 'status': final_st, 'progress': final_prog})}\n\n"
        finally:
            if queue in ctx.subscribers:
                ctx.subscribers.remove(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/{recon_id}/findings")
def get_recon_findings(
    recon_id: str,
    request: Request,
    scan_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    enforce_investigation_access(repo, current_user, recon_id, request=request, action_label="RECON_FINDINGS")
    return repo.list_findings(investigation_id=recon_id, scan_id=scan_id)


@router.post("/{recon_id}/remediation")
def update_remediation(
    recon_id: str,
    req: RemediationUpdateRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_investigator),
    repo: FootprintIQRepository = Depends(get_repository)
):
    enforce_investigation_access(
        repo,
        current_user,
        recon_id,
        require_execution=True,
        request=request,
        action_label="REMEDIATION_UPDATE",
    )
    finding = repo.get_finding(req.finding_id)
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding '{req.finding_id}' not found.")
    if finding.get("investigation_id") and finding.get("investigation_id") != recon_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Finding does not belong to this campaign.")
    try:
        res = repo.update_finding_remediation_status(
            finding_id=req.finding_id,
            new_status=req.status,
            changed_by=current_user.get("username", "investigator"),
            notes=req.notes or "",
            expected_version=req.expected_version
        )
        record_security_audit(
            repo,
            user=current_user,
            action="FINDING_REMEDIATION_UPDATED",
            target_resource=req.finding_id,
            details={"recon_id": recon_id, "new_status": req.status},
            outcome="SUCCESS",
            request=request,
        )
        return {
            "status": "SUCCESS",
            "finding_id": req.finding_id,
            "new_status": req.status,
            "version_id": res.get("version_id")
        }
    except ConcurrencyConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except EntityNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DatabaseIntegrityError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{recon_id}/compare/{other_recon_id}")
def compare_recon_campaigns(
    recon_id: str,
    other_recon_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    repo: FootprintIQRepository = Depends(get_repository)
):
    """Compares two reconnaissance campaigns to identify delta findings and port exposure."""
    from src.services.exposure_scoring import ExposureScoringEngine

    c1 = enforce_investigation_access(repo, current_user, recon_id, request=request, action_label="RECON_COMPARE")
    c2 = enforce_investigation_access(repo, current_user, other_recon_id, request=request, action_label="RECON_COMPARE")
    if not c1.get("recon_id") or not c2.get("recon_id"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or both Recon Campaigns not found.")

    f1 = repo.list_findings(investigation_id=recon_id)
    f2 = repo.list_findings(investigation_id=other_recon_id)

    f1_titles = {f["title"]: f for f in f1}
    f2_titles = {f["title"]: f for f in f2}

    # f1 is current scan, f2 is baseline
    new_findings = [f for t, f in f1_titles.items() if t not in f2_titles]
    resolved_findings = [f for t, f in f2_titles.items() if t not in f1_titles]
    persistent_findings = [f for t, f in f1_titles.items() if t in f2_titles]

    f1_ports = {f.get("port") for f in f1 if f.get("port")}
    f2_ports = {f.get("port") for f in f2 if f.get("port")}

    exp1 = ExposureScoringEngine.calculate_investigation_exposure(f1)["exposure_score"]
    exp2 = ExposureScoringEngine.calculate_investigation_exposure(f2)["exposure_score"]
    score_delta = round(exp1 - exp2, 1)

    return {
        "base_recon_id": recon_id,
        "compare_recon_id": other_recon_id,
        "target": c1.get("target_value"),
        "exposure_score_delta": score_delta,
        "metrics": {
            "exposure_score_delta": score_delta,
            "new_findings_count": len(new_findings),
            "resolved_findings_count": len(resolved_findings),
            "persistent_findings_count": len(persistent_findings),
            "newly_opened_ports": list(f1_ports - f2_ports),
            "closed_ports": list(f2_ports - f1_ports)
        },
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "persistent_findings": persistent_findings
    }
