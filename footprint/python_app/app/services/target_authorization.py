"""Target authorization validation and scope enforcement service."""

import re
import ipaddress
from datetime import datetime, timezone
from typing import Optional, Tuple, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models.investigation import InvestigationModel
from app.models.recon import TargetAuthorizationModel, ensure_utc
from app.core.auth import log_audit_event


def classify_target(target: str) -> str:
    """Classifies target string into DOMAIN, IP, CIDR, or UNKNOWN."""
    if not target or not isinstance(target, str):
        return "UNKNOWN"
    cleaned = target.strip()

    # Check CIDR
    if "/" in cleaned:
        try:
            ipaddress.ip_network(cleaned, strict=False)
            return "CIDR"
        except ValueError:
            return "UNKNOWN"

    # Check Single IP (IPv4 or IPv6)
    try:
        ipaddress.ip_address(cleaned)
        return "IP"
    except ValueError:
        pass

    # Check FQDN Domain
    domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if re.match(domain_pattern, cleaned):
        return "DOMAIN"

    return "UNKNOWN"


def is_target_in_investigation_scope(investigation: InvestigationModel, target: str) -> Tuple[bool, str]:
    """Checks whether target syntax is valid and falls within the investigation's approved scope."""
    target_type = classify_target(target)
    if target_type == "UNKNOWN":
        return False, f"Invalid target format: '{target}'."

    cleaned = target.strip().lower()

    if target_type == "DOMAIN":
        # Check against owned_domains or active_targets
        for owned in (investigation.owned_domains or []):
            owned_clean = owned.strip().lower()
            if cleaned == owned_clean or cleaned.endswith(f".{owned_clean}"):
                return True, f"Target matches approved investigation domain scope '{owned_clean}'."

        for active in (investigation.active_targets or []):
            if cleaned == active.strip().lower():
                return True, f"Target matches approved active target '{active}'."

        return False, f"Domain '{target}' is not within approved investigation scope."

    elif target_type == "IP":
        try:
            target_ip = ipaddress.ip_address(cleaned)
        except ValueError:
            return False, f"Invalid IP format: '{target}'."

        # Check approved_ips and active_targets
        for app_ip in (investigation.approved_ips or []) + (investigation.active_targets or []):
            try:
                if target_ip == ipaddress.ip_address(app_ip.strip()):
                    return True, f"IP matches approved target IP '{app_ip}'."
            except ValueError:
                continue

        # Check approved_cidrs
        for cidr in (investigation.approved_cidrs or []):
            try:
                net = ipaddress.ip_network(cidr.strip(), strict=False)
                if target_ip in net:
                    return True, f"IP falls within approved network CIDR '{cidr}'."
            except ValueError:
                continue

        return False, f"IP '{target}' is not within approved investigation IP or CIDR scope."

    elif target_type == "CIDR":
        try:
            target_net = ipaddress.ip_network(cleaned, strict=False)
        except ValueError:
            return False, f"Invalid CIDR format: '{target}'."

        for cidr in (investigation.approved_cidrs or []):
            try:
                net = ipaddress.ip_network(cidr.strip(), strict=False)
                if target_net.subnet_of(net) or target_net == net:
                    return True, f"CIDR is within approved investigation network '{cidr}'."
            except ValueError:
                continue

        return False, f"Network CIDR '{target}' is not within approved investigation scope."

    return False, "Target format unsupported."


def verify_target_authorization(
    db: Session,
    investigation: InvestigationModel,
    target: str,
    operation: str = "PASSIVE_RECON",
    actor_id: Optional[str] = None,
    request_id: Optional[str] = None,
    client_ip: Optional[str] = None,
    actor_user: Optional[Any] = None,
) -> Tuple[bool, str]:
    """Strictly validates target scope and verifies non-expired, unrevoked administrative authorization.

    Returns:
        (is_authorized, reason_message)
    """
    if actor_user and not actor_id:
        actor_id = getattr(actor_user, "id", None)

    # 1. Scope syntax & membership check
    in_scope, scope_msg = is_target_in_investigation_scope(investigation, target)
    if not in_scope:
        log_audit_event(
            db=db,
            event_type="TARGET_AUTHORIZATION_REJECTED",
            outcome="FAILURE",
            actor_id=actor_id,
            request_id=request_id,
            ip_address=client_ip,
            details={"investigation_id": investigation.id, "target": target, "reason": scope_msg},
        )
        return False, scope_msg

    cleaned_target = target.strip().lower()
    now = datetime.now(timezone.utc)

    # 2. Check explicit TargetAuthorizationModel
    stmt = (
        select(TargetAuthorizationModel)
        .where(
            TargetAuthorizationModel.investigation_id == investigation.id,
        )
        .order_by(TargetAuthorizationModel.created_at.desc())
    )
    authorizations = db.scalars(stmt).all()

    for authz in authorizations:
        authz_target = authz.target.strip().lower()
        matches = False

        if authz.target_type == "DOMAIN":
            if cleaned_target == authz_target or cleaned_target.endswith(f".{authz_target}"):
                matches = True
        elif authz.target_type == "IP":
            if cleaned_target == authz_target:
                matches = True
        elif authz.target_type == "CIDR":
            try:
                t_ip = ipaddress.ip_address(cleaned_target)
                authz_net = ipaddress.ip_network(authz_target, strict=False)
                if t_ip in authz_net:
                    matches = True
            except ValueError:
                if cleaned_target == authz_target:
                    matches = True

        if matches:
            valid, reason = authz.is_valid_for(operation)
            if valid:
                log_audit_event(
                    db=db,
                    event_type="TARGET_AUTHORIZATION_VERIFIED",
                    outcome="SUCCESS",
                    actor_id=actor_id,
                    request_id=request_id,
                    ip_address=client_ip,
                    details={
                        "investigation_id": investigation.id,
                        "target": target,
                        "authorization_id": authz.id,
                        "operation": operation,
                    },
                )
                return True, f"Target authorized via record '{authz.authorization_reference}'."
            else:
                log_audit_event(
                    db=db,
                    event_type="TARGET_AUTHORIZATION_REJECTED",
                    outcome="FAILURE",
                    actor_id=actor_id,
                    request_id=request_id,
                    ip_address=client_ip,
                    details={
                        "investigation_id": investigation.id,
                        "target": target,
                        "authorization_id": authz.id,
                        "reason": reason,
                    },
                )
                return False, reason

    # 3. Fallback: Investigation-level authorization reference and expiry
    # If the investigation itself has a valid authorization_reference and has not expired
    if investigation.authorization_reference:
        if investigation.authorization_expiry:
            expiry_utc = ensure_utc(investigation.authorization_expiry)
            if now > expiry_utc:
                reason = f"Investigation authorization '{investigation.authorization_reference}' expired on {expiry_utc.isoformat()}."
                log_audit_event(
                    db=db,
                    event_type="TARGET_AUTHORIZATION_REJECTED",
                    outcome="FAILURE",
                    actor_id=actor_id,
                    request_id=request_id,
                    ip_address=client_ip,
                    details={"investigation_id": investigation.id, "target": target, "reason": reason},
                )
                return False, reason

        log_audit_event(
            db=db,
            event_type="TARGET_AUTHORIZATION_VERIFIED",
            outcome="SUCCESS",
            actor_id=actor_id,
            request_id=request_id,
            ip_address=client_ip,
            details={
                "investigation_id": investigation.id,
                "target": target,
                "authorization_reference": investigation.authorization_reference,
                "operation": operation,
            },
        )
        return True, f"Target authorized via investigation reference '{investigation.authorization_reference}'."

    reason = f"No valid administrative authorization record permitting '{operation}' found for target '{target}'."
    log_audit_event(
        db=db,
        event_type="TARGET_AUTHORIZATION_REJECTED",
        outcome="FAILURE",
        actor_id=actor_id,
        request_id=request_id,
        ip_address=client_ip,
        details={"investigation_id": investigation.id, "target": target, "reason": reason},
    )
    return False, reason
