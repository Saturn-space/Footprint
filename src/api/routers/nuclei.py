"""
FootprintIQ - ProjectDiscovery Nuclei Scanner Status & Profiles Router
Endpoints:
- GET /api/v1/scanners/nuclei/status (Authenticated live readiness & template catalog counts)
- GET /api/v1/scanners/nuclei/profiles (Safe non-destructive profile definitions & exclusions)
"""

from fastapi import APIRouter, Depends
from typing import Any, Dict

from src.api.dependencies import get_current_user
from src.collectors.nuclei_collector import NucleiCollector
from src.services.nuclei_policy_service import NucleiPolicyService

router = APIRouter(prefix="/api/v1/scanners/nuclei", tags=["Nuclei Scanner"])


@router.get("/status")
def get_nuclei_status(_current_user: Dict[str, Any] = Depends(get_current_user)):
    """Returns real host readiness for the ProjectDiscovery Nuclei executable and templates."""
    return NucleiCollector().check_readiness()


@router.get("/profiles")
def get_nuclei_profiles(_current_user: Dict[str, Any] = Depends(get_current_user)):
    """Returns curated safe assessment profiles and excluded policy tags/protocols."""
    profiles = NucleiPolicyService.list_profiles()
    return {
        "count": len(profiles),
        "profiles": profiles,
        "catalog": NucleiPolicyService.inspect_templates_catalog(),
    }
