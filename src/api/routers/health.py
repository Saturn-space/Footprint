"""
FootprintIQ - System & Scanner Health Router
Endpoint:
- GET /api/v1/health (Comprehensive health status across DB, SeaweedFS, and all scanners)
"""

import os
import shutil
from fastapi import APIRouter
from src.db.session import check_db_health
from src.storage.seaweedfs_client import SeaweedFSClient
from src.collectors.nessus_collector import NessusCollector
from src.collectors.nuclei_collector import NucleiCollector
from src.services.graph_intelligence_service import GraphIntelligenceService

router = APIRouter(prefix="/api/v1/health", tags=["Health & Diagnostics"])


def _detect_nmap_binary() -> str:
    """Cross-platform binary resolution for Nmap."""
    env_path = os.getenv("NMAP_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path
    
    which_path = shutil.which("nmap") or shutil.which("nmap.exe")
    if which_path:
        return which_path

    # Common Windows install locations
    if os.name == "nt":
        for win_path in [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe"
        ]:
            if os.path.isfile(win_path):
                return win_path

    # Linux default
    if os.path.isfile("/usr/bin/nmap"):
        return "/usr/bin/nmap"

    return ""


@router.get("")
def get_system_health():
    # 1. Database Health
    db_status = check_db_health()

    # 2. SeaweedFS Health
    storage = SeaweedFSClient()
    seaweed_status = storage.check_health()

    # 3. Nmap / NSE Health (sanitized: omit internal binary paths on public health endpoint)
    nmap_path = _detect_nmap_binary()
    nmap_status = {
        "status": "ONLINE" if nmap_path else "MISSING",
        "capabilities": ["SYN", "TCP", "UDP", "NSE", "Service Detection", "OS Detection"]
    }

    # 4. ProjectDiscovery Nuclei Health (sanitized: omit internal binary/template paths)
    nuclei_info = NucleiCollector().check_readiness()
    nuclei_status = {
        "status": "ONLINE" if nuclei_info.get("ready") else "UNAVAILABLE",
        "version": nuclei_info.get("version"),
        "templates_count": nuclei_info.get("templates_count", 0),
        "profiles_count": len(nuclei_info.get("profiles") or []),
    }

    # 5. Nessus Scanner Health (sanitized: omit internal URL)
    nessus_collector = NessusCollector()
    nessus_status = nessus_collector.check_status()
    nessus_status.pop("server_url", None)

    # 6. Native Entity Graph / Maltego Interchange Readiness
    graph_rt = GraphIntelligenceService.get_maltego_runtime_status()
    maltego_graph_status = {
        "status": "ONLINE",
        "mode": graph_rt.get("mode"),
        "maltego_desktop_installed": graph_rt.get("maltego_desktop_installed", False),
    }

    # Overall system state
    all_ready = (
        seaweed_status.get("status") == "ONLINE" and
        nmap_status.get("status") == "ONLINE"
    )

    return {
        "platform": "FootprintIQ",
        "version": "2.0-Enterprise",
        "system_status": "OPERATIONAL" if all_ready else "DEGRADED",
        "database": {"status": db_status.get("status", "Active") if isinstance(db_status, dict) else str(db_status)},
        "object_storage": {"status": seaweed_status.get("status", "UNKNOWN")},
        "network_scanner": nmap_status,
        "vulnerability_scanners": {
            "nuclei": nuclei_status,
            "nessus": nessus_status,
        },
        "graph_intelligence": maltego_graph_status,
    }

