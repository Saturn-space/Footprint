"""Administrator-configured, immutable Nmap scan profiles for FootprintIQ."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass(frozen=True)
class ScanProfile:
    """Immutable representation of a vetted active scan profile."""

    id: str
    name: str
    description: str
    version: str
    args: List[str]
    timeout_seconds: int
    max_output_bytes: int
    permitted_target_types: List[str]
    requires_privileged: bool = False
    is_enabled: bool = True

    def to_dict(self) -> Dict:
        """Serializes profile details safe for API and UI consumption."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "timeout_seconds": self.timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
            "permitted_target_types": self.permitted_target_types,
            "requires_privileged": self.requires_privileged,
            "is_enabled": self.is_enabled,
            # Note: args are not exposed via client API to prevent argument manipulation
        }


# Strict, vetted profiles suitable for authorized laboratory environments
VETTED_SCAN_PROFILES: Dict[str, ScanProfile] = {
    "basic_tcp": ScanProfile(
        id="basic_tcp",
        name="Basic TCP Discovery",
        description="Conservative TCP connect scan targeting top 100 ports with standard timing.",
        version="1.0",
        args=["-sT", "-T3", "--top-ports", "100", "-Pn"],
        timeout_seconds=90,
        max_output_bytes=2 * 1024 * 1024,  # 2 MB
        permitted_target_types=["ip", "cidr", "domain"],
        requires_privileged=False,
        is_enabled=True,
    ),
    "service_inventory": ScanProfile(
        id="service_inventory",
        name="Service Inventory Scan",
        description="TCP connect scan with version detection (-sV) on top 100 ports with version intensity 2.",
        version="1.0",
        args=["-sT", "-sV", "--version-intensity", "2", "-T3", "--top-ports", "100", "-Pn"],
        timeout_seconds=180,
        max_output_bytes=5 * 1024 * 1024,  # 5 MB
        permitted_target_types=["ip", "cidr", "domain"],
        requires_privileged=False,
        is_enabled=True,
    ),
    "quick_ping": ScanProfile(
        id="quick_ping",
        name="Quick Host Discovery",
        description="Lightweight ping and host-reachability scan without port interrogation.",
        version="1.0",
        args=["-sn", "-T3"],
        timeout_seconds=45,
        max_output_bytes=1024 * 1024,  # 1 MB
        permitted_target_types=["ip", "cidr", "domain"],
        requires_privileged=False,
        is_enabled=True,
    ),
}


def get_scan_profile(profile_id: str) -> Optional[ScanProfile]:
    """Retrieves a vetted profile by ID. Returns None if unknown or disabled."""
    profile = VETTED_SCAN_PROFILES.get(profile_id)
    if profile and profile.is_enabled:
        return profile
    return None


def list_scan_profiles() -> List[ScanProfile]:
    """Returns list of all active vetted scan profiles."""
    return [p for p in VETTED_SCAN_PROFILES.values() if p.is_enabled]
