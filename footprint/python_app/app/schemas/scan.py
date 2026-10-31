"""Pydantic schemas for active Nmap reconnaissance scanning, profiles, and findings."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class NmapStatusResponse(BaseModel):
    """Safe diagnostic report of Nmap installation and runtime capabilities."""
    is_available: bool
    version: Optional[str] = None
    platform: Optional[str] = None
    binary_name: str
    diagnostic_code: str
    message: str
    capabilities: List[str] = []
    error: Optional[str] = None


class ScanProfileResponse(BaseModel):
    """Administrator-configured immutable scan profile descriptor."""
    id: str
    name: str
    description: str
    version: str
    timeout_seconds: int
    max_output_bytes: int
    permitted_target_types: List[str]
    requires_privileged: bool = False
    is_enabled: bool = True


class ScanJobCreate(BaseModel):
    """Payload to dispatch an authorized active Nmap scan."""
    target: str = Field(..., min_length=1, max_length=255, description="Authorized domain, IP or CIDR target")
    profile_id: str = Field(default="basic_tcp", description="Reviewed scan profile ID (e.g. 'basic_tcp')")


class ScanJobResponse(BaseModel):
    """Active scan job execution status and execution summary."""
    id: str
    investigation_id: str
    requested_by: str
    target: str
    resolved_ips: List[str] = []
    scan_profile: str
    scan_profile_version: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    exit_code: Optional[int] = None
    evidence_id: Optional[str] = None
    error_category: Optional[str] = None
    error_message: Optional[str] = None
    cancellation_reason: Optional[str] = None
    command_summary: Optional[str] = None
    hosts_count: int = 0


class ScanCancelRequest(BaseModel):
    """Payload to request cancellation of an active scan job."""
    reason: Optional[str] = Field(default="User requested cancellation", max_length=255)


class ScanPortResponse(BaseModel):
    """Port and service finding from an active scan."""
    id: str
    protocol: str
    port_number: int
    state: str
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    cpe: Optional[str] = None
    method: Optional[str] = None
    confidence: Optional[int] = None
    created_at: datetime


class ScanHostResponse(BaseModel):
    """Host finding containing discovered ports and metadata."""
    id: str
    address: str
    address_type: str
    status: str
    hostname: Optional[str] = None
    os_match: Optional[str] = None
    ports: List[ScanPortResponse] = []


class ScanResultsResponse(BaseModel):
    """Aggregated findings for a completed or partial scan job."""
    job_id: str
    investigation_id: str
    target: str
    scan_profile: str
    status: str
    evidence_id: Optional[str] = None
    hosts: List[ScanHostResponse] = []
    total_hosts: int = 0
    total_ports: int = 0
