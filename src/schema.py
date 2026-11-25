"""
OSINT-RECON Standardized Data Models (Pydantic v2)
Ensures strict validation, serialization, and normalization of reconnaissance findings.
Preserves full backward compatibility with W1 baseline models.
"""

from datetime import datetime, timezone
from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field


class TargetInfo(BaseModel):
    target: str = Field(..., description="Target domain, hostname, or IP address")
    category: Literal[
        "intentionally_vulnerable_lab",
        "nmap_practice_target",
        "normal_benchmark_domain",
        "local_loopback"
    ] = Field(..., description="Target category")
    authorization_status: str = Field(..., description="Authorization status / scope permission")
    scope: str = Field(..., description="Explicit permitted scope string")


class ToolInfo(BaseModel):
    name: str = Field(..., description="Tool name (e.g. nmap, whois, theHarvester, dnspython)")
    version: str = Field(..., description="Installed tool version")
    execution_args: Optional[str] = Field(None, description="Arguments supplied to the tool")


class DNSRecord(BaseModel):
    record_type: str = Field(..., description="DNS record type (A, AAAA, MX, NS, TXT, CNAME, etc.)")
    value: str = Field(..., description="Resolved value of the record")
    ttl: Optional[int] = Field(None, description="Time-To-Live in seconds")
    priority: Optional[int] = Field(None, description="Priority value for MX/SRV records")


class ServiceInfo(BaseModel):
    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field("tcp", description="Protocol (tcp or udp)")
    state: str = Field(..., description="Port state (open, filtered, closed)")
    service_name: Optional[str] = Field(None, description="Detected service name")
    product: Optional[str] = Field(None, description="Detected service product/banner")
    version: Optional[str] = Field(None, description="Detected service version")


class WhoisData(BaseModel):
    domain_name: Optional[str] = Field(None, description="Registered domain name")
    registrar: Optional[str] = Field(None, description="Domain registrar name")
    creation_date: Optional[str] = Field(None, description="Domain creation date in ISO 8601 UTC")
    expiration_date: Optional[str] = Field(None, description="Domain expiration date in ISO 8601 UTC")
    updated_date: Optional[str] = Field(None, description="Domain last updated date in ISO 8601 UTC")
    status: List[str] = Field(default_factory=list, description="EPP status codes")
    name_servers: List[str] = Field(default_factory=list, description="Authoritative name servers")
    registrant_name: Optional[str] = Field(None, description="Registrant name (if public)")
    registrant_organization: Optional[str] = Field(None, description="Registrant organization (if public)")
    registrant_country: Optional[str] = Field(None, description="Registrant country code")
    emails: List[str] = Field(default_factory=list, description="Associated contact/abuse emails")
    dnssec: Optional[str] = Field(None, description="DNSSEC configuration status")
    raw_text: Optional[str] = Field(None, description="Raw WHOIS server response text")


class ReconRecord(BaseModel):
    target_info: TargetInfo
    timestamp_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    tool_info: ToolInfo
    recon_category: Literal[
        "whois",
        "dns",
        "search_engine_harvesting",
        "port_scan",
        "vulnerability_scan"
    ]
    scan_id: Optional[str] = Field(None, description="Unique scan session identifier")
    discovered_domains: List[str] = Field(default_factory=list)
    ip_addresses: List[str] = Field(default_factory=list)
    dns_records: List[DNSRecord] = Field(default_factory=list)
    email_addresses: List[str] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    service_information: List[ServiceInfo] = Field(default_factory=list)
    whois_data: Optional[WhoisData] = Field(None, description="Structured WHOIS registration data")
    evidence_source: str = Field(..., description="Primary evidence source file or command stream")
    scan_status: Literal["SUCCESS", "PARTIAL", "FAILED"] = "SUCCESS"
    errors_and_warnings: List[str] = Field(default_factory=list)
    raw_output_reference: Optional[str] = Field(None, description="Path to preserved raw output file")


class NormalizedFinding(BaseModel):
    target: str = Field(..., description="Target domain or hostname")
    scan_id: str = Field(..., description="Unique scan session ID")
    collector: str = Field(..., description="Collector module that sourced the finding")
    finding_type: Literal[
        "domain",
        "subdomain",
        "ip_address",
        "dns_record",
        "email",
        "nameserver",
        "registrar"
    ] = Field(..., description="Categorized finding type")
    finding_value: str = Field(..., description="Normalized string representation of the finding")
    source_tools: List[str] = Field(default_factory=list, description="All tools that contributed this finding")
    source_details: Dict[str, Any] = Field(default_factory=dict, description="Metadata and context from sources")
    timestamp_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: Literal["VALID", "PARTIAL", "UNVERIFIED"] = "VALID"
    evidence_reference: Optional[str] = Field(None, description="Path to raw evidence file")
    verification_state: str = Field("unverified", description="Passive verification state")


class PassivePipelineResult(BaseModel):
    scan_id: str = Field(..., description="Unique execution identifier")
    target_domain: str = Field(..., description="Validated target domain")
    start_time_utc: str = Field(..., description="Pipeline execution start time in ISO 8601 UTC")
    end_time_utc: str = Field(..., description="Pipeline execution end time in ISO 8601 UTC")
    overall_status: Literal["SUCCESS", "PARTIAL", "FAILED"] = Field(..., description="Consolidated pipeline status")
    collector_records: List[ReconRecord] = Field(default_factory=list, description="Per-collector reconnaissance records")
    deduplicated_findings: List[NormalizedFinding] = Field(default_factory=list, description="Normalized, deduplicated findings")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Summary counts and statistics")
    defensive_observations: List[str] = Field(default_factory=list, description="Defensive security observations")
    recommended_actions: List[str] = Field(default_factory=list, description="Defensive recommendations")
    raw_files: Dict[str, str] = Field(default_factory=dict, description="Paths to preserved raw evidence files")
    json_report_path: Optional[str] = Field(None, description="Path to output JSON report")
    pdf_report_path: Optional[str] = Field(None, description="Path to generated PDF report")
    errors: List[str] = Field(default_factory=list, description="Aggregated pipeline errors or warnings")


# =============================================================================
# W3 ACTIVE RECONNAISSANCE MODELS (Nmap Integration & Scope Control)
# =============================================================================

class TargetAuthorizationRecord(BaseModel):
    target: str = Field(..., description="Authorized target IP address or hostname")
    authorized: bool = Field(True, description="Strict authorization decision")
    authorization_status: str = Field(..., description="Authorization code or status string")
    category: str = Field(..., description="Target category (e.g. intentionally_vulnerable_lab)")
    scope: str = Field(..., description="Explicit permitted scope string")
    permitted_profiles: List[str] = Field(default_factory=list, description="Allowed scan profiles")
    scan_profile: str = Field(..., description="Active scan profile requested")
    operator: str = Field(..., description="Operator identifier")
    timestamp_utc: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    notes: Optional[str] = Field(None, description="Scope and authorization notes")


class NmapService(BaseModel):
    name: str = Field(..., description="Service name (e.g. ssh, http, ftp)")
    product: Optional[str] = Field(None, description="Software product banner")
    version: Optional[str] = Field(None, description="Software version detected")
    extrainfo: Optional[str] = Field(None, description="Extra service metadata")
    ostype: Optional[str] = Field(None, description="Detected operating system family")
    method: Optional[str] = Field(None, description="Detection method (e.g. probed, table)")
    conf: Optional[int] = Field(None, description="Confidence level (3-10)")
    cpe: List[str] = Field(default_factory=list, description="Common Platform Enumeration strings")
    servicefp: Optional[str] = Field(None, description="Service fingerprint if unparsed")


class NmapPort(BaseModel):
    portid: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field("tcp", description="Protocol (tcp or udp)")
    state: str = Field(..., description="Port state (open, filtered, closed)")
    reason: Optional[str] = Field(None, description="Nmap reason for state assignment")
    reason_ttl: Optional[int] = Field(None, description="Reason TTL")
    service: Optional[NmapService] = Field(None, description="Detected service details")


class NmapHost(BaseModel):
    address: str = Field(..., description="Target host address")
    addrtype: str = Field("ipv4", description="Address type (ipv4, ipv6, mac)")
    status: str = Field("up", description="Host state (up, down, unknown)")
    status_reason: Optional[str] = Field(None, description="Reason for host status")
    hostnames: List[str] = Field(default_factory=list, description="Resolved hostnames")
    ports: List[NmapPort] = Field(default_factory=list, description="Discovered port objects")
    closed_ports_count: int = Field(0, description="Count of closed ports reported by extraports")
    filtered_ports_count: int = Field(0, description="Count of filtered ports reported by extraports")


class NmapScanMetadata(BaseModel):
    scanner: str = Field("nmap", description="Scanner identifier")
    version: str = Field(..., description="Nmap version string")
    profile: str = Field(..., description="Scan profile executed")
    command_args: str = Field(..., description="Command arguments executed")
    start_time_utc: str = Field(..., description="Scan start time in ISO 8601 UTC")
    end_time_utc: str = Field(..., description="Scan end time in ISO 8601 UTC")
    elapsed_seconds: Optional[float] = Field(None, description="Scan duration in seconds")
    xml_version: Optional[str] = Field(None, description="Nmap XML format version")
    exit_code: int = Field(0, description="Nmap process exit code")


class ActiveReconResult(BaseModel):
    scan_id: str = Field(..., description="Unique execution identifier")
    target: str = Field(..., description="Target host address")
    authorization_record: TargetAuthorizationRecord = Field(..., description="Strict authorization record")
    scan_profile: str = Field(..., description="Scan profile executed")
    start_time_utc: str = Field(..., description="Start time in ISO 8601 UTC")
    end_time_utc: str = Field(..., description="End time in ISO 8601 UTC")
    overall_status: Literal["SUCCESS", "PARTIAL", "FAILED", "BLOCKED"] = Field(..., description="Consolidated scan status")
    hosts: List[NmapHost] = Field(default_factory=list, description="Scanned host objects")
    scan_metadata: Optional[NmapScanMetadata] = Field(None, description="Scan execution metadata")
    recon_record: Optional[ReconRecord] = Field(None, description="Unified ReconRecord validating against recon_schema.json")
    raw_files: Dict[str, str] = Field(default_factory=dict, description="Paths to preserved raw evidence files")
    file_hashes: Dict[str, str] = Field(default_factory=dict, description="SHA256 checksums of raw evidence")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Summary counts and statistics")
    defensive_observations: List[str] = Field(default_factory=list, description="Defensive security observations")
    recommended_actions: List[str] = Field(default_factory=list, description="Defensive hardening actions")
    json_report_path: Optional[str] = Field(None, description="Path to output JSON report")
    pdf_report_path: Optional[str] = Field(None, description="Path to generated PDF report")
    errors: List[str] = Field(default_factory=list, description="Scanner and pipeline errors or warnings")


# =============================================================================
# W4 INTELLIGENCE CORRELATION MODELS (Cross-Source Synthesis & Graph)
# =============================================================================

class Asset(BaseModel):
    asset_id: str = Field(..., description="Stable deterministic asset identifier (e.g. ASSET:DOMAIN:example.com)")
    asset_type: Literal[
        "domain",
        "subdomain",
        "ipv4",
        "ipv6",
        "hostname",
        "email",
        "nameserver",
        "service",
        "port",
        "cpe"
    ] = Field(..., description="Standardized asset entity type")
    canonical_value: str = Field(..., description="Canonical normalized representation of the asset")
    display_name: str = Field(..., description="Human-readable display name")
    first_seen: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp when asset was first observed"
    )
    last_seen: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp when asset was most recently observed"
    )
    sources: List[str] = Field(default_factory=list, description="Source tools/scans that observed this asset")
    tags: List[str] = Field(default_factory=list, description="Categorization tags (e.g. lab, external, public_dns)")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary verified asset attributes")


class AssetRelationship(BaseModel):
    relationship_id: str = Field(..., description="Unique deterministic relationship identifier")
    source_asset_id: str = Field(..., description="Originating asset identifier")
    target_asset_id: str = Field(..., description="Target asset identifier")
    relationship_type: Literal[
        "DOMAIN_RESOLVES_TO_IP",
        "SUBDOMAIN_OF",
        "DOMAIN_USES_NAMESERVER",
        "HOSTNAME_RESOLVES_TO_IP",
        "IP_HAS_OPEN_PORT",
        "IP_EXPOSES_SERVICE",
        "SERVICE_HAS_VERSION",
        "SERVICE_HAS_CPE",
        "EMAIL_DOMAIN_ASSOCIATION",
        "HOSTNAME_OBSERVED_ON_SCAN",
        "DOMAIN_HAS_REGISTRAR"
    ] = Field(..., description="Standardized relationship predicate")
    evidence_ids: List[str] = Field(default_factory=list, description="Identifiers of supporting evidence records")
    confidence: Literal["DIRECT", "CORROBORATED", "INDIRECT", "UNCONFIRMED"] = Field(
        ..., description="Qualitative confidence classification"
    )
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Deterministic numeric confidence score (0.0 - 1.0)")
    confidence_explanation: str = Field(..., description="Human-readable justification for confidence evaluation")
    first_observed: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of earliest observation"
    )
    last_observed: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of latest observation"
    )


class EvidenceReference(BaseModel):
    evidence_id: str = Field(..., description="Unique deterministic evidence identifier (e.g. EVID-...)")
    source_module: str = Field(..., description="Originating module or collector (e.g. whois, dnspython, nmap)")
    scan_id: str = Field(..., description="Scan identifier where evidence was captured")
    evidence_type: str = Field(..., description="Categorical evidence type (e.g. dns_a_record, nmap_syn_ack, whois_txt)")
    original_value: str = Field(..., description="Raw observed value before normalization")
    normalized_value: str = Field(..., description="Standardized normalized value")
    source_file: Optional[str] = Field(None, description="Path to raw evidence artifact on disk")
    observation_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of observation"
    )
    sha256: Optional[str] = Field(None, description="Cryptographic SHA256 checksum of raw source file")
    context: Dict[str, Any] = Field(default_factory=dict, description="Contextual metadata (e.g. TTL, record type, port)")


class UnifiedAssetProfile(BaseModel):
    asset_id: str = Field(..., description="Asset identifier this profile summarizes")
    asset_type: str = Field(..., description="Entity type of the primary asset")
    canonical_identity: str = Field(..., description="Canonical value of the asset")
    display_name: str = Field(..., description="Human-readable display name")
    environment: Literal["lab", "external", "local", "unknown"] = Field("unknown", description="Environment classification")
    related_domains: List[str] = Field(default_factory=list, description="Verified associated domain names")
    related_hostnames: List[str] = Field(default_factory=list, description="Verified reverse or forward hostnames")
    related_ips: List[str] = Field(default_factory=list, description="Verified resolving IP addresses")
    dns_records: List[Dict[str, Any]] = Field(default_factory=list, description="Associated DNS resource records")
    whois_information: Optional[Dict[str, Any]] = Field(None, description="WHOIS registration summary if available")
    discovered_subdomains: List[str] = Field(default_factory=list, description="Discovered subdomains")
    associated_email_evidence: List[str] = Field(default_factory=list, description="Associated contact or OSINT emails")
    open_ports: List[Dict[str, Any]] = Field(default_factory=list, description="Observed open network ports")
    detected_services: List[Dict[str, Any]] = Field(default_factory=list, description="Identified network services and banners")
    detected_versions: List[str] = Field(default_factory=list, description="Identified software product and version strings")
    cpe_identifiers: List[str] = Field(default_factory=list, description="Discovered Common Platform Enumeration strings")
    evidence_references: List[str] = Field(default_factory=list, description="List of evidence IDs backing this profile")
    correlation_confidence: str = Field("DIRECT", description="Overall profile confidence assessment")
    unresolved_relationships: List[str] = Field(default_factory=list, description="Unresolved or ambiguous associations")
    notes: List[str] = Field(default_factory=list, description="Investigator and correlation notes")


class CorrelationResult(BaseModel):
    correlation_id: str = Field(..., description="Unique deterministic correlation session identifier")
    investigation_id: Optional[str] = Field(None, description="Optional overarching investigation identifier")
    source_scan_ids: List[str] = Field(default_factory=list, description="All passive and active scan IDs synthesized")
    overall_status: Literal["SUCCESS", "PARTIAL", "FAILED"] = Field(..., description="Overall correlation execution status")
    start_time_utc: str = Field(..., description="Execution start timestamp in ISO 8601 UTC")
    end_time_utc: str = Field(..., description="Execution completion timestamp in ISO 8601 UTC")
    assets: List[Asset] = Field(default_factory=list, description="Inventory of deduplicated resolved assets")
    relationships: List[AssetRelationship] = Field(default_factory=list, description="Evidence-backed relationships")
    evidence: List[EvidenceReference] = Field(default_factory=list, description="Complete evidence registry")
    profiles: List[UnifiedAssetProfile] = Field(default_factory=list, description="Consolidated asset profiles")
    graph: Dict[str, Any] = Field(default_factory=dict, description="Graph representation with nodes and edges")
    confidence_summary: Dict[str, Any] = Field(default_factory=dict, description="Summary statistics of confidence scores")
    unresolved_relationships: List[str] = Field(default_factory=list, description="Identified ambiguities or disconnected nodes")
    warnings: List[str] = Field(default_factory=list, description="Non-fatal warnings encountered during correlation")
    errors: List[str] = Field(default_factory=list, description="Fatal or semi-fatal processing errors")
    processing_metadata: Dict[str, Any] = Field(default_factory=dict, description="Execution parameters and metrics")
    json_report_path: Optional[str] = Field(None, description="Path to generated JSON report file")
    pdf_report_path: Optional[str] = Field(None, description="Path to generated PDF report file")


# =============================================================================
# W5 VULNERABILITY ASSESSMENT MODELS (Greenbone / OpenVAS Integration)
# =============================================================================

class VulnerabilityFinding(BaseModel):
    finding_id: str = Field(..., description="Unique vulnerability finding identifier")
    nvt_oid: str = Field(..., description="Network Vulnerability Test OID identifier")
    name: str = Field(..., description="Vulnerability title / test name")
    host: str = Field(..., description="Affected host IP address")
    port: int = Field(0, ge=0, le=65535, description="Affected port (0 indicates host-level)")
    protocol: str = Field("tcp", description="Protocol (tcp, udp, or general)")
    threat: Literal["Critical", "High", "Medium", "Low", "Log", "Unknown"] = Field(
        ..., description="Standardized severity level"
    )
    severity: float = Field(..., ge=0.0, le=10.0, description="Greenbone CVSS severity score (0.0 - 10.0)")
    cvss_version: Optional[str] = Field(None, description="CVSS version (e.g. 2.0, 3.0, 3.1)")
    cvss_base: Optional[float] = Field(None, description="Raw CVSS base score")
    cve_ids: List[str] = Field(default_factory=list, description="Associated CVE identifiers (CVE-YYYY-XXXXX)")
    qod: Optional[int] = Field(None, ge=0, le=100, description="Quality of Detection score (0 - 100)")
    qod_type: Optional[str] = Field(None, description="Quality of Detection classification type")
    solution: Optional[str] = Field(None, description="Remediation or mitigation solution")
    solution_type: Optional[str] = Field(None, description="Solution category (e.g. VendorFix, Workaround, Mitigation)")
    description: Optional[str] = Field(None, description="Detailed vulnerability description")
    summary: Optional[str] = Field(None, description="Concise vulnerability summary")
    insight: Optional[str] = Field(None, description="Specific technical result information or proof")
    references: List[str] = Field(default_factory=list, description="External advisory and reference URLs")
    timestamp_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of observation"
    )
    source_tool: str = Field("greenbone_openvas", description="Originating vulnerability scanner")
    original_threat: Optional[str] = Field(None, description="Original threat classification from Greenbone XML")
    calculated_severity: Optional[str] = Field(None, description="Calculated threat tier from CVSS score")
    execution_mode: Literal["LIVE_SCAN", "OFFLINE_IMPORTED_REPORT"] = Field("LIVE_SCAN", description="Execution mode: LIVE_SCAN or OFFLINE_IMPORTED_REPORT")
    evidence_id: Optional[str] = Field(None, description="Associated EvidenceReference identifier")
    correlated_service: Optional[str] = Field(None, description="Correlated Nmap network service name")
    correlated_port: Optional[int] = Field(None, description="Correlated Nmap discovered port")
    correlated_cpe: Optional[str] = Field(None, description="Correlated Common Platform Enumeration")


class GreenboneScanMetadata(BaseModel):
    task_id: Optional[str] = Field(None, description="GVM scan task UUID")
    target_id: Optional[str] = Field(None, description="GVM target UUID")
    report_id: Optional[str] = Field(None, description="GVM report UUID")
    config_name: str = Field("Full and fast", description="GVM scan configuration name")
    config_id: Optional[str] = Field(None, description="GVM scan configuration UUID")
    scanner_name: str = Field("OpenVAS", description="Scanner daemon identifier")
    scanner_version: Optional[str] = Field(None, description="Installed OpenVAS scanner version")
    feed_version: Optional[str] = Field(None, description="Vulnerability test feed timestamp or version")
    start_time_utc: str = Field(..., description="Assessment execution start in ISO 8601 UTC")
    end_time_utc: str = Field(..., description="Assessment execution end in ISO 8601 UTC")
    elapsed_seconds: Optional[float] = Field(None, description="Assessment duration in seconds")
    status: str = Field("Done", description="GVM task completion status")


class VulnerabilityAssessmentResult(BaseModel):
    assessment_id: str = Field(..., description="Unique assessment execution identifier (VULN-YYYYMMDD-HHMMSS-xxxx)")
    target: str = Field(..., description="Assessed target IP address")
    authorization_record: TargetAuthorizationRecord = Field(..., description="Strict target scope authorization record")
    overall_status: Literal["SUCCESS", "PARTIAL", "FAILED", "TIMEOUT", "CANCELLED", "BLOCKED"] = Field(
        ..., description="Assessment pipeline outcome status"
    )
    execution_mode: Literal["LIVE_SCAN", "OFFLINE_IMPORTED_REPORT"] = Field(
        "LIVE_SCAN", description="Execution mode: LIVE_SCAN or OFFLINE_IMPORTED_REPORT"
    )
    start_time_utc: str = Field(..., description="Assessment execution start time in ISO 8601 UTC")
    end_time_utc: str = Field(..., description="Assessment execution completion time in ISO 8601 UTC")
    metadata: Optional[GreenboneScanMetadata] = Field(None, description="Greenbone scan metadata")
    findings: List[VulnerabilityFinding] = Field(default_factory=list, description="Parsed, normalized vulnerability findings")
    severity_summary: Dict[str, int] = Field(default_factory=dict, description="Counts by threat level (Critical, High, Medium, Low, Log)")
    correlated_nmap_services: List[Dict[str, Any]] = Field(default_factory=list, description="Cross-correlated W3 Nmap service exposures")
    raw_files: Dict[str, str] = Field(default_factory=dict, description="Paths to preserved raw Greenbone artifacts")
    file_hashes: Dict[str, str] = Field(default_factory=dict, description="SHA256 checksums of raw evidence artifacts")
    defensive_observations: List[str] = Field(default_factory=list, description="Defensive observations from findings")
    recommended_actions: List[str] = Field(default_factory=list, description="Prioritized defensive remediation actions")
    json_report_path: Optional[str] = Field(None, description="Path to generated JSON vulnerability report")
    pdf_report_path: Optional[str] = Field(None, description="Path to generated PDF vulnerability report")
    warnings: List[str] = Field(default_factory=list, description="Non-fatal warnings encountered during assessment")
    errors: List[str] = Field(default_factory=list, description="Fatal or diagnostic errors encountered")


