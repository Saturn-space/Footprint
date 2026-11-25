"""
OSINT-RECON Active Reconnaissance Pipeline Module
Orchestrates target authorization, connectivity verification, safe Nmap execution,
XML parsing, schema compliance, evidence hashing, and dual JSON/PDF reporting.
"""

import os
import re
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple

import jsonschema

from src.schema import (
    TargetInfo,
    ToolInfo,
    ServiceInfo,
    ReconRecord,
    TargetAuthorizationRecord,
    NmapHost,
    NmapScanMetadata,
    ActiveReconResult
)
from src.authorization.target_authorizer import (
    TargetAuthorizer,
    TargetAuthorizationError,
    TargetSyntaxError
)
from src.collectors.nmap_collector import NmapCollector, NmapCollectorResult, compute_file_sha256
from src.parsers.nmap_xml_parser import NmapXMLParser, NmapXMLParseError
from src.reporting.pdf_generator import PDFReportGenerator

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_SCHEMA_PATH = os.path.join(PROJECT_ROOT, "config", "recon_schema.json")


def generate_scan_id() -> str:
    """Generates a timestamped, unique scan ID (e.g. SCAN-20261109-110022-a1b2)."""
    now = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rand_hex = uuid.uuid4().hex[:4]
    return f"SCAN-{now}-{rand_hex}"


class ActiveReconPipeline:
    """
    End-to-end active network reconnaissance pipeline.
    Maintains strict scope authorization, error containment, and evidence preservation.
    """

    def __init__(
        self,
        base_dir: Optional[str] = None,
        config_path: Optional[str] = None,
        schema_path: Optional[str] = None,
        timeout: int = 60,
        enable_pdf: bool = True
    ):
        self.base_dir = base_dir or PROJECT_ROOT
        self.timeout = timeout
        self.enable_pdf = enable_pdf
        self.schema_path = schema_path or DEFAULT_SCHEMA_PATH

        # Directories
        self.raw_dir = os.path.join(self.base_dir, "data", "raw_outputs")
        self.processed_dir = os.path.join(self.base_dir, "data", "processed")
        self.reports_dir = os.path.join(self.base_dir, "reports")

        os.makedirs(self.raw_dir, exist_ok=True)
        os.makedirs(self.processed_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)

        # Core modules
        self.authorizer = TargetAuthorizer(config_path=config_path)
        self.collector = NmapCollector(timeout=self.timeout)
        self.parser = NmapXMLParser()
        self.pdf_generator = PDFReportGenerator(output_dir=self.reports_dir)

        self.json_schema = self._load_schema()

    def _load_schema(self) -> Optional[Dict[str, Any]]:
        """Loads Draft 2020-12 JSON schema for ReconRecord validation."""
        if os.path.exists(self.schema_path):
            try:
                with open(self.schema_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    def _generate_defensive_insights(
        self, target: str, hosts: List[NmapHost]
    ) -> Tuple[List[str], List[str]]:
        """
        Derives defensive security observations and actionable recommendations.
        Strict compliance: Never labels open ports as vulnerabilities or invents risk scores.
        """
        observations: List[str] = []
        actions: List[str] = []

        all_open_ports = []
        services = []
        for h in hosts:
            for p in h.ports:
                if p.state == "open":
                    all_open_ports.append(p)
                    if p.service and p.service.name:
                        services.append(p.service.name.lower())

        if not all_open_ports:
            observations.append(f"Network Perimeter: No open TCP ports observed on target {target}.")
            actions.append("Maintain baseline firewall filtering policies.")
            return observations, actions

        observations.append(
            f"Exposure Surface: Observed {len(all_open_ports)} open TCP port(s) on target {target}. "
            "Open ports reflect available network listener exposure and do not constitute confirmed vulnerabilities."
        )

        # Check for unencrypted or legacy management protocols
        plaintext_services = {
            "telnet": (23, "Telnet transmits all credentials and session data in cleartext."),
            "rlogin": (513, "Legacy BSD r-command transmits unencrypted authentication data."),
            "rsh": (514, "Remote shell service lacks encryption and secure session validation."),
            "ftp": (21, "Plaintext FTP transmits credentials without TLS encryption by default.")
        }

        detected_cleartext = []
        for s_name, (port_num, notice) in plaintext_services.items():
            if any(p.portid == port_num or (p.service and p.service.name.lower() == s_name) for p in all_open_ports):
                detected_cleartext.append((s_name, port_num, notice))

        if detected_cleartext:
            names = ", ".join(f"{s.upper()} ({p})" for s, p, _ in detected_cleartext)
            observations.append(f"Plaintext Services Detected: Legacy unencrypted service(s) running: {names}.")
            actions.append(
                "Disable legacy unencrypted protocols (Telnet, Rlogin, plain FTP) and replace with encrypted alternatives (SSH, SFTP/FTPS)."
            )

        # Check for database exposure
        db_services = {
            3306: "MySQL Database",
            5432: "PostgreSQL Database",
            1521: "Oracle TNS",
            1433: "Microsoft SQL Server"
        }
        detected_dbs = [db_services[p.portid] for p in all_open_ports if p.portid in db_services]
        if detected_dbs:
            observations.append(f"Database Listener Exposure: Database service(s) exposed: {', '.join(detected_dbs)}.")
            actions.append("Restrict database listeners to localhost or internal private application tiers using host-based firewalls.")

        # Check for SMB / NetBIOS exposure
        if any(p.portid in (139, 445) for p in all_open_ports):
            observations.append("File Sharing Exposure: SMB / NetBIOS services observed on ports 139/445.")
            actions.append("Isolate SMB file sharing services and verify that guest access and SMBv1 are strictly disabled.")

        # Generic action
        actions.append("Conduct regular external port auditing to minimize exposed attack surfaces and eliminate unnecessary network daemons.")

        return observations, actions

    def run(
        self,
        target: Optional[str] = None,
        profile: str = "lab-basic",
        operator: str = "asip_ali",
        scan_id: Optional[str] = None,
        skip_connectivity_check: bool = False,
        custom_active_options: Optional[Dict[str, Any]] = None,
        repo: Optional[Any] = None,
        investigation_id: Optional[str] = None,
        allow_privileged: bool = False
    ) -> ActiveReconResult:
        """
        Executes complete active reconnaissance workflow:
        1. Scope & Target Authorization
        2. Connectivity Verification (with reachability error isolation)
        3. Nmap Execution & Raw Evidence Persistence
        4. XML Parsing & Schema Validation
        5. Dual JSON/PDF Reporting
        """
        start_time = datetime.now(timezone.utc).isoformat()
        sid = scan_id or generate_scan_id()
        errors: List[str] = []

        # 1. Target Authorization
        try:
            auth_record = self.authorizer.authorize_target(
                target=target,
                profile=profile,
                operator=operator,
                investigation_id=investigation_id,
                repo=repo
            )
        except (TargetAuthorizationError, TargetSyntaxError) as ae:
            end_time = datetime.now(timezone.utc).isoformat()
            return ActiveReconResult(
                scan_id=sid,
                target=str(target or "UNKNOWN"),
                authorization_record=TargetAuthorizationRecord(
                    target=str(target or "UNKNOWN"),
                    authorized=False,
                    authorization_status="REJECTED_UNAUTHORIZED",
                    category="unauthorized_target",
                    scope="None",
                    scan_profile=profile,
                    operator=operator,
                    notes=str(ae)
                ),
                scan_profile=profile,
                start_time_utc=start_time,
                end_time_utc=end_time,
                overall_status="FAILED",
                errors=[str(ae)]
            )

        clean_target = auth_record.target

        # 2. Target Reachability Check (skip if CIDR/range or explicitly bypassed)
        is_range_target = "/" in clean_target or (
            "-" in clean_target and any(ch.isdigit() for ch in clean_target.split("-")[-1])
        )
        if not skip_connectivity_check and not is_range_target:
            is_up, reach_msg = self.authorizer.verify_target_connectivity(clean_target)
            if not is_up:
                end_time = datetime.now(timezone.utc).isoformat()
                blocked_msg = (
                    f"Target '{clean_target}' is UNREACHABLE or OFFLINE. "
                    "Active reconnaissance halted before scanning to prevent inaccurate or stalled results.\n"
                    "Action Required: Please verify that the target host is online and reachable."
                )
                return ActiveReconResult(
                    scan_id=sid,
                    target=clean_target,
                    authorization_record=auth_record,
                    scan_profile=profile,
                    start_time_utc=start_time,
                    end_time_utc=end_time,
                    overall_status="BLOCKED",
                    errors=[blocked_msg]
                )

        # 3. Create Scan Directory Hierarchy
        scan_evidence_dir = os.path.join(self.raw_dir, sid, "nmap")
        os.makedirs(scan_evidence_dir, exist_ok=True)

        # 4. Execute Nmap (custom manual options or named safe profile)
        if custom_active_options:
            collector_res = self.collector.execute_custom_scan(
                auth_record=auth_record,
                options=custom_active_options,
                output_dir=scan_evidence_dir,
                timeout=self.timeout,
                allow_privileged=allow_privileged
            )
        else:
            collector_res = self.collector.execute_scan(
                auth_record=auth_record,
                profile_name=profile,
                output_dir=scan_evidence_dir,
                timeout=self.timeout
            )

        if collector_res.error_message:
            errors.append(collector_res.error_message)

        # 5. Parse Nmap XML Output
        hosts: List[NmapHost] = []
        scan_metadata: Optional[NmapScanMetadata] = None

        if collector_res.xml_path and os.path.exists(collector_res.xml_path):
            try:
                hosts, scan_metadata = self.parser.parse_xml_file(
                    collector_res.xml_path, profile_name=profile
                )
            except NmapXMLParseError as pe:
                errors.append(f"XML Parsing Error: {pe}")
        else:
            errors.append("Nmap XML output file was not produced by scanner.")

        # 6. Map to Unified W1/W2 ReconRecord
        open_ports_list = []
        service_info_list = []
        for h in hosts:
            for p in h.ports:
                if p.state == "open":
                    open_ports_list.append(p.portid)
                    if p.service:
                        service_info_list.append(ServiceInfo(
                            port=p.portid,
                            protocol=p.protocol,
                            state=p.state,
                            service_name=p.service.name,
                            product=p.service.product,
                            version=p.service.version
                        ))

        recon_record = ReconRecord(
            target_info=TargetInfo(
                target=clean_target,
                category=auth_record.category,  # type: ignore
                authorization_status=auth_record.authorization_status,
                scope=auth_record.scope
            ),
            tool_info=ToolInfo(
                name="nmap",
                version=scan_metadata.version if scan_metadata else self.collector.version,
                execution_args=collector_res.command_str
            ),
            recon_category="port_scan",
            scan_id=sid,
            discovered_domains=[],
            ip_addresses=[clean_target],
            dns_records=[],
            email_addresses=[],
            open_ports=open_ports_list,
            service_information=service_info_list,
            evidence_source=collector_res.xml_path or "nmap active scan",
            scan_status="SUCCESS" if collector_res.returncode == 0 else "PARTIAL",
            errors_and_warnings=errors,
            raw_output_reference=collector_res.xml_path
        )

        # Validate against JSON Schema
        if self.json_schema:
            try:
                rec_dict = json.loads(recon_record.model_dump_json())
                jsonschema.validate(instance=rec_dict, schema=self.json_schema)
            except jsonschema.ValidationError as ve:
                errors.append(f"JSON Schema validation warning on ReconRecord: {ve.message}")

        # 7. Summary & Defensive Insights
        total_open = len(open_ports_list)
        total_closed = sum(h.closed_ports_count for h in hosts)
        total_filtered = sum(h.filtered_ports_count for h in hosts)

        summary = {
            "target": clean_target,
            "host_status": hosts[0].status if hosts else "unknown",
            "open_ports_count": total_open,
            "closed_ports_count": total_closed,
            "filtered_ports_count": total_filtered,
            "services_detected_count": len(service_info_list),
            "scan_duration_seconds": collector_res.duration_seconds
        }

        observations, recommendations = self._generate_defensive_insights(clean_target, hosts)

        # 8. Overall Pipeline Status
        if collector_res.returncode == 0 and not errors:
            overall_status = "SUCCESS"
        elif collector_res.returncode == 0 or hosts:
            overall_status = "PARTIAL"
        else:
            overall_status = "FAILED"

        end_time = datetime.now(timezone.utc).isoformat()

        raw_files_dict = {}
        if collector_res.xml_path and os.path.exists(collector_res.xml_path):
            raw_files_dict["xml"] = os.path.abspath(collector_res.xml_path)
        if collector_res.stdout_path and os.path.exists(collector_res.stdout_path):
            raw_files_dict["stdout"] = os.path.abspath(collector_res.stdout_path)
        if collector_res.stderr_path and os.path.exists(collector_res.stderr_path):
            raw_files_dict["stderr"] = os.path.abspath(collector_res.stderr_path)

        result = ActiveReconResult(
            scan_id=sid,
            target=clean_target,
            authorization_record=auth_record,
            scan_profile=profile,
            start_time_utc=start_time,
            end_time_utc=end_time,
            overall_status=overall_status,
            hosts=hosts,
            scan_metadata=scan_metadata,
            recon_record=recon_record,
            raw_files=raw_files_dict,
            file_hashes=collector_res.file_hashes,
            summary=summary,
            defensive_observations=observations,
            recommended_actions=recommendations,
            errors=errors
        )

        # Save metadata JSON file in evidence directory
        if collector_res.metadata_path:
            try:
                with open(collector_res.metadata_path, "w", encoding="utf-8") as mf:
                    mf.write(result.model_dump_json(indent=2))
                raw_files_dict["metadata"] = os.path.abspath(collector_res.metadata_path)
                result.file_hashes["metadata"] = compute_file_sha256(collector_res.metadata_path)
            except IOError:
                pass

        # 9. PDF Intelligence Report Generation
        if self.enable_pdf and overall_status in ("SUCCESS", "PARTIAL"):
            try:
                pdf_path = self.pdf_generator.generate_active_report(result)
                result.pdf_report_path = pdf_path
            except Exception as pe:
                result.errors.append(f"PDF generation error: {str(pe)}")

        # 10. Save Machine-Readable JSON Report
        json_filename = f"{sid}_report.json"
        json_path = os.path.join(self.processed_dir, json_filename)
        result.json_report_path = os.path.abspath(json_path)
        try:
            with open(json_path, "w", encoding="utf-8") as jf:
                jf.write(result.model_dump_json(indent=2))
        except IOError as ioe:
            result.errors.append(f"Failed to write JSON report: {ioe}")

        return result
