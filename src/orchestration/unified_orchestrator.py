"""
FootprintIQ - Unified Scan Orchestration Layer
Orchestrates multi-scanner and reconnaissance workflows across:
1. Passive OSINT Reconnaissance (WHOIS, RDAP, DNS, theHarvester)
2. Network Discovery (Host reachability, Ping sweep)
3. Nmap Service Discovery (Service versions, OS detection)
4. Nmap NSE Assessment (Policy-controlled vulnerability scripts)
5. ProjectDiscovery Nuclei Assessment (Safe template-based CVE/Web/SSL scanning)
6. Tenable Nessus Assessment (Read-only inspection / licensed API scan)
7. Combined Multi-Engine Assessment (Cross-scanner correlation & unified exposure scoring)
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from src.authorization.target_authorizer import TargetAuthorizer
from src.collectors.nse_collector import NSECollector
from src.collectors.nessus_collector import NessusCollector
from src.collectors.nuclei_collector import NucleiCollector
from src.collectors.rdap_collector import RDAPCollector
from src.collectors.passive_intel_collector import PassiveIntelCollector
from src.orchestration.passive_pipeline import PassiveReconPipeline
from src.orchestration.active_pipeline import ActiveReconPipeline
from src.processors.vulnerability_correlator import VulnerabilityCorrelator
from src.services.exposure_scoring import ExposureScoringEngine
from src.storage.seaweedfs_client import SeaweedFSClient
from src.db.repository import FootprintIQRepository

logger = logging.getLogger("FootprintIQ.UnifiedOrchestrator")


class UnifiedScanOrchestrator:
    def __init__(
        self,
        repo: Optional[FootprintIQRepository] = None,
        authorizer: Optional[TargetAuthorizer] = None,
        storage_client: Optional[SeaweedFSClient] = None
    ):
        self.repo = repo or FootprintIQRepository()
        self.authorizer = authorizer or TargetAuthorizer()
        self.storage = storage_client or SeaweedFSClient()
        self.nse_collector = NSECollector(authorizer=self.authorizer, storage_client=self.storage)
        self.nuclei_collector = NucleiCollector(storage=self.storage, authorizer=self.authorizer)
        self.nessus_collector = NessusCollector()
        self.rdap_collector = RDAPCollector()
        self.passive_collector = PassiveIntelCollector()

    def execute_scan(
        self,
        investigation_id: str,
        scan_type: str,
        target: str,
        profile: str = "default",
        custom_scripts: Optional[List[str]] = None,
        nuclei_profile: Optional[str] = None,
        nuclei_tags: Optional[List[str]] = None,
        nuclei_severities: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Unified dispatch entry point for all supported FootprintIQ scan workflows.
        """
        # Create execution record
        scan_rec = self.repo.create_scan_execution(
            investigation_id=investigation_id,
            scan_type=scan_type,
            target=target,
            profile=profile
        )
        scan_id = scan_rec["scan_id"]

        try:
            if scan_type == "passive":
                result = self._run_passive_recon(target, investigation_id, scan_id)
            elif scan_type == "network_discovery":
                result = self._run_network_discovery(target, investigation_id, scan_id)
            elif scan_type == "nmap_services":
                result = self._run_nmap_services(target, profile, investigation_id, scan_id)
            elif scan_type == "nmap_nse":
                result = self._run_nmap_nse(target, custom_scripts, investigation_id, scan_id)
            elif scan_type == "nuclei":
                result = self._run_nuclei(
                    target,
                    investigation_id,
                    scan_id,
                    profile=nuclei_profile or "http-security",
                    tags=nuclei_tags,
                    severities=nuclei_severities,
                )
            elif scan_type == "nessus":
                result = self._run_nessus(target, investigation_id, scan_id)
            elif scan_type == "combined":
                result = self._run_combined_assessment(
                    target,
                    profile,
                    custom_scripts,
                    investigation_id,
                    scan_id,
                    nuclei_profile=nuclei_profile or "safe-all",
                )
            elif scan_type == "greenbone":
                raise ValueError(
                    "Active Greenbone/OpenVAS execution has been removed from FootprintIQ. Use 'nuclei' or 'nmap_nse' instead."
                )
            else:
                raise ValueError(f"Unknown scan type: {scan_type}")

            # Mark final status accurately in DB
            exec_status = "failed" if result.get("status") == "FAILED" else "completed"
            self.repo.update_scan_execution(
                scan_id=scan_id,
                status=exec_status,
                error_message=result.get("error") if exec_status == "failed" else None,
                result_summary_json=json.dumps({
                    "target": target,
                    "status": result.get("status"),
                    "findings_count": len(result.get("findings", [])),
                    "vulnerabilities": result.get("vulnerabilities_found", 0)
                })
            )
            result["scan_id"] = scan_id
            result["investigation_id"] = investigation_id
            return result

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            self.repo.update_scan_execution(
                scan_id=scan_id,
                status="failed",
                error_message=str(e)
            )
            return {
                "scan_id": scan_id,
                "investigation_id": investigation_id,
                "target": target,
                "status": "FAILED",
                "error": str(e)
            }

    # ==========================================
    # SCAN IMPLEMENTATIONS
    # ==========================================

    def _run_passive_recon(self, target: str, investigation_id: str, scan_id: str) -> Dict[str, Any]:
        """Runs WHOIS, DNS, theHarvester and RDAP."""
        summary = {}
        try:
            pipeline = PassiveReconPipeline()
            summary_obj = pipeline.run(target_domain=target)
            summary_obj = getattr(res, "summary", None)
            if hasattr(summary_obj, "model_dump"):
                summary = summary_obj.model_dump()
            elif hasattr(summary_obj, "to_dict"):
                summary = summary_obj.to_dict()
            elif isinstance(summary_obj, dict):
                summary = summary_obj
            else:
                summary = {}
        except Exception as e:
            logger.info(f"Passive pipeline run note for {target}: {e}")

        # Complement with RDAP
        rdap_res = self.rdap_collector.lookup_domain(target) if "." in target and not target.replace(".", "").isdigit() else self.rdap_collector.lookup_ip(target)

        # Upload JSON report to SeaweedFS
        report_path = summary.get("json_report_path")
        ev_meta = {}
        if report_path and os.path.exists(report_path):
            with open(report_path, "rb") as f:
                content = f.read()
            ev_meta = self.storage.upload_content(
                content=content,
                file_name=f"passive_report_{target}.json",
                investigation_id=investigation_id,
                evidence_type="passive_json",
                content_type="application/json"
            )
            self.repo.add_evidence_record(
                investigation_id=investigation_id,
                evidence_type="passive_json",
                file_name=ev_meta["file_name"],
                file_size=ev_meta["file_size"],
                sha256_hash=ev_meta["sha256_hash"],
                seaweed_fid=ev_meta.get("seaweed_fid"),
                seaweed_url=ev_meta.get("seaweed_url"),
                local_path=ev_meta["local_path"],
                scanner_source="Passive Intelligence",
                target=target,
                content_type="application/json",
            )

        return {
            "status": "COMPLETED",
            "scan_type": "passive",
            "target": target,
            "passive_summary": summary,
            "rdap": rdap_res,
            "evidence": ev_meta,
            "findings": []
        }

    def _run_network_discovery(self, target: str, investigation_id: str, scan_id: str) -> Dict[str, Any]:
        """Runs lightweight host and port ping discovery."""
        auth = self.authorizer.authorize_target(target, profile="lab-safe-minimal")
        if not auth.authorized:
            raise PermissionError(f"Target '{target}' is not authorized: {auth.failure_reason}")

        pipeline = ActiveReconPipeline()
        result = pipeline.run(target=target, profile="lab-safe-minimal")
        return {
            "status": "COMPLETED",
            "scan_type": "network_discovery",
            "target": target,
            "hosts_discovered": 1 if result else 0,
            "active_result": result.model_dump() if hasattr(result, "model_dump") else str(result),
            "findings": []
        }

    def _run_passive_intel(
        self,
        target: str,
        selected_checks: List[str],
        allow_target_contact: bool,
        investigation_id: str,
        scan_id: str,
        progress_cb=None
    ) -> Dict[str, Any]:
        """Executes modular passive OSINT & infrastructure intelligence checks."""
        intel_res = self.passive_collector.run_selected_checks(
            target=target,
            selected_checks=selected_checks,
            allow_target_contact=allow_target_contact,
            progress_cb=progress_cb
        )
        try:
            payload = json.dumps(intel_res, indent=2).encode("utf-8")
            ev_meta = self.storage.upload_content(
                content=payload,
                file_name=f"passive_intel_{target.replace('/', '_')}_{scan_id}.json",
                investigation_id=investigation_id,
                evidence_type="passive_intel_json",
                content_type="application/json"
            )
            self.repo.add_evidence_record(
                investigation_id=investigation_id,
                evidence_type="passive_intel_json",
                file_name=ev_meta["file_name"],
                file_size=ev_meta["file_size"],
                sha256_hash=ev_meta["sha256_hash"],
                seaweed_fid=ev_meta.get("seaweed_fid"),
                seaweed_url=ev_meta.get("seaweed_url"),
                local_path=ev_meta.get("local_path"),
                scan_id=scan_id,
                scanner_source="Passive Intelligence",
                target=target,
                content_type="application/json",
            )
        except Exception as e:
            logger.warning(f"Failed to archive passive intel evidence: {e}")

        return intel_res

    def _run_nmap_services(
        self,
        target: str,
        profile: str,
        investigation_id: str,
        scan_id: str,
        custom_active_options: Optional[Dict[str, Any]] = None,
        use_db_scope: bool = False,
        allow_privileged: bool = False
    ) -> Dict[str, Any]:
        """Runs Nmap host/port/service detection and extracts discovered hosts & open ports cleanly."""
        prof = profile if profile in ("lab-basic", "lab-safe-minimal", "lab-common-services") else "lab-basic"
        pipeline = ActiveReconPipeline()
        result = pipeline.run(
            target=target,
            profile=prof,
            scan_id=scan_id,
            custom_active_options=custom_active_options,
            repo=self.repo if use_db_scope else None,
            investigation_id=investigation_id if use_db_scope else None,
            allow_privileged=allow_privileged
        )

        # Save active Nmap XML evidence
        xml_path = (result.raw_files or {}).get("xml") if hasattr(result, "raw_files") else None
        ev_meta = {}
        if xml_path and os.path.exists(xml_path):
            with open(xml_path, "rb") as f:
                content = f.read()
            ev_meta = self.storage.upload_content(
                content=content,
                file_name=f"nmap_{target.replace('/', '_')}_{scan_id}.xml",
                investigation_id=investigation_id,
                evidence_type="nmap_xml",
                content_type="application/xml"
            )
            self.repo.add_evidence_record(
                investigation_id=investigation_id,
                evidence_type="nmap_xml",
                file_name=ev_meta["file_name"],
                file_size=ev_meta["file_size"],
                sha256_hash=ev_meta["sha256_hash"],
                seaweed_fid=ev_meta.get("seaweed_fid"),
                seaweed_url=ev_meta.get("seaweed_url"),
                local_path=ev_meta.get("local_path"),
                scan_id=scan_id,
                scanner_source="Nmap Active Discovery",
                target=target,
                content_type="application/xml",
            )

        extracted_hosts: List[Dict[str, Any]] = []
        extracted_ports: List[Dict[str, Any]] = []
        for h in getattr(result, "hosts", []) or []:
            host_ip = getattr(h, "ip", None) or getattr(h, "address", None) or target
            os_guesses = []
            for om in getattr(h, "os_matches", []) or []:
                os_guesses.append(getattr(om, "name", str(om)))
            extracted_hosts.append({
                "ip": host_ip,
                "hostname": getattr(h, "hostname", None),
                "status": getattr(h, "status", "unknown"),
                "os_matches": os_guesses[:3],
                "open_ports_count": sum(1 for p in getattr(h, "ports", []) if getattr(p, "state", "") == "open")
            })
            for p in getattr(h, "ports", []) or []:
                if getattr(p, "state", "") == "open":
                    svc = getattr(p, "service", None)
                    svc_name = getattr(svc, "name", "unknown") if svc else "unknown"
                    product = getattr(svc, "product", "") if svc else ""
                    version = getattr(svc, "version", "") if svc else ""
                    svc_ver = " ".join([x for x in (product, version) if x]).strip()
                    extracted_ports.append({
                        "target_ip": host_ip,
                        "port": getattr(p, "portid", 0),
                        "protocol": getattr(p, "protocol", "tcp"),
                        "state": getattr(p, "state", "open"),
                        "service": svc_name,
                        "service_version": svc_ver,
                        "extrainfo": getattr(svc, "extrainfo", "") if svc else ""
                    })

        return {
            "status": getattr(result, "overall_status", "COMPLETED"),
            "scan_type": "nmap_services",
            "target": target,
            "hosts": extracted_hosts,
            "ports": extracted_ports,
            "summary": getattr(result, "summary", {}),
            "errors": getattr(result, "errors", []),
            "active_recon": result.model_dump() if hasattr(result, "model_dump") else {},
            "evidence": ev_meta,
            "findings": []
        }

    def _run_nmap_nse(self, target: str, scripts: Optional[List[str]], investigation_id: str, scan_id: str) -> Dict[str, Any]:
        """Runs policy-controlled Nmap NSE checks and registers XML evidence idempotently."""
        nse_res = self.nse_collector.scan_target(
            target=target,
            scripts=scripts,
            investigation_id=investigation_id,
            scan_id=scan_id,
            allow_vuln_checks=True
        )
        findings = nse_res.get("findings", [])
        for f in findings:
            self.repo.add_vulnerability_finding(investigation_id, f, scan_id=scan_id)

        ev = nse_res.get("evidence")
        if isinstance(ev, dict) and ev.get("file_name") and ev.get("sha256_hash"):
            try:
                self.repo.add_evidence_record(
                    investigation_id=investigation_id,
                    evidence_type="nse_xml",
                    file_name=ev["file_name"],
                    file_size=ev["file_size"],
                    sha256_hash=ev["sha256_hash"],
                    seaweed_fid=ev.get("seaweed_fid"),
                    seaweed_url=ev.get("seaweed_url"),
                    local_path=ev.get("local_path"),
                    scan_id=scan_id,
                    scanner_source="Nmap NSE",
                    target=target,
                    content_type="application/xml",
                )
            except Exception as ev_err:
                logger.warning(f"SeaweedFS DB record notice for NSE XML: {ev_err}")

        return nse_res

    def _run_nuclei(
        self,
        target: str,
        investigation_id: str,
        scan_id: str,
        profile: str = "http-security",
        severities: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        template_ids: Optional[List[str]] = None,
        discovered_ports: Optional[List[Dict[str, Any]]] = None,
        cancel_event=None,
        rate_limit: int = 30,
    ) -> Dict[str, Any]:
        """Runs policy-governed ProjectDiscovery Nuclei vulnerability scan and archives evidence."""
        nuc_res = self.nuclei_collector.run_scan(
            target=target,
            investigation_id=investigation_id,
            scan_id=scan_id,
            profile=profile,
            severities=severities,
            tags=tags,
            template_ids=template_ids,
            discovered_ports=discovered_ports,
            cancel_event=cancel_event,
            repo=self.repo,
            rate_limit=rate_limit,
        )
        findings = nuc_res.get("findings") or []
        for f in findings:
            self.repo.add_vulnerability_finding(investigation_id, f, scan_id=scan_id)

        ev = nuc_res.get("evidence")
        if isinstance(ev, dict) and ev.get("file_name"):
            try:
                self.repo.add_evidence_record(
                    investigation_id=investigation_id,
                    evidence_type="nuclei_jsonl",
                    file_name=ev["file_name"],
                    file_size=ev["file_size"],
                    sha256_hash=ev["sha256_hash"],
                    seaweed_fid=ev.get("seaweed_fid"),
                    seaweed_url=ev.get("seaweed_url"),
                    local_path=ev.get("local_path"),
                    scan_id=scan_id,
                    scanner_source="ProjectDiscovery Nuclei",
                    target=target,
                    content_type="application/x-ndjson",
                )
            except Exception as ev_err:
                logger.warning(f"SeaweedFS DB record notice for Nuclei JSONL: {ev_err}")

        return {
            "status": nuc_res.get("status", "COMPLETED"),
            "scan_type": "nuclei",
            "target": target,
            "targets_scanned": nuc_res.get("targets_scanned", []),
            "applied_policy": nuc_res.get("applied_policy", {}),
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "evidence": ev,
            "error": nuc_res.get("error"),
            "errors": nuc_res.get("errors", []),
            "duration_seconds": nuc_res.get("duration_seconds"),
            "timeout_seconds": nuc_res.get("timeout_seconds"),
            "timed_out": nuc_res.get("timed_out", False),
            "returncode": nuc_res.get("returncode"),
            "raw_records_count": nuc_res.get("raw_records_count", len(findings)),
            "skipped_checks": nuc_res.get("skipped_checks", []),
            "execution_meta": nuc_res.get("execution_meta", {}),
        }

    def _run_nessus(self, target: str, investigation_id: str, scan_id: str, template_uuid: Optional[str] = None) -> Dict[str, Any]:
        """Runs live Tenable Nessus assessment when scan_api is permitted; never fakes simulated findings."""
        nessus_res = self.nessus_collector.scan_target(
            target=target,
            investigation_id=investigation_id,
            scan_id=scan_id,
            template_uuid=template_uuid,
            allow_simulation=False,
        )
        findings = nessus_res.get("findings", [])
        for f in findings:
            self.repo.add_vulnerability_finding(investigation_id, f, scan_id=scan_id)

        # Preserve Nessus report export in SeaweedFS if present
        report_bytes = nessus_res.get("report_bytes")
        if report_bytes:
            try:
                ev_meta = self.storage.upload_content(
                    content=report_bytes,
                    file_name=f"nessus_report_{target}_{scan_id}.nessus",
                    investigation_id=investigation_id,
                    evidence_type="nessus_export",
                    content_type="application/xml"
                )
                self.repo.add_evidence_record(
                    investigation_id=investigation_id,
                    evidence_type="nessus_export",
                    file_name=ev_meta["file_name"],
                    file_size=ev_meta["file_size"],
                    sha256_hash=ev_meta["sha256_hash"],
                    seaweed_fid=ev_meta.get("seaweed_fid"),
                    seaweed_url=ev_meta.get("seaweed_url"),
                    local_path=ev_meta.get("local_path"),
                    scan_id=scan_id,
                    scanner_source="Tenable Nessus",
                    target=target,
                    content_type="application/xml",
                )
            except Exception as e:
                logger.warning(f"SeaweedFS upload notice for Nessus export: {e}")

        return nessus_res

    def _run_combined_assessment(
        self,
        target: str,
        profile: str,
        custom_scripts: Optional[List[str]],
        investigation_id: str,
        scan_id: str,
        nuclei_profile: str = "safe-all",
    ) -> Dict[str, Any]:
        """
        Executes a complete combined assessment across:
        1. Nmap Service Detection
        2. Nmap NSE Vulnerability Checks
        3. ProjectDiscovery Nuclei Safe Templates (using discovered HTTP/TLS ports)
        4. Tenable Nessus Assessment (only if connected and scan_api_enabled=True)
        Correlates all findings and calculates exposure score.
        """
        all_findings: List[Dict[str, Any]] = []
        scanners_executed: List[str] = []
        scanners_skipped: List[Dict[str, Any]] = []

        # 1. Nmap Services
        services_res = self._run_nmap_services(target, profile, investigation_id, scan_id)
        scanners_executed.append("nmap_services")
        discovered_ports: List[Dict[str, Any]] = []
        for h in (services_res.get("hosts") or []):
            for p in (h.get("ports") or []):
                if str(p.get("state") or "open").lower() == "open":
                    discovered_ports.append({
                        "target_ip": h.get("ip") or target,
                        "port": p.get("port"),
                        "protocol": p.get("protocol", "tcp"),
                        "service": p.get("service", ""),
                        "service_version": p.get("version") or "",
                    })

        # 2. NSE Vulnerability Checks
        nse_res = self._run_nmap_nse(target, custom_scripts, investigation_id, scan_id)
        all_findings.extend(nse_res.get("findings", []))
        scanners_executed.append("nmap_nse")

        # 3. ProjectDiscovery Nuclei
        nuc_ready = self.nuclei_collector.check_readiness()
        if nuc_ready.get("ready"):
            nuc_res = self._run_nuclei(
                target=target,
                investigation_id=investigation_id,
                scan_id=scan_id,
                profile=nuclei_profile,
                discovered_ports=discovered_ports,
            )
            all_findings.extend(nuc_res.get("findings", []))
            scanners_executed.append("nuclei")
        else:
            scanners_skipped.append({"scanner": "nuclei", "reason": nuc_ready.get("reason") or "Nuclei unavailable"})

        # 4. Tenable Nessus (only when scan_api_enabled=True; honest skip on read-only license)
        nessus_status = "READ_ONLY"
        try:
            n_conn = self.nessus_collector.test_connection()
            if n_conn.get("connected") and n_conn.get("scan_api_enabled", False):
                nessus_res = self._run_nessus(target, investigation_id, scan_id)
                all_findings.extend(nessus_res.get("findings", []))
                scanners_executed.append("nessus")
                nessus_status = "ONLINE"
            elif n_conn.get("connected"):
                nessus_status = "READ_ONLY"
                scanners_skipped.append({
                    "scanner": "nessus",
                    "reason": n_conn.get("limitations") or "Nessus Essentials operates in Read-Only mode (scan_api=false); import existing Nessus scan results separately.",
                })
            else:
                nessus_status = "UNAVAILABLE"
                scanners_skipped.append({
                    "scanner": "nessus",
                    "reason": n_conn.get("error") or "Tenable Nessus is disconnected.",
                })
        except Exception as e:
            nessus_status = "UNAVAILABLE"
            scanners_skipped.append({"scanner": "nessus", "reason": str(e)})

        # 5. Exposure scoring and Investigation Entity Graph synthesis
        exposure_report = ExposureScoringEngine.calculate_investigation_exposure(all_findings)
        self.repo.update_exposure_score(investigation_id, exposure_report["exposure_score"])
        try:
            from src.services.graph_intelligence_service import GraphIntelligenceService
            GraphIntelligenceService(repo=self.repo, storage=self.storage).sync_campaign_graph(
                investigation_id, scan_id=scan_id
            )
        except Exception as graph_err:
            logger.warning(f"Combined scan graph synthesis notice: {graph_err}")

        return {
            "status": "COMPLETED",
            "scan_type": "combined",
            "target": target,
            "scanners_executed": scanners_executed,
            "scanners_skipped": scanners_skipped,
            "nuclei_status": "ONLINE" if nuc_ready.get("ready") else "UNAVAILABLE",
            "nessus_status": nessus_status,
            "vulnerabilities_found": len(all_findings),
            "findings": all_findings,
            "exposure_summary": exposure_report
        }
