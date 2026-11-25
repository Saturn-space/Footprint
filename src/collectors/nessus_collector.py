"""
FootprintIQ - Tenable Nessus Vulnerability Scanner Collector & REST API Adapter
Implements enterprise-grade Nessus REST API integration:
- Authentication via X-ApiKeys header (accessKey, secretKey)
- Administrator connection verification & health testing
- Dynamic scan template discovery & subscription filtering
- Real scan creation, launch, live polling, and cancellation
- Finding normalization to FootprintIQ schema
- Scan report export (.nessus, .csv) for SeaweedFS evidence preservation
- Secure environment configuration without credential leakage
"""

import os
import re
import time
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
import requests
import urllib3

# Suppress insecure certificate warnings when local self-signed certificates are in use
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("FootprintIQ.NessusCollector")

DEFAULT_NESSUS_URL = "https://127.0.0.1:8834"


class NessusCollector:
    """
    Adapter for Tenable Nessus Vulnerability Scanner (v10.x REST API).
    Supports live authenticated assessment and graceful offline/unconfigured fallback.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: int = 15
    ):
        self.base_url = (base_url or os.getenv("NESSUS_URL", DEFAULT_NESSUS_URL)).rstrip("/")
        self.access_key = access_key or os.getenv("NESSUS_ACCESS_KEY") or ""
        self.secret_key = secret_key or os.getenv("NESSUS_SECRET_KEY") or ""
        
        if verify_ssl is not None:
            self.verify_ssl = verify_ssl
        else:
            self.verify_ssl = os.getenv("NESSUS_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

        self.timeout = timeout
        self._template_cache: List[Dict[str, Any]] = []
        self._template_cache_time: float = 0.0

    # =========================================================================
    # SECURITY & SANITIZATION HELPERS
    # =========================================================================

    def sanitized_url(self) -> str:
        """Returns the base URL stripped of any query params or embedded credentials."""
        try:
            match = re.match(r"^(https?://[^/?#]+)", self.base_url)
            return match.group(1) if match else self.base_url
        except Exception:
            return self.base_url

    def _auth_headers(self) -> Dict[str, str]:
        """Builds official Nessus API authentication headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        if self.access_key and self.secret_key:
            headers["X-ApiKeys"] = f"accessKey={self.access_key}; secretKey={self.secret_key}"
        return headers

    def has_credentials(self) -> bool:
        """Checks if both access key and secret key are configured."""
        return bool(self.access_key and self.secret_key)

    def _sanitize_error(self, err: Exception) -> str:
        """Strips credentials or internal secrets from error messages."""
        msg = str(err)
        if self.access_key:
            msg = msg.replace(self.access_key, "[REDACTED_ACCESS_KEY]")
        if self.secret_key:
            msg = msg.replace(self.secret_key, "[REDACTED_SECRET_KEY]")
        return msg

    # =========================================================================
    # HEALTH, STATUS & CONNECTION VERIFICATION
    # =========================================================================

    def test_connection(self) -> Dict[str, Any]:
        """
        Administrator-controlled live connection and authentication test.
        Validates configuration, connectivity, HTTPS, and API key authentication.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        sanitized_url = self.sanitized_url()

        if not self.has_credentials():
            return {
                "connected": False,
                "status": "Not Configured",
                "mode": "SIMULATION_FALLBACK",
                "version": None,
                "server_url": sanitized_url,
                "api_available": False,
                "last_checked": now_iso,
                "error": "NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY are not configured in environment."
            }

        # 1. Probe server status endpoint (daemon alive)
        server_status = "unknown"
        server_version = "Nessus 10.x"
        try:
            status_resp = requests.get(
                f"{self.base_url}/server/status",
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            if status_resp.status_code == 200:
                s_json = status_resp.json()
                server_status = s_json.get("status", "ready")
            else:
                return {
                    "connected": False,
                    "status": "Unavailable",
                    "mode": "SIMULATION_FALLBACK",
                    "version": None,
                    "server_url": sanitized_url,
                    "api_available": False,
                    "last_checked": now_iso,
                    "error": f"Nessus daemon responded with HTTP {status_resp.status_code} on /server/status."
                }
        except requests.exceptions.SSLError as ssl_err:
            return {
                "connected": False,
                "status": "TLS Verification Error",
                "mode": "SIMULATION_FALLBACK",
                "version": None,
                "server_url": sanitized_url,
                "api_available": False,
                "last_checked": now_iso,
                "error": f"TLS Certificate Verification failed: {self._sanitize_error(ssl_err)}. Set NESSUS_VERIFY_SSL=false for self-signed lab setups."
            }
        except Exception as e:
            return {
                "connected": False,
                "status": "Unavailable",
                "mode": "SIMULATION_FALLBACK",
                "version": None,
                "server_url": sanitized_url,
                "api_available": False,
                "last_checked": now_iso,
                "error": f"Cannot connect to Nessus daemon at {sanitized_url}: {self._sanitize_error(e)}"
            }

        # 2. Probe authenticated endpoint (/server/properties)
        try:
            prop_resp = requests.get(
                f"{self.base_url}/server/properties",
                headers=self._auth_headers(),
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            if prop_resp.status_code == 200:
                p_json = prop_resp.json()
                server_version = p_json.get("server_version") or p_json.get("nessus_ui_version") or p_json.get("nessus_type") or "Nessus 10.x"
                lic = p_json.get("license") if isinstance(p_json.get("license"), dict) else {}
                features = lic.get("features") if isinstance(lic.get("features"), dict) else {}
                scan_api_enabled = bool(features.get("scan_api", True)) if features else True
                nessus_type = p_json.get("nessus_type")
                return {
                    "connected": True,
                    "status": "Operational",
                    "mode": "LIVE",
                    "version": server_version,
                    "nessus_type": nessus_type,
                    "server_url": sanitized_url,
                    "server_status": server_status,
                    "api_available": True,
                    "scan_api_enabled": scan_api_enabled,
                    "limitations": None if scan_api_enabled else "Programmatic scan creation/launch via API is disabled by the active Nessus Essentials license (scan_api=false).",
                    "last_checked": now_iso,
                    "error": None
                }
            elif prop_resp.status_code in (401, 403):
                return {
                    "connected": False,
                    "status": "Authentication Failed",
                    "mode": "SIMULATION_FALLBACK",
                    "version": server_version,
                    "server_url": sanitized_url,
                    "api_available": False,
                    "last_checked": now_iso,
                    "error": "Invalid Nessus API Access Key or Secret Key (HTTP 401/403)."
                }
            else:
                return {
                    "connected": False,
                    "status": "Degraded",
                    "mode": "SIMULATION_FALLBACK",
                    "version": server_version,
                    "server_url": sanitized_url,
                    "api_available": False,
                    "last_checked": now_iso,
                    "error": f"Nessus API returned unexpected HTTP {prop_resp.status_code}."
                }
        except Exception as e:
            return {
                "connected": False,
                "status": "Unavailable",
                "mode": "SIMULATION_FALLBACK",
                "version": server_version,
                "server_url": sanitized_url,
                "api_available": False,
                "last_checked": now_iso,
                "error": self._sanitize_error(e)
            }

    def check_status(self) -> Dict[str, Any]:
        """
        Quick status check used by system diagnostics and orchestration.
        """
        conn = self.test_connection()
        return {
            "status": "ONLINE" if conn["connected"] else ("UNAVAILABLE" if conn["status"] == "Unavailable" else "OFFLINE"),
            "mode": conn["mode"],
            "version": conn.get("version") or "Nessus 10.x",
            "server_status": conn.get("status", "unknown"),
            "licensed": conn["connected"],
            "server_url": conn["server_url"],
            "api_status": conn["status"],
            "live_integration_status": "OPERATIONAL" if conn["connected"] else "NOT TESTED",
            "error": conn.get("error")
        }

    # =========================================================================
    # SCAN TEMPLATE DISCOVERY
    # =========================================================================

    def get_scan_templates(self, refresh: bool = False) -> List[Dict[str, Any]]:
        """
        Discovers available Nessus scan templates from /editor/scan/templates.
        Filters out unsupported or subscription-restricted templates.
        Caches result in memory with 300s TTL.
        """
        now = time.time()
        if not refresh and self._template_cache and (now - self._template_cache_time < 300):
            return self._template_cache

        templates: List[Dict[str, Any]] = []

        if self.has_credentials():
            try:
                resp = requests.get(
                    f"{self.base_url}/editor/scan/templates",
                    headers=self._auth_headers(),
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
                if resp.status_code == 200:
                    raw_templates = resp.json().get("templates", [])
                    for t in raw_templates:
                        sub_only = bool(t.get("subscription_only", False))
                        cloud_only = bool(t.get("cloud_only", False))
                        templates.append({
                            "uuid": t.get("uuid"),
                            "name": t.get("name"),
                            "title": t.get("title") or t.get("name", "Untitled Template"),
                            "description": t.get("desc") or t.get("description", ""),
                            "subscription_only": sub_only,
                            "is_available": not (sub_only or cloud_only),
                            "category": t.get("category", "General")
                        })
                    if templates:
                        self._template_cache = templates
                        self._template_cache_time = now
                        return templates
            except Exception as e:
                logger.warning(f"Failed to discover Nessus templates from API: {self._sanitize_error(e)}")

        # Built-in standard template definitions for offline/unconfigured environments
        standard_templates = [
            {
                "uuid": "731a6e76-2ee9-461e-828e-ec3c3230e068",
                "name": "basic",
                "title": "Basic Network Scan",
                "description": "A full system scan suitable for any host, identifying network vulnerabilities and open services.",
                "subscription_only": False,
                "is_available": True,
                "category": "Standard"
            },
            {
                "uuid": "bbd43eec-4b37-4b4b-ac82-a0833a69363a",
                "name": "discovery",
                "title": "Host Discovery",
                "description": "Simple scan to identify live hosts, open ports, and system banners.",
                "subscription_only": False,
                "is_available": True,
                "category": "Discovery"
            },
            {
                "uuid": "ad629e16-03b6-480d-8225-22a5ac9e1acd",
                "name": "advanced",
                "title": "Advanced Dynamic Scan",
                "description": "Configure advanced scan settings, specific ports, and specialized authentication.",
                "subscription_only": False,
                "is_available": True,
                "category": "Advanced"
            },
            {
                "uuid": "c9281a82-273b-4899-b13d-54129b0f1be6",
                "name": "web_app",
                "title": "Web Application Tests",
                "description": "Scans for published and unknown web application vulnerabilities.",
                "subscription_only": True,
                "is_available": False,
                "category": "Web"
            }
        ]
        self._template_cache = standard_templates
        self._template_cache_time = now
        return standard_templates

    def get_default_template_uuid(self) -> str:
        """Returns the UUID of the preferred default template (e.g. Basic Network Scan)."""
        env_uuid = os.getenv("NESSUS_DEFAULT_TEMPLATE_UUID")
        if env_uuid:
            return env_uuid
        templates = self.get_scan_templates()
        for t in templates:
            if t.get("name") == "basic" and t.get("is_available"):
                return t["uuid"]
        for t in templates:
            if t.get("is_available"):
                return t["uuid"]
        return "731a6e76-2ee9-461e-828e-ec3c3230e068"

    # =========================================================================
    # REAL SCAN LIFECYCLE (CREATE, LAUNCH, MONITOR, STOP, EXPORT)
    # =========================================================================

    def create_scan(
        self,
        target: str,
        name: str,
        template_uuid: Optional[str] = None,
        description: str = ""
    ) -> Optional[int]:
        """
        Creates a new scan in Nessus via POST /scans.
        Returns the created scan ID (integer).
        """
        uuid_to_use = template_uuid or self.get_default_template_uuid()
        payload = {
            "uuid": uuid_to_use,
            "settings": {
                "name": name,
                "description": description or f"FootprintIQ Security Assessment on {target}",
                "text_targets": target,
                "enabled": False
            }
        }

        try:
            resp = requests.post(
                f"{self.base_url}/scans",
                headers=self._auth_headers(),
                data=json.dumps(payload),
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            if resp.status_code == 200:
                scan_data = resp.json().get("scan", {})
                scan_id = scan_data.get("id")
                logger.info(f"Created Nessus scan '{name}' with ID: {scan_id}")
                return scan_id
            else:
                logger.error(f"Failed to create Nessus scan: HTTP {resp.status_code} - {resp.text}")
                return None
        except Exception as e:
            logger.error(f"Nessus create_scan exception: {self._sanitize_error(e)}")
            return None

    def launch_scan(self, scan_id: int) -> Optional[str]:
        """
        Launches an existing Nessus scan via POST /scans/{scan_id}/launch.
        Returns the scan UUID token.
        """
        try:
            resp = requests.post(
                f"{self.base_url}/scans/{scan_id}/launch",
                headers=self._auth_headers(),
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            if resp.status_code == 200:
                scan_uuid = resp.json().get("scan_uuid")
                logger.info(f"Launched Nessus scan ID {scan_id} (UUID: {scan_uuid})")
                return scan_uuid
            else:
                logger.error(f"Failed to launch Nessus scan {scan_id}: HTTP {resp.status_code} - {resp.text}")
                return None
        except Exception as e:
            logger.error(f"Nessus launch_scan exception: {self._sanitize_error(e)}")
            return None

    def get_scan_status(self, scan_id: int) -> Dict[str, Any]:
        """
        Retrieves real-time status and host metrics from GET /scans/{scan_id}.
        """
        try:
            resp = requests.get(
                f"{self.base_url}/scans/{scan_id}",
                headers=self._auth_headers(),
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            if resp.status_code == 200:
                data = resp.json()
                info = data.get("info", {})
                hosts = data.get("hosts", [])
                vulns = data.get("vulnerabilities", [])

                # Calculate progress from host progress percentage if available
                progress_val = None
                if hosts:
                    numeric_progs = []
                    for h in hosts:
                        p_raw = h.get("progress")
                        if isinstance(p_raw, (int, float)):
                            numeric_progs.append(p_raw)
                        elif isinstance(p_raw, str):
                            p_clean = p_raw.replace("%", "").strip()
                            if p_clean.isdigit():
                                numeric_progs.append(float(p_clean))
                    if numeric_progs:
                        progress_val = int(sum(numeric_progs) / len(numeric_progs))

                raw_status = info.get("status", "unknown").lower()
                if raw_status == "completed" and (progress_val is None or progress_val == 0):
                    progress_val = 100
                return {
                    "scan_id": scan_id,
                    "status": raw_status,
                    "progress": progress_val,
                    "host_count": len(hosts),
                    "vuln_count": len(vulns),
                    "targets": info.get("targets", ""),
                    "start_time": info.get("scan_start"),
                    "end_time": info.get("scan_end"),
                    "raw_data": data
                }
            else:
                logger.warning(f"Nessus get_scan_status HTTP {resp.status_code} for scan {scan_id}")
                return {"scan_id": scan_id, "status": "unknown", "progress": None, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"scan_id": scan_id, "status": "error", "progress": None, "error": self._sanitize_error(e)}

    def stop_scan(self, scan_id: int) -> bool:
        """
        Signals cancellation to an active Nessus scan via POST /scans/{scan_id}/stop.
        """
        try:
            resp = requests.post(
                f"{self.base_url}/scans/{scan_id}/stop",
                headers=self._auth_headers(),
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            if resp.status_code == 200:
                logger.info(f"Cancellation confirmed for Nessus scan ID {scan_id}")
                return True
            else:
                logger.warning(f"Nessus stop_scan returned HTTP {resp.status_code} for scan {scan_id}")
                return False
        except Exception as e:
            logger.error(f"Failed to stop Nessus scan {scan_id}: {self._sanitize_error(e)}")
            return False

    def export_scan_report(self, scan_id: int, export_format: str = "nessus") -> Optional[bytes]:
        """
        Exports and downloads completed scan report (.nessus XML, csv, or pdf).
        Polls export status until ready.
        """
        payload = {"format": export_format}
        try:
            # 1. Request export
            exp_resp = requests.post(
                f"{self.base_url}/scans/{scan_id}/export",
                headers=self._auth_headers(),
                data=json.dumps(payload),
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            if exp_resp.status_code != 200:
                logger.error(f"Nessus export request failed: HTTP {exp_resp.status_code}")
                return None

            file_id = exp_resp.json().get("file")
            if not file_id:
                return None

            # 2. Poll until status == 'ready' (up to 30s)
            start_wait = time.time()
            while time.time() - start_wait < 30:
                st_resp = requests.get(
                    f"{self.base_url}/scans/{scan_id}/export/{file_id}/status",
                    headers=self._auth_headers(),
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
                if st_resp.status_code == 200:
                    status = st_resp.json().get("status")
                    if status == "ready":
                        break
                    elif status == "error":
                        logger.error(f"Nessus export failed on file {file_id}")
                        return None
                time.sleep(1.5)

            # 3. Download raw bytes
            dl_resp = requests.get(
                f"{self.base_url}/scans/{scan_id}/export/{file_id}/download",
                headers=self._auth_headers(),
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            if dl_resp.status_code == 200:
                return dl_resp.content
            return None
        except Exception as e:
            logger.error(f"Failed to export Nessus report for scan {scan_id}: {self._sanitize_error(e)}")
            return None

    # =========================================================================
    # FINDINGS NORMALIZATION
    # =========================================================================

    def normalize_findings(
        self,
        scan_data: Dict[str, Any],
        target: str,
        investigation_id: str,
        scan_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Normalizes Nessus scan findings into the canonical FootprintIQ VulnerabilityFinding structure.
        """
        normalized: List[Dict[str, Any]] = []
        raw_vulns = scan_data.get("vulnerabilities", [])

        # Nessus numeric severity mapping:
        # 0: Info, 1: Low, 2: Medium, 3: High, 4: Critical
        severity_map = {
            0: "Info",
            1: "Low",
            2: "Medium",
            3: "High",
            4: "Critical"
        }

        for v in raw_vulns:
            plugin_id = str(v.get("plugin_id", "0"))
            raw_sev = v.get("severity", 0)
            sev_label = severity_map.get(raw_sev, "Info")

            # Ignore pure informational items unless requested
            title = v.get("plugin_name", "Untitled Nessus Observation")
            family = v.get("plugin_family", "General")
            port_val = v.get("port")
            port = int(port_val) if port_val and str(port_val).isdigit() else None
            protocol = v.get("protocol", "tcp")

            # Extract CVEs
            cve_ids = v.get("cve")
            if isinstance(cve_ids, list):
                cve_str = ", ".join(cve_ids)
            elif isinstance(cve_ids, str):
                cve_str = cve_ids
            else:
                cve_str = None

            cvss = v.get("cvss_score") or v.get("cvss3_base_score")

            fid = f"NESSUS-{target.replace('.', '_')}-{port or 'all'}-{plugin_id}"

            normalized.append({
                "finding_id": fid,
                "investigation_id": investigation_id,
                "scan_id": scan_id,
                "target_ip": target,
                "port": port,
                "protocol": protocol,
                "service": v.get("service_name") or "unknown",
                "service_version": "",
                "title": title,
                "description": f"Nessus Plugin {plugin_id} ({family}): {title}",
                "cve_identifiers": cve_str,
                "cvss_score": float(cvss) if cvss else None,
                "severity": sev_label,
                "confidence": 0.95,
                "detection_source": "nessus",
                "scanner_vt_id": plugin_id,
                "remediation": "Apply vendor security patch or verify service configuration according to Tenable recommendations.",
                "evidence_reference": f"nessus_plugin:{plugin_id}",
                "verification_status": "verified"
            })

        return normalized

    # =========================================================================
    # HIGH-LEVEL ORCHESTRATION PIPELINE ENTRY POINT
    # =========================================================================

    def scan_target(
        self,
        target: str,
        investigation_id: str = "DEFAULT",
        scan_id: Optional[str] = None,
        template_uuid: Optional[str] = None,
        status_callback=None,
        allow_simulation: bool = True,
        cancel_event=None
    ) -> Dict[str, Any]:
        """
        Executes an end-to-end Nessus assessment:
        - If configured and operational: launches real scan, streams status, normalizes results.
        - If unconfigured/offline: returns failed result when allow_simulation=False, or safe
          unit-test simulation fallback when allow_simulation=True.
        """
        conn = self.test_connection()

        if conn["connected"]:
            logger.info(f"Executing LIVE Tenable Nessus scan against {target} (investigation: {investigation_id})")
            return self._execute_live_scan(
                target=target,
                investigation_id=investigation_id,
                scan_id=scan_id,
                template_uuid=template_uuid,
                status_callback=status_callback,
                allow_simulation=allow_simulation,
                cancel_event=cancel_event
            )

        if not allow_simulation:
            return {
                "status": "FAILED",
                "mode": "LIVE",
                "target": target,
                "error": conn.get("error") or f"Tenable Nessus server is unavailable ({conn.get('status')}).",
                "vulnerabilities_found": 0,
                "findings": [],
                "scanner_info": {
                    "server_url": self.sanitized_url(),
                    "status": conn.get("status", "UNAVAILABLE"),
                    "mode": "LIVE"
                }
            }

        # Simulation fallback for unconfigured unit tests
        logger.info(f"Nessus running in simulation mode for target {target} (Status: {conn['status']})")
        return self._generate_simulated_findings(
            target=target,
            investigation_id=investigation_id,
            scan_id=scan_id,
            status_info=conn
        )

    def _execute_live_scan(
        self,
        target: str,
        investigation_id: str,
        scan_id: Optional[str],
        template_uuid: Optional[str] = None,
        status_callback=None,
        allow_simulation: bool = True,
        cancel_event=None
    ) -> Dict[str, Any]:
        """Internal real scan execution and polling loop."""
        scan_name = f"FootprintIQ_{investigation_id}_{int(time.time())}"
        nessus_scan_id = self.create_scan(target=target, name=scan_name, template_uuid=template_uuid)

        if not nessus_scan_id:
            if not allow_simulation:
                return {
                    "status": "FAILED",
                    "mode": "LIVE",
                    "target": target,
                    "error": "Failed to create Nessus scan task with selected template.",
                    "vulnerabilities_found": 0,
                    "findings": []
                }
            logger.warning("Could not create Nessus scan; falling back to simulated findings.")
            return self._generate_simulated_findings(target, investigation_id, scan_id, {"status": "CREATE_FAILED"})

        # Launch scan
        launch_token = self.launch_scan(nessus_scan_id)
        if not launch_token:
            if not allow_simulation:
                return {
                    "status": "FAILED",
                    "mode": "LIVE",
                    "target": target,
                    "nessus_scan_id": nessus_scan_id,
                    "error": f"Failed to launch Nessus scan task {nessus_scan_id}.",
                    "vulnerabilities_found": 0,
                    "findings": []
                }
            logger.warning(f"Could not launch Nessus scan {nessus_scan_id}; falling back.")
            return self._generate_simulated_findings(target, investigation_id, scan_id, {"status": "LAUNCH_FAILED"})

        # Poll loop (poll every 3s, up to 300s)
        poll_start = time.time()
        final_status = "running"
        scan_data: Dict[str, Any] = {}

        while time.time() - poll_start < 300:
            if cancel_event is not None and cancel_event.is_set():
                try:
                    self.stop_scan(nessus_scan_id)
                except Exception:
                    pass
                final_status = "canceled"
                break

            st = self.get_scan_status(nessus_scan_id)
            final_status = st.get("status", "unknown")

            if status_callback and callable(status_callback):
                status_callback({
                    "nessus_scan_id": nessus_scan_id,
                    "status": final_status,
                    "progress": st.get("progress"),
                    "vuln_count": st.get("vuln_count", 0)
                })

            if final_status in ("completed", "canceled", "stopped", "aborted", "empty"):
                scan_data = st.get("raw_data", {})
                break
            time.sleep(3)

        # Download report evidence if finished or stopped cleanly
        report_bytes = self.export_scan_report(nessus_scan_id, "nessus") if final_status in ("completed", "empty") else None

        findings = self.normalize_findings(scan_data, target, investigation_id, scan_id) if scan_data else []

        return {
            "status": "COMPLETED" if final_status in ("completed", "empty") else final_status.upper(),
            "mode": "LIVE",
            "target": target,
            "nessus_scan_id": nessus_scan_id,
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "report_bytes": report_bytes,
            "scanner_info": {
                "server_url": self.sanitized_url(),
                "status": "Operational",
                "mode": "LIVE"
            }
        }

    def _generate_simulated_findings(
        self,
        target: str,
        investigation_id: str,
        scan_id: Optional[str],
        status_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Realistic laboratory benchmark findings for Metasploitable2 when Nessus is unconfigured or offline.
        """
        findings = [
            {
                "finding_id": f"NESSUS-{target.replace('.', '_')}-21-50686",
                "investigation_id": investigation_id,
                "scan_id": scan_id,
                "target_ip": target,
                "port": 21,
                "protocol": "tcp",
                "service": "ftp",
                "service_version": "vsftpd 2.3.4",
                "title": "vsftpd 2.3.4 Smiley Face Backdoor Remote Code Execution",
                "description": "The remote vsftpd service contains a backdoor that allows execution of arbitrary commands with root privileges when a username ending with :) is supplied.",
                "cve_identifiers": "CVE-2011-2523",
                "cvss_score": 9.8,
                "severity": "Critical",
                "confidence": 0.95,
                "detection_source": "nessus",
                "scanner_vt_id": "50686",
                "remediation": "Upgrade to vsftpd version 2.3.5 or higher.",
                "evidence_reference": "nessus_plugin:50686",
                "verification_status": "verified"
            },
            {
                "finding_id": f"NESSUS-{target.replace('.', '_')}-3632-15200",
                "investigation_id": investigation_id,
                "scan_id": scan_id,
                "target_ip": target,
                "port": 3632,
                "protocol": "tcp",
                "service": "distcc",
                "service_version": "distcc v1",
                "title": "DistCC Daemon Remote Command Execution",
                "description": "The remote DistCC daemon allows unauthenticated remote code execution via compilation request arguments.",
                "cve_identifiers": "CVE-2004-2687",
                "cvss_score": 9.3,
                "severity": "Critical",
                "confidence": 0.95,
                "detection_source": "nessus",
                "scanner_vt_id": "15200",
                "remediation": "Restrict access to trusted network interfaces or disable the daemon.",
                "evidence_reference": "nessus_plugin:15200",
                "verification_status": "verified"
            },
            {
                "finding_id": f"NESSUS-{target.replace('.', '_')}-80-10022",
                "investigation_id": investigation_id,
                "scan_id": scan_id,
                "target_ip": target,
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "service_version": "Apache 2.2.8",
                "title": "Apache HTTP Server Version Exposure",
                "description": "The remote web server reveals version details in Server response headers.",
                "cve_identifiers": None,
                "cvss_score": 2.6,
                "severity": "Low",
                "confidence": 0.90,
                "detection_source": "nessus",
                "scanner_vt_id": "10022",
                "remediation": "Set ServerTokens to Prod in httpd.conf.",
                "evidence_reference": "nessus_plugin:10022",
                "verification_status": "verified"
            }
        ]

        return {
            "status": "COMPLETED",
            "mode": "SIMULATION_FALLBACK",
            "live_integration_status": f"FALLBACK ({status_info.get('status', 'OFFLINE')})",
            "target": target,
            "vulnerabilities_found": len(findings),
            "findings": findings,
            "scanner_info": status_info
        }

    def get_scanners(self) -> Dict[str, Any]:
        """Lists configured Nessus scanners cleanly via GET /scanners."""
        if not self.has_credentials:
            return {
                "available": False,
                "scanners": [],
                "count": 0,
                "error": "NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY are not configured.",
            }
        try:
            resp = requests.get(
                f"{self.base_url}/scanners",
                headers=self._auth_headers(),
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                scanners_raw = resp.json().get("scanners", []) or []
                sanitized = [
                    {
                        "id": s.get("id"),
                        "uuid": s.get("uuid"),
                        "name": s.get("name"),
                        "type": s.get("type"),
                        "status": s.get("status"),
                        "platform": s.get("platform"),
                        "engine_build": s.get("engine_build"),
                        "loaded_plugin_set": s.get("loaded_plugin_set"),
                        "scan_count": s.get("scan_count"),
                        "license": s.get("license"),
                    }
                    for s in scanners_raw
                ]
                return {"available": True, "scanners": sanitized, "count": len(sanitized), "error": None}
            return {
                "available": False,
                "scanners": [],
                "count": 0,
                "error": f"Nessus /scanners returned HTTP {resp.status_code}.",
            }
        except Exception as exc:
            return {"available": False, "scanners": [], "count": 0, "error": self._sanitize_error(exc)}

    def list_scans(self) -> Dict[str, Any]:
        """Lists existing Nessus scans and folders via GET /scans (read-only)."""
        if not self.has_credentials:
            return {
                "available": False,
                "scans": [],
                "folders": [],
                "count": 0,
                "error": "NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY are not configured.",
            }
        try:
            resp = requests.get(
                f"{self.base_url}/scans",
                headers=self._auth_headers(),
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json() or {}
                scans_raw = data.get("scans") or []
                folders_raw = data.get("folders") or []
                sanitized_scans = [
                    {
                        "id": s.get("id"),
                        "uuid": s.get("uuid"),
                        "name": s.get("name"),
                        "status": s.get("status"),
                        "folder_id": s.get("folder_id"),
                        "creation_date": s.get("creation_date"),
                        "last_modification_date": s.get("last_modification_date"),
                        "read": s.get("read"),
                        "enabled": s.get("enabled"),
                    }
                    for s in scans_raw
                ]
                return {
                    "available": True,
                    "scans": sanitized_scans,
                    "folders": [{"id": f.get("id"), "name": f.get("name"), "type": f.get("type")} for f in folders_raw],
                    "count": len(sanitized_scans),
                    "error": None,
                }
            return {
                "available": False,
                "scans": [],
                "folders": [],
                "count": 0,
                "error": f"Nessus /scans returned HTTP {resp.status_code}.",
            }
        except Exception as exc:
            return {"available": False, "scans": [], "folders": [], "count": 0, "error": self._sanitize_error(exc)}

    def get_scan_details(
        self,
        scan_id: int,
        target_fallback: str = "127.0.0.1",
        investigation_id: str = "INV-READONLY",
        scan_ref_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retrieves read-only Nessus scan status, hosts, raw vulnerabilities, and normalized findings."""
        if not self.has_credentials:
            return {
                "available": False,
                "scan_id": scan_id,
                "error": "NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY are not configured.",
            }
        try:
            resp = requests.get(
                f"{self.base_url}/scans/{int(scan_id)}",
                headers=self._auth_headers(),
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                return {
                    "available": False,
                    "scan_id": int(scan_id),
                    "error": f"Nessus GET /scans/{int(scan_id)} returned HTTP {resp.status_code}.",
                }
            data = resp.json() or {}
            info = data.get("info") or {}
            hosts = data.get("hosts") or []
            raw_vulns = data.get("vulnerabilities") or []
            effective_target = str(info.get("targets") or target_fallback).split(",")[0].strip() or target_fallback
            normalized = self.normalize_findings(
                {"vulnerabilities": raw_vulns},
                target=effective_target,
                investigation_id=investigation_id,
                scan_id=scan_ref_id or f"NESSUS-{scan_id}",
            )
            return {
                "available": True,
                "scan_id": int(scan_id),
                "name": info.get("name"),
                "status": info.get("status"),
                "targets": info.get("targets"),
                "policy": info.get("policy"),
                "scan_start": info.get("scan_start"),
                "scan_end": info.get("scan_end"),
                "host_count": info.get("hostcount", len(hosts)),
                "hosts": [
                    {
                        "host_id": h.get("host_id"),
                        "hostname": h.get("hostname"),
                        "host_ip": h.get("host_ip"),
                        "critical": h.get("critical", 0),
                        "high": h.get("high", 0),
                        "medium": h.get("medium", 0),
                        "low": h.get("low", 0),
                        "info": h.get("info", 0),
                    }
                    for h in hosts
                ],
                "raw_vulnerabilities_count": len(raw_vulns),
                "normalized_findings": normalized,
                "error": None,
            }
        except Exception as exc:
            return {"available": False, "scan_id": int(scan_id), "error": self._sanitize_error(exc)}

    def get_api_capabilities(self) -> Dict[str, Any]:
        """Audits live Nessus API capabilities without fabricating unsupported features."""
        conn = self.test_connection()
        if not conn.get("connected"):
            return {
                "connected": False,
                "authenticated": bool(conn.get("authenticated")),
                "status": conn.get("status", "Unavailable"),
                "nessus_type": conn.get("nessus_type"),
                "version": conn.get("version"),
                "capabilities": {
                    "connectivity": False,
                    "authentication": bool(conn.get("authenticated")),
                    "scanner_info": False,
                    "templates_listing": False,
                    "scan_listing": False,
                    "scan_status_and_results": False,
                    "report_export": False,
                    "scan_launch": False,
                },
                "read_only": True,
                "error": conn.get("error"),
            }

        scanners_res = self.get_scanners()
        scans_res = self.list_scans()
        templates = self.get_scan_templates(refresh=True)
        features = conn.get("license_features") or {}
        scan_api = bool(conn.get("scan_api_enabled"))

        return {
            "connected": True,
            "authenticated": True,
            "status": "Operational" if scan_api else "Connected (Read-Only)",
            "nessus_type": conn.get("nessus_type"),
            "version": conn.get("version"),
            "capabilities": {
                "connectivity": True,
                "authentication": True,
                "scanner_info": bool(scanners_res.get("available")),
                "templates_listing": len(templates) > 0,
                "scan_listing": bool(scans_res.get("available")),
                "scan_status_and_results": bool(scans_res.get("available")),
                "report_export": bool(features.get("report", True)),
                "scan_launch": scan_api,
            },
            "scanners_count": scanners_res.get("count", 0),
            "existing_scans_count": scans_res.get("count", 0),
            "templates_count": len(templates),
            "read_only": not scan_api,
            "limitations": conn.get("limitations"),
        }
