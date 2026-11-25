"""
OSINT-RECON theHarvester Collector Module
Executes theHarvester securely using argument lists for passive OSINT gathering.
Extracts public subdomains and email addresses from both JSON artifacts and stdout.
"""

import os
import re
import json
import shutil
import tempfile
import subprocess
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple

from src.schema import ReconRecord, TargetInfo, ToolInfo


DEFAULT_PASSIVE_SOURCES = ["duckduckgo"]


def clean_discovered_host(raw_host: str, target_domain: str) -> Optional[str]:
    """
    Cleans up artifact strings from search engines (e.g., '2Fdocs.kali.org' -> 'docs.kali.org').
    Ensures the host is a valid subdomain or exact match of the target domain.
    """
    if not raw_host or not isinstance(raw_host, str):
        return None
    cleaned = raw_host.strip().lower()
    # Strip URL prefixes or path artifacts
    cleaned = re.sub(r"^(?:https?://|2f|252f|//)", "", cleaned)
    cleaned = cleaned.split(":")[0].split("/")[0].strip().rstrip(".")
    
    # Must end with target_domain
    if not (cleaned == target_domain or cleaned.endswith("." + target_domain)):
        return None
        
    # Valid hostname characters check
    if re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", cleaned):
        return cleaned
    return None


class TheHarvesterCollector:
    """
    Passive OSINT Collector wrapping Kali's native theHarvester binary.
    Collects subdomains and public emails without active port scanning or intrusion probes.
    """

    def __init__(
        self,
        sources: Optional[List[str]] = None,
        limit: int = 50,
        timeout: int = 40,
        raw_dir: Optional[str] = None
    ):
        self.sources = sources or DEFAULT_PASSIVE_SOURCES
        self.limit = limit
        self.timeout = timeout
        self.raw_dir = raw_dir
        self.binary = shutil.which("theHarvester") or "/usr/bin/theHarvester"

    def validate_domain(self, domain: str) -> str:
        """Validates domain format."""
        if not domain or not isinstance(domain, str):
            raise ValueError("Target domain must be a non-empty string")
        clean = domain.strip().lower().rstrip(".")
        clean = re.sub(r"^https?://", "", clean)
        clean = clean.split("/")[0].split(":")[0]
        if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", clean):
            raise ValueError(f"Invalid domain format: '{domain}'")
        return clean

    def _parse_stdout_sections(self, stdout: str, target_domain: str) -> Tuple[List[str], List[str]]:
        """Parses stdout text for discovered hosts and email addresses."""
        hosts: List[str] = []
        emails: List[str] = []

        current_section = None
        for line in stdout.splitlines():
            line_str = line.strip()
            if "Hosts found:" in line_str:
                current_section = "hosts"
                continue
            elif "Emails found:" in line_str:
                current_section = "emails"
                continue
            elif line_str.startswith("[*]") or line_str.startswith("[-]"):
                current_section = None
                continue

            if current_section == "hosts":
                if line_str.startswith("-") or not line_str:
                    continue
                cleaned = clean_discovered_host(line_str, target_domain)
                if cleaned and cleaned not in hosts:
                    hosts.append(cleaned)
            elif current_section == "emails":
                if line_str.startswith("-") or not line_str:
                    continue
                # Email validation
                if re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", line_str):
                    if line_str.lower() not in [e.lower() for e in emails]:
                        emails.append(line_str)

        # General regex fallback for emails
        email_matches = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", stdout)
        for em in email_matches:
            if not em.endswith((".png", ".jpg", ".gif", ".css", ".js")):
                if em.lower() not in [e.lower() for e in emails]:
                    emails.append(em)

        return hosts, emails

    def _execute_harvester(
        self, domain: str, sources_str: str, tmp_prefix: str
    ) -> Tuple[int, str, str, Dict[str, Any]]:
        """Safely executes theHarvester via subprocess argument lists."""
        if not os.path.exists(self.binary):
            raise FileNotFoundError(f"theHarvester binary not found at '{self.binary}'")

        cmd = [
            self.binary,
            "-d", domain,
            "-b", sources_str,
            "-l", str(self.limit),
            "-f", tmp_prefix
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            json_file = f"{tmp_prefix}.json"
            json_data = {}
            if os.path.exists(json_file):
                try:
                    with open(json_file, "r", encoding="utf-8") as jf:
                        json_data = json.load(jf)
                except Exception:
                    pass
            return proc.returncode, stdout, stderr, json_data
        except subprocess.TimeoutExpired:
            return -1, "", f"theHarvester execution timed out after {self.timeout}s", {}
        except Exception as e:
            return -2, "", f"theHarvester execution failed: {str(e)}", {}

    def collect(
        self,
        domain: str,
        sources: Optional[List[str]] = None,
        scan_id: Optional[str] = None
    ) -> ReconRecord:
        """
        Executes passive harvesting for domain, normalizes subdomains/emails,
        preserves raw output, and returns a validated ReconRecord.
        """
        errors: List[str] = []
        raw_output_path = None
        selected_sources = sources or self.sources
        sources_arg = ",".join(selected_sources)

        try:
            clean_domain = self.validate_domain(domain)
        except ValueError as ve:
            return ReconRecord(
                target_info=TargetInfo(
                    target=str(domain),
                    category="normal_benchmark_domain",
                    authorization_status="AUTHORIZED_PASSIVE_ONLY",
                    scope=str(domain)
                ),
                tool_info=ToolInfo(
                    name="theHarvester",
                    version="4.8.2",
                    execution_args=f"theHarvester -d {domain} -b {sources_arg}"
                ),
                recon_category="search_engine_harvesting",
                scan_id=scan_id,
                scan_status="FAILED",
                errors_and_warnings=[str(ve)],
                evidence_source="theharvester_collector"
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_prefix = os.path.join(tmpdir, f"harvester_{clean_domain}")
            code, stdout, stderr, json_data = self._execute_harvester(clean_domain, sources_arg, tmp_prefix)

        raw_output = stdout if stdout else stderr
        if code != 0:
            if stderr:
                errors.append(stderr.strip())
            else:
                errors.append(f"theHarvester process returned non-zero code {code}")

        # Check for upstream search engine errors/rate-limiting
        if "502, message=" in raw_output or "503" in raw_output or "rate limit" in raw_output.lower():
            errors.append("Search engine rate-limiting or service unavailability detected")

        # Extract hosts and emails from both json_data and stdout
        discovered_hosts: List[str] = []
        discovered_emails: List[str] = []

        # From JSON artifact
        if json_data:
            for raw_h in json_data.get("hosts", []):
                cleaned = clean_discovered_host(raw_h, clean_domain)
                if cleaned and cleaned not in discovered_hosts:
                    discovered_hosts.append(cleaned)
            for raw_e in json_data.get("emails", []):
                if raw_e and raw_e.lower() not in [e.lower() for e in discovered_emails]:
                    discovered_emails.append(raw_e)

        # From stdout parser
        stdout_hosts, stdout_emails = self._parse_stdout_sections(stdout, clean_domain)
        for h in stdout_hosts:
            if h not in discovered_hosts:
                discovered_hosts.append(h)
        for e in stdout_emails:
            if e.lower() not in [em.lower() for em in discovered_emails]:
                discovered_emails.append(e)

        # Determine scan status
        if code == 0:
            scan_status = "SUCCESS" if not errors else "PARTIAL"
        elif discovered_hosts or discovered_emails:
            scan_status = "PARTIAL"
        else:
            scan_status = "FAILED"

        # Preserve raw evidence file if raw_dir is provided
        if self.raw_dir:
            os.makedirs(self.raw_dir, exist_ok=True)
            filename = f"{scan_id}_theharvester_raw.txt" if scan_id else f"theharvester_{clean_domain}_raw.txt"
            raw_output_path = os.path.join(self.raw_dir, filename)
            try:
                with open(raw_output_path, "w", encoding="utf-8") as f:
                    f.write(raw_output)
            except IOError as ioe:
                errors.append(f"Failed to write raw harvester output: {ioe}")

        # Ensure base domain is in discovered_domains if any were found
        all_domains = list(dict.fromkeys([clean_domain] + discovered_hosts)) if (discovered_hosts or scan_status == "SUCCESS") else []

        return ReconRecord(
            target_info=TargetInfo(
                target=clean_domain,
                category="normal_benchmark_domain",
                authorization_status="AUTHORIZED_PASSIVE_ONLY",
                scope=f"{clean_domain} (Passive theHarvester Query)"
            ),
            tool_info=ToolInfo(
                name="theHarvester",
                version="4.8.2",
                execution_args=f"theHarvester -d {clean_domain} -b {sources_arg} -l {self.limit}"
            ),
            recon_category="search_engine_harvesting",
            scan_id=scan_id,
            discovered_domains=all_domains,
            email_addresses=discovered_emails,
            evidence_source=raw_output_path or f"theHarvester ({clean_domain})",
            scan_status=scan_status,
            errors_and_warnings=errors,
            raw_output_reference=raw_output_path
        )

