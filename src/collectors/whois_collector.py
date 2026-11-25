"""
OSINT-RECON WHOIS Collector Module
Gathers authoritative domain registration metadata via CLI whois / python-whois.
Normalizes timestamps, preserves raw evidence, and handles redaction and timeouts.
"""

import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Union
from dateutil import parser as date_parser

try:
    import whois
    from whois.parser import WhoisEntry
except ImportError:
    whois = None
    WhoisEntry = None

from src.schema import ReconRecord, TargetInfo, ToolInfo, WhoisData


def normalize_iso8601(val: Any) -> Optional[str]:
    """Converts datetimes, lists, or date strings into an ISO 8601 UTC string."""
    if not val:
        return None
    if isinstance(val, (list, tuple, set)):
        val = next(iter(val), None)
        if not val:
            return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        else:
            val = val.astimezone(timezone.utc)
        return val.isoformat()
    if isinstance(val, str):
        val = val.strip()
        if not val or val.lower() in ("null", "none", "not applicable", "n/a"):
            return None
        try:
            dt = date_parser.parse(val)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.isoformat()
        except Exception:
            return val
    return str(val)


def normalize_string_list(val: Any) -> List[str]:
    """Ensures input is a deduplicated, stripped list of non-empty strings."""
    if not val:
        return []
    if isinstance(val, str):
        val = [val]
    items = []
    seen = set()
    for item in val:
        if isinstance(item, str):
            clean = item.strip()
            if clean and clean.lower() not in seen:
                seen.add(clean.lower())
                items.append(clean)
    return items


def is_privacy_protected(val: Optional[str]) -> bool:
    """Checks whether registrant value is redacted or privacy-protected."""
    if not val:
        return False
    markers = [
        "redacted for privacy",
        "privacy service",
        "whoisguard",
        "private registrant",
        "gdpr masked",
        "domains by proxy",
        "withheld for privacy",
        "data protected",
        "statutory masking"
    ]
    val_lower = val.lower()
    return any(marker in val_lower for marker in markers)


class WhoisCollector:
    """
    Automated passive WHOIS collector that executes queries, normalizes registration
    metadata, and preserves raw text evidence.
    """

    def __init__(self, timeout: int = 15, raw_dir: Optional[str] = None):
        self.timeout = timeout
        self.raw_dir = raw_dir
        self.whois_bin = shutil.which("whois") or "/usr/bin/whois"
        self.version = self._detect_version()

    def _detect_version(self) -> str:
        """Detects WHOIS CLI binary version dynamically with fallback."""
        if os.path.exists(self.whois_bin):
            try:
                proc = subprocess.run([self.whois_bin, "--version"], capture_output=True, text=True, timeout=3)
                out = (proc.stdout or proc.stderr or "").strip()
                match = re.search(r"Version\s+([\d\.]+)", out, re.IGNORECASE)
                if match:
                    return match.group(1).rstrip(".")
            except Exception:
                pass
        return "5.6.5"

    def validate_domain(self, domain: str) -> str:
        """Validates and cleans input domain string."""
        if not domain or not isinstance(domain, str):
            raise ValueError("Target domain must be a non-empty string")
        clean = domain.strip().lower()
        clean = re.sub(r"^https?://", "", clean)
        clean = clean.split("/")[0].split(":")[0]
        # Basic domain format validation
        if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", clean):
            raise ValueError(f"Invalid domain format: '{domain}'")
        return clean

    def _execute_cli_whois(self, domain: str) -> tuple[int, str, str]:
        """Runs the native whois CLI binary safely using subprocess."""
        if not os.path.exists(self.whois_bin):
            raise FileNotFoundError(f"WHOIS binary not found at '{self.whois_bin}'")
        cmd = [self.whois_bin, domain]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired:
            return -1, "", f"WHOIS execution timed out after {self.timeout} seconds"
        except Exception as e:
            return -2, "", f"WHOIS execution error: {str(e)}"

    def parse_raw_whois(self, domain: str, raw_text: str) -> WhoisData:
        """Parses raw WHOIS response text using python-whois with regex fallbacks."""
        data_dict: Dict[str, Any] = {
            "domain_name": domain.upper(),
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "status": [],
            "name_servers": [],
            "registrant_name": None,
            "registrant_organization": None,
            "registrant_country": None,
            "emails": [],
            "dnssec": None,
            "raw_text": raw_text
        }

        # 1. Attempt parsing via python-whois library if available
        if WhoisEntry is not None:
            try:
                entry = WhoisEntry.load(domain, raw_text)
                if entry:
                    if entry.get("domain_name"):
                        dom = entry.get("domain_name")
                        data_dict["domain_name"] = dom[0] if isinstance(dom, list) else dom
                    data_dict["registrar"] = entry.get("registrar")
                    data_dict["creation_date"] = normalize_iso8601(entry.get("creation_date"))
                    data_dict["expiration_date"] = normalize_iso8601(entry.get("expiration_date"))
                    data_dict["updated_date"] = normalize_iso8601(entry.get("updated_date"))
                    raw_statuses = normalize_string_list(entry.get("status"))
                    data_dict["status"] = [s.split()[0] for s in raw_statuses if s.strip()]
                    data_dict["name_servers"] = [ns.lower() for ns in normalize_string_list(entry.get("name_servers"))]
                    data_dict["registrant_name"] = entry.get("name")
                    data_dict["registrant_organization"] = entry.get("org")
                    data_dict["registrant_country"] = entry.get("country")
                    data_dict["emails"] = normalize_string_list(entry.get("emails"))
                    data_dict["dnssec"] = entry.get("dnssec")
            except Exception:
                pass

        # 2. Regex fallback parser to extract or backfill missing attributes
        def extract_regex(pattern: str, text: str) -> Optional[str]:
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            return match.group(1).strip() if match else None

        if not data_dict["registrar"]:
            data_dict["registrar"] = extract_regex(r"Registrar:\s*([^\r\n]+)", raw_text)
        if not data_dict["creation_date"]:
            data_dict["creation_date"] = normalize_iso8601(
                extract_regex(r"(?:Creation Date|Created|Registration Date):\s*([^\r\n]+)", raw_text)
            )
        if not data_dict["expiration_date"]:
            data_dict["expiration_date"] = normalize_iso8601(
                extract_regex(r"(?:Registry Expiry Date|Expir\w+ Date):\s*([^\r\n]+)", raw_text)
            )
        if not data_dict["updated_date"]:
            data_dict["updated_date"] = normalize_iso8601(
                extract_regex(r"(?:Updated Date|Last Updated):\s*([^\r\n]+)", raw_text)
            )
        if not data_dict["name_servers"]:
            ns_matches = re.findall(r"Name Server:\s*([^\r\n]+)", raw_text, re.IGNORECASE)
            data_dict["name_servers"] = [ns.strip().lower() for ns in ns_matches if ns.strip()]
        if not data_dict["status"]:
            status_matches = re.findall(r"Domain Status:\s*([^\r\n]+)", raw_text, re.IGNORECASE)
            data_dict["status"] = [s.strip().split()[0] for s in status_matches if s.strip()]
        if not data_dict["registrant_name"]:
            data_dict["registrant_name"] = extract_regex(r"Registrant Name:\s*([^\r\n]+)", raw_text)
        if not data_dict["registrant_organization"]:
            data_dict["registrant_organization"] = extract_regex(r"Registrant Organization:\s*([^\r\n]+)", raw_text)
        if not data_dict["registrant_country"]:
            data_dict["registrant_country"] = extract_regex(r"Registrant Country:\s*([^\r\n]+)", raw_text)
        if not data_dict["emails"]:
            emails_matches = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", raw_text)
            data_dict["emails"] = normalize_string_list(emails_matches)
        if not data_dict["dnssec"]:
            data_dict["dnssec"] = extract_regex(r"DNSSEC:\s*([^\r\n]+)", raw_text)

        # 3. Privacy redaction handling
        for field in ("registrant_name", "registrant_organization"):
            val = data_dict.get(field)
            if is_privacy_protected(val):
                data_dict[field] = "[REDACTED FOR PRIVACY]"

        return WhoisData(**data_dict)

    def collect(self, domain: str, scan_id: Optional[str] = None) -> ReconRecord:
        """
        Executes WHOIS query for domain, saves raw output, and returns validated ReconRecord.
        """
        errors: List[str] = []
        raw_output_path = None
        raw_text = ""
        scan_status = "SUCCESS"

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
                    name="whois",
                    version=self.version,
                    execution_args=f"whois {domain}"
                ),
                recon_category="whois",
                scan_id=scan_id,
                scan_status="FAILED",
                errors_and_warnings=[str(ve)],
                evidence_source="whois_collector"
            )

        # Execute query
        code, stdout, stderr = self._execute_cli_whois(clean_domain)
        raw_text = stdout if stdout else stderr

        if code != 0:
            scan_status = "FAILED" if not stdout else "PARTIAL"
            if stderr:
                errors.append(stderr.strip())
            else:
                errors.append(f"WHOIS binary exited with code {code}")

        # Preserve raw output if raw_dir is provided
        if self.raw_dir:
            os.makedirs(self.raw_dir, exist_ok=True)
            filename = f"{scan_id}_whois_raw.txt" if scan_id else f"whois_{clean_domain}_raw.txt"
            raw_output_path = os.path.join(self.raw_dir, filename)
            try:
                with open(raw_output_path, "w", encoding="utf-8") as f:
                    f.write(raw_text)
            except IOError as ioe:
                errors.append(f"Failed to write raw output file: {ioe}")

        # Parse structured WHOIS data
        whois_data: Optional[WhoisData] = None
        if raw_text and ("Domain Name:" in raw_text or "domain:" in raw_text or "Registrar:" in raw_text):
            whois_data = self.parse_raw_whois(clean_domain, raw_text)
        elif scan_status == "SUCCESS":
            scan_status = "PARTIAL"
            errors.append("WHOIS server returned unparsed response without standard domain records")

        discovered_domains = [clean_domain]
        if whois_data and whois_data.name_servers:
            discovered_domains.extend([ns for ns in whois_data.name_servers if ns != clean_domain])

        return ReconRecord(
            target_info=TargetInfo(
                target=clean_domain,
                category="normal_benchmark_domain",
                authorization_status="AUTHORIZED_PASSIVE_ONLY",
                scope=f"{clean_domain} (Passive WHOIS Query)"
            ),
            tool_info=ToolInfo(
                name="whois",
                version=self.version,
                execution_args=f"whois {clean_domain}"
            ),
            recon_category="whois",
            scan_id=scan_id,
            discovered_domains=list(dict.fromkeys(discovered_domains)),
            email_addresses=whois_data.emails if whois_data else [],
            whois_data=whois_data,
            evidence_source=raw_output_path or f"whois {clean_domain}",
            scan_status=scan_status,
            errors_and_warnings=errors,
            raw_output_reference=raw_output_path
        )
