"""
OSINT-RECON Target Authorization & Scope Control Module
Enforces strict lab scope allowlists, input validation, and authorization records
prior to executing active reconnaissance.
"""

import os
import re
import json
import socket
import ipaddress
import subprocess
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

from src.schema import TargetAuthorizationRecord

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_CONFIG_PATH = os.path.join(PROJECT_ROOT, "config", "target_authorization.json")


class TargetAuthorizationError(PermissionError):
    """Raised when a target or profile violates authorization boundaries."""
    pass


class TargetSyntaxError(ValueError):
    """Raised when a target format is invalid, malformed, or unauthorized CIDR."""
    pass


class TargetAuthorizer:
    """
    Validates target formatting and enforces configuration allowlists
    for active reconnaissance.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or DEFAULT_CONFIG_PATH
        self.config = self._load_config()
        self.default_target = self.config.get("default_target", "192.168.56.111")
        self.authorized_targets = self.config.get("authorized_targets", [])
        self.approved_lab_ranges = self.config.get("approved_lab_ranges", [])
        self.authorized_domains = self.config.get("authorized_domains", [])
        self.rules = self.config.get("rules", {
            "allow_cidr_ranges": False,
            "allow_public_ips": False,
            "allow_unlisted_targets": False,
            "require_explicit_authorization": True
        })

    def _save_config(self) -> None:
        """Persists updated target authorization configuration atomically."""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        self.config["default_target"] = self.default_target
        self.config["authorized_targets"] = self.authorized_targets
        self.config["approved_lab_ranges"] = self.approved_lab_ranges
        self.config["authorized_domains"] = self.authorized_domains
        self.config["rules"] = self.rules
        tmp_path = f"{self.config_path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(self.config, f, indent=2)
        os.replace(tmp_path, self.config_path)

    def get_scope_summary(self) -> Dict[str, Any]:
        return {
            "default_target": self.default_target,
            "authorized_targets": self.authorized_targets,
            "approved_lab_ranges": self.approved_lab_ranges,
            "authorized_domains": self.authorized_domains,
            "rules": self.rules
        }

    def add_approved_lab_range(self, range_spec: str, description: str = "Approved Lab Range", added_by: str = "admin") -> Dict[str, Any]:
        clean = range_spec.strip()
        # Validate CIDR or hyphenated IPv4 range
        if "/" in clean:
            net = ipaddress.ip_network(clean, strict=False)
            if not (net.is_private or net.is_loopback):
                raise TargetAuthorizationError(f"Only private or loopback ranges can be registered as lab ranges ('{clean}').")
            normalized = str(net)
        elif "-" in clean:
            parts = [p.strip() for p in clean.split("-", 1)]
            ip1 = ipaddress.ip_address(parts[0])
            ip2 = ipaddress.ip_address(parts[1])
            if not ((ip1.is_private or ip1.is_loopback) and (ip2.is_private or ip2.is_loopback)):
                raise TargetAuthorizationError(f"Only private/loopback IP ranges are allowed ('{clean}').")
            if int(ip2) < int(ip1):
                raise TargetSyntaxError(f"Invalid IP range order: '{clean}'.")
            if int(ip2) - int(ip1) > 4096:
                raise TargetSyntaxError(f"Lab IP range exceeds maximum 4096 addresses: '{clean}'.")
            normalized = f"{ip1}-{ip2}"
        else:
            ip_obj = ipaddress.ip_address(clean)
            if not (ip_obj.is_private or ip_obj.is_loopback):
                raise TargetAuthorizationError(f"Public IP '{clean}' cannot be added as a lab range.")
            normalized = f"{ip_obj}/32"

        existing = next((r for r in self.approved_lab_ranges if r.get("range") == normalized), None)
        if existing:
            existing["description"] = description
            existing["added_by"] = added_by
            self._save_config()
            return existing

        entry = {
            "range": normalized,
            "description": description,
            "permitted_profiles": ["lab-basic", "lab-safe-minimal", "lab-common-services"],
            "added_by": added_by,
            "added_at": datetime.now(timezone.utc).isoformat()
        }
        self.approved_lab_ranges.append(entry)
        self._save_config()
        return entry

    def remove_approved_lab_range(self, range_spec: str) -> bool:
        clean = range_spec.strip()
        before = len(self.approved_lab_ranges)
        self.approved_lab_ranges = [r for r in self.approved_lab_ranges if r.get("range") != clean]
        if len(self.approved_lab_ranges) < before:
            self._save_config()
            return True
        return False

    def add_authorized_domain(self, domain: str, scope_notes: str = "Explicitly Authorized Domain", added_by: str = "admin") -> Dict[str, Any]:
        clean = domain.strip().lower()
        if any(c in clean for c in [";", "&", "|", "`", "$", " ", "\t", "\n", "\r", ">", "<", "\"", "'", "\\", "/"]):
            raise TargetSyntaxError(f"Invalid characters in domain '{domain}'.")
        hostname_regex = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if not re.match(hostname_regex, clean):
            raise TargetSyntaxError(f"Invalid domain format '{domain}'.")
        existing = next((d for d in self.authorized_domains if d.get("domain") == clean), None)
        if existing:
            existing["notes"] = scope_notes
            existing["added_by"] = added_by
            self._save_config()
            return existing
        entry = {
            "domain": clean,
            "notes": scope_notes,
            "added_by": added_by,
            "added_at": datetime.now(timezone.utc).isoformat(),
            "permitted_profiles": ["lab-basic", "lab-safe-minimal", "lab-common-services"]
        }
        self.authorized_domains.append(entry)
        self._save_config()
        return entry

    def remove_authorized_domain(self, domain: str) -> bool:
        clean = domain.strip().lower()
        before = len(self.authorized_domains)
        self.authorized_domains = [d for d in self.authorized_domains if d.get("domain") != clean]
        if len(self.authorized_domains) < before:
            self._save_config()
            return True
        return False

    def _is_ip_in_approved_range(self, ip_obj: ipaddress._BaseAddress) -> Optional[Dict[str, Any]]:
        for rng in self.approved_lab_ranges:
            spec = str(rng.get("range", "")).strip()
            try:
                if "/" in spec:
                    if ip_obj in ipaddress.ip_network(spec, strict=False):
                        return rng
                elif "-" in spec:
                    p1, p2 = [ipaddress.ip_address(x.strip()) for x in spec.split("-", 1)]
                    if int(p1) <= int(ip_obj) <= int(p2):
                        return rng
            except Exception:
                continue
        return None

    def _is_range_covered_by_approved(self, target_spec: str) -> Optional[Dict[str, Any]]:
        clean = target_spec.strip()
        try:
            if "/" in clean:
                target_net = ipaddress.ip_network(clean, strict=False)
                for rng in self.approved_lab_ranges:
                    spec = str(rng.get("range", "")).strip()
                    if "/" in spec and target_net.subnet_of(ipaddress.ip_network(spec, strict=False)):  # type: ignore
                        return rng
            elif "-" in clean:
                p1, p2 = [ipaddress.ip_address(x.strip()) for x in clean.split("-", 1)]
                if int(p2) >= int(p1) and (int(p2) - int(p1) <= 1024):
                    if self._is_ip_in_approved_range(p1) and self._is_ip_in_approved_range(p2):
                        return self._is_ip_in_approved_range(p1)
        except Exception:
            return None
        return None

    def _load_config(self) -> Dict[str, Any]:
        """Loads target authorization allowlist from configuration file."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                raise RuntimeError(f"Failed to load authorization config from {self.config_path}: {e}")
        return {
            "default_target": "192.168.56.111",
            "authorized_targets": [
                {
                  "target": "192.168.56.111",
                  "target_type": "ipv4",
                  "name": "Authorized Lab Host",
                  "category": "intentionally_vulnerable_lab",
                  "authorization_status": "AUTHORIZED_LOCAL_LAB",
                  "scope": "Private Authorized Scope",
                  "permitted_profiles": ["lab-basic", "lab-safe-minimal", "lab-common-services"],
                  "allowed_ports": "1-65535",
                  "operator": "asip_ali"
                }
            ],
            "rules": {
                "allow_cidr_ranges": False,
                "allow_public_ips": False,
                "allow_unlisted_targets": False,
                "require_explicit_authorization": True
            }
        }

    def validate_target_syntax(self, target: str) -> Tuple[str, str]:
        """
        Validates target format.
        Rejects CIDR notations, URLs, shell characters, and invalid syntaxes.
        Returns: (clean_target, target_type) where target_type is 'ipv4', 'ipv6', or 'hostname'.
        """
        if not target or not isinstance(target, str):
            raise TargetSyntaxError("Target must be a non-empty string.")

        clean = target.strip()

        # Reject URL prefixes
        if clean.lower().startswith(("http://", "https://", "ftp://", "ssh://")):
            raise TargetSyntaxError(f"Target '{target}' contains URL protocol scheme. Specify host/IP only.")

        # Reject CIDR ranges (prohibit broad network sweeps)
        if "/" in clean:
            raise TargetSyntaxError(
                f"Target '{target}' contains CIDR range notation. "
                "Arbitrary subnet scanning and CIDR ranges are strictly forbidden."
            )

        # Reject shell metacharacters and suspicious control sequences
        if any(c in clean for c in [";", "&", "|", "`", "$", " ", "\t", "\n", "\r", ">", "<", "\"", "'", "\\"]):
            raise TargetSyntaxError(f"Target '{target}' contains invalid or unsafe shell characters.")

        # Remove port if specified as host:port
        clean = clean.split(":")[0]

        # 1. Check IP address
        try:
            ip_obj = ipaddress.ip_address(clean)
            target_type = "ipv4" if ip_obj.version == 4 else "ipv6"

            # Check if public IP and rule forbids public scanning
            if not self.rules.get("allow_public_ips", False) and not (ip_obj.is_private or ip_obj.is_loopback):
                raise TargetAuthorizationError(
                    f"Target IP '{clean}' is a public routable address. "
                    "Active reconnaissance against unauthorized public internet infrastructure is strictly prohibited."
                )

            return clean, target_type
        except ValueError:
            pass  # Not an IP address, proceed to hostname check

        # 2. Hostname validation (RFC 1123)
        hostname_regex = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if not re.match(hostname_regex, clean) and clean != "localhost":
            raise TargetSyntaxError(f"Invalid target IP address or hostname format: '{clean}'")

        # Public hostname check
        if not self.rules.get("allow_public_ips", False):
            raise TargetAuthorizationError(
                f"Target hostname '{clean}' resolves to or represents external infrastructure. "
                "Active reconnaissance is strictly confined to authorized local lab targets."
            )

        return clean.lower(), "hostname"

    def authorize_campaign_targets(
        self,
        targets: List[str],
        scope_mode: str = "combined",
        excluded_targets: Optional[str] = None,
        explicit_authorization: bool = False,
        operator: str = "asip_ali"
    ) -> Dict[str, Any]:
        """
        Validates and authorizes one or more campaign targets according to the selected
        reconnaissance scope mode:
        - 'passive': Pure external OSINT / DNS / WHOIS / RDAP / CT lookups. Permits valid domains and IPs when explicitly scoped.
        - 'active' / 'vulnerability' / 'combined': Strict target authorization! Only allows:
            1) Explicit allowlisted lab/host targets (config/target_authorization.json),
            2) IPs or subnets strictly inside Admin-approved private lab ranges (requires explicit_authorization=True),
            3) Domains explicitly registered in Admin-approved authorized_domains (requires explicit_authorization=True).
          Public IPs not allowlisted (e.g. 8.8.8.8) or arbitrary unlisted CIDR ranges are ALWAYS rejected.
        """
        if not targets:
            raise TargetSyntaxError("At least one target must be specified.")

        clean_exclusions = {
            e.strip().lower() for e in (excluded_targets or "").split(",") if e.strip()
        }

        mode = (scope_mode or "combined").strip().lower()
        passive_only = mode in ("passive", "passive_osint", "passive_only")
        draft_only = mode == "draft"

        validated_targets: List[Dict[str, str]] = []
        hostname_regex = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

        for raw in targets:
            clean = (raw or "").strip()
            if not clean:
                continue

            # Common safety checks against URLs, wildcards, shell metacharacters
            if clean.lower().startswith(("http://", "https://", "ftp://", "ssh://")):
                raise TargetSyntaxError(f"Target '{raw}' contains URL protocol scheme. Specify domain or IP only.")
            if "*" in clean:
                raise TargetSyntaxError(f"Wildcard targets ('{raw}') are not permitted.")
            if any(c in clean for c in [";", "&", "|", "`", "$", " ", "\t", "\n", "\r", ">", "<", "\"", "'", "\\"]):
                raise TargetSyntaxError(f"Target '{raw}' contains unsafe characters.")

            if clean.lower() in clean_exclusions:
                raise TargetAuthorizationError(f"Target '{clean}' is listed in excluded targets.")

            # Strip optional host:port only for host/IP parsing
            host_only = clean.split(":")[0] if ":" in clean and "/" not in clean and "-" not in clean else clean

            # Case 1: IP Range / CIDR
            if "/" in clean or (re.match(r"^\d{1,3}(?:\.\d{1,3}){3}-\d{1,3}(?:\.\d{1,3}){3}$", clean)):
                # Verify valid CIDR or valid start-end IPv4 ordering
                if "/" in clean:
                    try:
                        ipaddress.ip_network(clean, strict=False)
                    except ValueError:
                        raise TargetSyntaxError(f"Invalid CIDR range format: '{clean}'.")
                else:
                    start_s, end_s = clean.split("-", 1)
                    try:
                        if int(ipaddress.IPv4Address(start_s)) > int(ipaddress.IPv4Address(end_s)):
                            raise TargetSyntaxError(f"Invalid IP range bounds: '{clean}'.")
                    except ValueError:
                        raise TargetSyntaxError(f"Invalid IPv4 range format: '{clean}'.")

                if draft_only:
                    validated_targets.append({
                        "target": clean,
                        "target_type": "range",
                        "scope_basis": "Draft Scope (Pending Scan Configuration)"
                    })
                    continue
                if passive_only:
                    raise TargetSyntaxError(f"Passive OSINT targets should be individual domains, hostnames, or single IPs ('{clean}').")
                if not explicit_authorization:
                    raise TargetAuthorizationError("Scanning an approved IP range requires explicit authorization confirmation.")
                covered = self._is_range_covered_by_approved(clean)
                if not covered:
                    raise TargetAuthorizationError(
                        f"Target range '{clean}' is NOT within any Admin-approved network range. "
                        "Arbitrary CIDR or network range scanning is prohibited."
                    )
                validated_targets.append({
                    "target": clean,
                    "target_type": "range",
                    "scope_basis": "Approved Network Scope"
                })
                continue

            # Case 2: Single IPv4 / IPv6
            ip_obj = None
            try:
                ip_obj = ipaddress.ip_address(host_only)
            except ValueError:
                ip_obj = None

            if ip_obj is not None:
                ttype = "ipv4" if ip_obj.version == 4 else "ipv6"
                allow_entry = next((item for item in self.authorized_targets if item.get("target") == host_only), None)
                approved_rng = self._is_ip_in_approved_range(ip_obj)

                if draft_only:
                    validated_targets.append({
                        "target": host_only,
                        "target_type": ttype,
                        "scope_basis": "Draft Scope (Pending Scan Configuration)"
                    })
                    continue

                if passive_only:
                    validated_targets.append({
                        "target": host_only,
                        "target_type": ttype,
                        "scope_basis": "Authorized Scope Target" if allow_entry else "Explicit Passive OSINT Scope"
                    })
                    continue

                if allow_entry:
                    validated_targets.append({
                        "target": host_only,
                        "target_type": ttype,
                        "scope_basis": "Explicit Allowlisted Target"
                    })
                    continue

                if approved_rng and explicit_authorization and (ip_obj.is_private or ip_obj.is_loopback):
                    validated_targets.append({
                        "target": host_only,
                        "target_type": ttype,
                        "scope_basis": "Approved Network Scope"
                    })
                    continue

                raise TargetAuthorizationError(
                    f"Target IP '{host_only}' is NOT authorized for active or vulnerability scanning. "
                    f"Public internet hosts and unlisted targets require explicit Admin authorization."
                )

            # Case 3: Domain / Hostname
            lower_host = host_only.lower()
            if not re.match(hostname_regex, lower_host) and lower_host != "localhost":
                raise TargetSyntaxError(f"Invalid target IP address, range, or domain format: '{clean}'.")

            if draft_only:
                validated_targets.append({
                    "target": lower_host,
                    "target_type": "domain" if "." in lower_host else "hostname",
                    "scope_basis": "Draft Scope (Pending Scan Configuration)"
                })
                continue

            if passive_only:
                validated_targets.append({
                    "target": lower_host,
                    "target_type": "domain" if "." in lower_host else "hostname",
                    "scope_basis": "Passive OSINT Public Intelligence"
                })
                continue

            # Active/Vuln/Combined on domain/hostname requires allowlist or admin authorized_domains + confirmation
            allow_entry = next((item for item in self.authorized_targets if item.get("target", "").lower() == lower_host), None)
            domain_entry = next(
                (d for d in self.authorized_domains if d.get("domain", "").lower() == lower_host or lower_host.endswith("." + d.get("domain", "").lower())),
                None
            )
            if allow_entry or (domain_entry and explicit_authorization) or (lower_host == "localhost" and explicit_authorization):
                validated_targets.append({
                    "target": lower_host,
                    "target_type": "domain" if "." in lower_host else "hostname",
                    "scope_basis": "Admin-Authorized Domain" if domain_entry else "Explicit Allowlisted Target"
                })
                continue

            raise TargetAuthorizationError(
                f"Domain '{lower_host}' is NOT authorized for active scanning or vulnerability probing. "
                "Add the domain in Admin Scope Settings or select Passive Reconnaissance only."
            )

        if not validated_targets:
            raise TargetSyntaxError("No valid targets remained after validation.")

        return {
            "targets": validated_targets,
            "primary_target": validated_targets[0]["target"],
            "primary_type": validated_targets[0]["target_type"],
            "scope_mode": mode,
            "operator": operator,
            "timestamp_utc": datetime.now(timezone.utc).isoformat()
        }

    def authorize_target(
        self,
        target: Optional[str] = None,
        profile: str = "lab-basic",
        operator: str = "asip_ali",
        investigation_id: Optional[str] = None,
        repo: Optional[Any] = None
    ) -> TargetAuthorizationRecord:
        """
        Enforces target authorization against explicit configuration allowlist and
        optional investigation-specific database target registration.
        Generates and returns a signed TargetAuthorizationRecord.
        """
        # Default to initial lab target if none provided
        effective_target = target.strip() if target else self.default_target

        # If repo and investigation_id are provided, check DB-registered authorized targets first
        db_entry = None
        if repo is not None and investigation_id is not None:
            inv_targets = repo.list_authorized_targets(investigation_id=investigation_id)
            db_entry = next((item for item in inv_targets if item.get("target", "").lower() == effective_target.lower()), None)

        # Validate syntax and safety (allow approved range/domain when backed by DB campaign registration)
        if db_entry:
            clean_target = db_entry.get("target", effective_target)
            # Still enforce shell safety and exclusion against public IP rules if unlisted
            if any(c in clean_target for c in [";", "&", "|", "`", "$", " ", "\t", "\n", "\r", ">", "<", "\"", "'", "\\"]):
                raise TargetSyntaxError(f"Target '{clean_target}' contains invalid or unsafe shell characters.")
        else:
            clean_target, target_type = self.validate_target_syntax(effective_target)

        if repo is not None and investigation_id is not None and not db_entry:
            raise TargetAuthorizationError(
                f"Target '{clean_target}' is NOT registered as an authorized target under investigation '{investigation_id}'. "
                "Target must be explicitly added to the investigation before active reconnaissance can be launched."
            )

        # Match against allowlist
        entry = next((item for item in self.authorized_targets if item.get("target") == clean_target), None)
        if not entry and not db_entry:
            raise TargetAuthorizationError(
                f"Target '{clean_target}' is NOT in the authorized active reconnaissance allowlist.\n"
                f"Authorized lab targets: {[t.get('target') for t in self.authorized_targets]}.\n"
                "To scan a target, it must be explicitly configured in config/target_authorization.json."
            )

        permitted_profiles = ["lab-basic"]
        if db_entry:
            permitted_profiles_raw = db_entry.get("permitted_profiles", "lab-basic")
            if isinstance(permitted_profiles_raw, list):
                permitted_profiles = permitted_profiles_raw
            else:
                permitted_profiles = [p.strip() for p in str(permitted_profiles_raw).split(",") if p.strip()]
        elif entry:
            permitted_profiles = entry.get("permitted_profiles", ["lab-basic"])

        if profile not in permitted_profiles and profile != "default":
            raise TargetAuthorizationError(
                f"Scan profile '{profile}' is not authorized for target '{clean_target}'.\n"
                f"Permitted profiles for this target: {permitted_profiles}"
            )

        auth_status = "AUTHORIZED_LOCAL_LAB"
        category = "intentionally_vulnerable_lab"
        scope = f"{clean_target} scope"
        notes = None

        if db_entry:
            auth_status = db_entry.get("authorization_status", "AUTHORIZED_LOCAL_LAB")
            scope = db_entry.get("scope", scope)
            operator = db_entry.get("authorized_by", operator)
        elif entry:
            auth_status = entry.get("authorization_status", "AUTHORIZED_LOCAL_LAB")
            category = entry.get("category", "intentionally_vulnerable_lab")
            scope = entry.get("scope", scope)
            notes = entry.get("notes")

        return TargetAuthorizationRecord(
            target=clean_target,
            authorized=True,
            authorization_status=auth_status,
            category=category,
            scope=scope,
            permitted_profiles=permitted_profiles,
            scan_profile=profile,
            operator=operator,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            notes=notes
        )

    @staticmethod
    def verify_target_connectivity(target: str, timeout: float = 1.5) -> Tuple[bool, str]:
        """
        Checks whether target host is responsive on the network.
        CRITICAL: A responsive target does NOT imply authorization.
        Authorization must always be verified first.
        """
        # Non-destructive TCP probe on common ports
        for test_port in [22, 80, 21, 23, 445]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                res = s.connect_ex((target, test_port))
                s.close()
                if res == 0:
                    return True, f"Target {target} is UP (responding on TCP port {test_port})"
            except Exception:
                pass

        # Try ICMP ping probe (1 packet)
        try:
            res = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(timeout)), target],
                capture_output=True,
                text=True,
                timeout=timeout + 1
            )
            if res.returncode == 0:
                return True, f"Target {target} is UP (responding to ICMP echo)"
        except Exception:
            pass

        return False, f"Target {target} is UNREACHABLE or OFFLINE (no TCP handshake or ICMP echo received)"

