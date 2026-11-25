"""
FootprintIQ - ProjectDiscovery Nuclei Policy & Profile Governance Service
Enforces strict non-destructive scanning profiles, excluded dangerous tags/protocols,
target normalization, and safe subprocess argument construction for Nuclei.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

DEFAULT_TEMPLATES_CANDIDATES = (
    os.getenv("NUCLEI_TEMPLATES_DIR", "").strip(),
    os.path.expanduser("~/.local/nuclei-templates"),
    "/home/asip_ali/.local/nuclei-templates",
    "/root/.local/nuclei-templates",
    "/usr/share/nuclei-templates",
)

# Dangerous template tags and protocol types permanently blocked in FootprintIQ
EXCLUDED_NUCLEI_TAGS: Tuple[str, ...] = (
    "dos",
    "fuzz",
    "bruteforce",
    "intrusive",
    "exploit",
    "dast",
    "sqli",
    "credential-stuffing",
    "default-logins",
    "honeypot",
)

EXCLUDED_NUCLEI_PROTOCOLS: Tuple[str, ...] = (
    "code",
    "javascript",
    "headless",
)

ALLOWED_SEVERITIES: Tuple[str, ...] = ("info", "low", "medium", "high", "critical")

_SAFE_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
_SAFE_TEMPLATE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,90}$")
_UNSAFE_TARGET_CHARS_RE = re.compile(r"[\s;|&$`\"'<>\\(){}\[\]\r\n\t]")

# Curated, non-destructive assessment profiles mapped to real nuclei-templates subtrees/files
SAFE_NUCLEI_PROFILES: Dict[str, Dict[str, Any]] = {
    "http-security": {
        "label": "HTTP Security Posture & Headers",
        "description": "Audits missing security headers, insecure cookies, CSP wildcards, and HTTP-to-HTTPS hygiene.",
        "template_files": [
            "http/misconfiguration/http-missing-security-headers.yaml",
            "http/misconfiguration/cookies-without-httponly.yaml",
            "http/misconfiguration/cookies-without-secure.yaml",
            "http/misconfiguration/missing-cookie-samesite-strict.yaml",
            "http/misconfiguration/csp-script-src-wildcard.yaml",
            "http/misconfiguration/https-to-http-redirect.yaml",
        ],
        "template_subdirs": ["http/misconfiguration"],
        "use_files_over_subdir": True,
        "default_severities": ["info", "low", "medium", "high", "critical"],
        "default_tags": ["headers", "misconfig"],
        "requires_http": True,
        "recommended_timeout": 90,
    },
    "ssl-tls": {
        "label": "SSL / TLS Certificate & Cipher Audit",
        "description": "Evaluates deprecated TLS protocols, weak ciphers, expired/self-signed/mismatched certificates, and issuer trust.",
        "template_subdirs": ["ssl"],
        "default_severities": ["info", "low", "medium", "high", "critical"],
        "default_tags": ["ssl", "tls"],
        "requires_http": False,
        "recommended_timeout": 120,
    },
    "exposed-panels": {
        "label": "Exposed Admin Panels & Consoles",
        "description": "Safely identifies exposed administrative portals, dashboards, and management interfaces without brute force.",
        "template_subdirs": ["http/exposed-panels"],
        "default_severities": ["info", "low", "medium", "high", "critical"],
        "default_tags": ["panel", "login"],
        "requires_http": True,
        "recommended_timeout": 180,
    },
    "web-vuln-misconfig": {
        "label": "Web Vulnerabilities & Misconfigurations",
        "description": "Checks for server misconfigurations, directory listings, sensitive info exposures, and safe web vulnerability signatures.",
        "template_subdirs": ["http/misconfiguration", "http/exposures", "http/vulnerabilities"],
        "default_severities": ["low", "medium", "high", "critical"],
        "default_tags": ["misconfig", "exposure", "vuln"],
        "requires_http": True,
        "recommended_timeout": 240,
    },
    "safe-cve": {
        "label": "Verified Known CVE Detection",
        "description": "Matches known CVE fingerprints (Low to Critical) across exposed HTTP and network services excluding exploit/DoS/fuzz templates.",
        "template_subdirs": ["http/cves", "network/cves"],
        "default_severities": ["medium", "high", "critical"],
        "default_tags": ["cve"],
        "requires_http": True,
        "recommended_timeout": 300,
    },
    "safe-all": {
        "label": "Comprehensive Safe Nuclei Baseline",
        "description": "Balanced safe audit combining SSL/TLS, HTTP misconfigurations, exposed panels, sensitive exposures, and High/Critical CVEs.",
        "template_subdirs": [
            "ssl",
            "http/misconfiguration",
            "http/exposed-panels",
            "http/exposures",
            "http/cves",
        ],
        "default_severities": ["low", "medium", "high", "critical"],
        "default_tags": [],
        "requires_http": True,
        "recommended_timeout": 360,
    },
}

_COMMON_HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8088, 8888, 3000, 5000, 9000}
_COMMON_HTTPS_PORTS = {443, 8443, 8834, 9443, 4443, 10443}


def resolve_templates_dir(explicit_dir: Optional[str] = None) -> Optional[str]:
    """Finds an initialized ProjectDiscovery nuclei-templates directory."""
    candidates: List[str] = []
    if explicit_dir:
        candidates.append(explicit_dir.strip())
    candidates.extend(DEFAULT_TEMPLATES_CANDIDATES)
    for raw in candidates:
        if not raw:
            continue
        p = Path(os.path.expanduser(raw))
        if p.is_dir():
            # Verify it contains actual YAML templates rather than an empty folder
            for sub in ("http", "ssl", "dns", "network"):
                if (p / sub).is_dir():
                    return str(p.resolve())
    return None


def ensure_nuclei_ignore_file(templates_dir: Optional[str]) -> Optional[str]:
    """
    Ensures ~/.config/nuclei/.nuclei-ignore exists when present in the template store
    so Nuclei honors upstream false-positive exclusions cleanly without CLI stderr noise.
    """
    if not templates_dir:
        return None
    src_ignore = Path(templates_dir) / ".nuclei-ignore"
    cfg_dir = Path(os.path.expanduser("~/.config/nuclei"))
    dst_ignore = cfg_dir / ".nuclei-ignore"
    try:
        if src_ignore.is_file() and not dst_ignore.exists():
            cfg_dir.mkdir(parents=True, exist_ok=True)
            dst_ignore.write_bytes(src_ignore.read_bytes())
        if dst_ignore.is_file():
            return str(dst_ignore)
    except OSError:
        return str(src_ignore) if src_ignore.is_file() else None
    return None


class NucleiPolicyService:
    """Validates Nuclei profiles, severities, tags, targets, and command parameters."""

    @staticmethod
    def list_profiles() -> List[Dict[str, Any]]:
        """Returns metadata for UI and API consumption."""
        templates_dir = resolve_templates_dir()
        profiles = []
        for pid, meta in SAFE_NUCLEI_PROFILES.items():
            resolved_paths = NucleiPolicyService._resolve_profile_template_paths(
                pid, templates_dir=templates_dir
            )
            profiles.append({
                "id": pid,
                "label": meta["label"],
                "description": meta["description"],
                "default_severities": list(meta["default_severities"]),
                "default_tags": list(meta["default_tags"]),
                "excluded_tags": list(EXCLUDED_NUCLEI_TAGS),
                "excluded_protocols": list(EXCLUDED_NUCLEI_PROTOCOLS),
                "recommended_timeout": meta["recommended_timeout"],
                "templates_available": bool(resolved_paths),
                "template_sources_count": len(resolved_paths),
            })
        return profiles

    @staticmethod
    def inspect_templates_catalog(templates_dir: Optional[str] = None) -> Dict[str, Any]:
        """Inspects real installed nuclei-templates counts by category on disk."""
        tdir = resolve_templates_dir(templates_dir)
        if not tdir:
            return {
                "installed": False,
                "templates_dir": None,
                "total_templates": 0,
                "categories": {},
            }

        categories: Dict[str, int] = {}
        total = 0
        category_paths = {
            "cves": os.path.join(tdir, "http", "cves"),
            "vulnerabilities": os.path.join(tdir, "http", "vulnerabilities"),
            "misconfiguration": os.path.join(tdir, "http", "misconfiguration"),
            "exposed_panels": os.path.join(tdir, "http", "exposed-panels"),
            "exposures": os.path.join(tdir, "http", "exposures"),
            "ssl": os.path.join(tdir, "ssl"),
            "dns": os.path.join(tdir, "dns"),
            "network": os.path.join(tdir, "network"),
        }
        for key, path in category_paths.items():
            cnt = 0
            if os.path.isdir(path):
                for _root, _dirs, files in os.walk(path):
                    cnt += sum(1 for f in files if f.endswith((".yaml", ".yml")))
            categories[key] = cnt
            total += cnt

        return {
            "installed": total > 0,
            "templates_dir": tdir,
            "total_templates": total,
            "categories": categories,
        }

    @staticmethod
    def validate_profile(profile: Optional[str]) -> str:
        """Validates a requested Nuclei profile against SAFE_NUCLEI_PROFILES."""
        prof = (profile or "http-security").strip().lower()
        if prof not in SAFE_NUCLEI_PROFILES:
            raise ValueError(
                f"Unsupported Nuclei profile '{prof}'. Allowed profiles: {', '.join(SAFE_NUCLEI_PROFILES.keys())}"
            )
        return prof

    @staticmethod
    def validate_severities(severities: Optional[List[str]], profile: str) -> List[str]:
        """Normalizes and validates Nuclei severity filters."""
        if not severities:
            return list(SAFE_NUCLEI_PROFILES[profile]["default_severities"])
        cleaned: List[str] = []
        for s in severities:
            val = str(s).strip().lower()
            if val == "informational":
                val = "info"
            if val not in ALLOWED_SEVERITIES:
                raise ValueError(f"Invalid Nuclei severity '{s}'. Allowed: {', '.join(ALLOWED_SEVERITIES)}")
            if val not in cleaned:
                cleaned.append(val)
        return cleaned

    @staticmethod
    def validate_tags(tags: Optional[List[str]]) -> List[str]:
        """Validates custom safe filter tags and blocks excluded intrusive tags."""
        if not tags:
            return []
        cleaned: List[str] = []
        excluded_set = set(EXCLUDED_NUCLEI_TAGS)
        for t in tags:
            val = str(t).strip().lower()
            if not val:
                continue
            if not _SAFE_TAG_RE.match(val):
                raise ValueError(f"Unsafe or malformed Nuclei tag '{t}'.")
            if val in excluded_set:
                raise ValueError(f"Tag '{val}' is permanently prohibited by FootprintIQ safety policy.")
            if val not in cleaned:
                cleaned.append(val)
        return cleaned

    @staticmethod
    def validate_template_ids(template_ids: Optional[List[str]], templates_dir: Optional[str]) -> List[str]:
        """Validates explicit safe template YAML filenames or template IDs inside templates_dir."""
        if not template_ids:
            return []
        if not templates_dir:
            raise ValueError("Nuclei templates directory is unavailable on this host.")
        troot = Path(templates_dir).resolve()
        resolved: List[str] = []
        for raw in template_ids:
            val = str(raw).strip()
            if not val or ".." in val or val.startswith("/"):
                raise ValueError(f"Unsafe Nuclei template reference '{raw}'.")
            if "/" in val or val.endswith((".yaml", ".yml")):
                cand = (troot / val).resolve()
                if not str(cand).startswith(str(troot) + os.sep) or not cand.is_file():
                    raise ValueError(f"Template '{val}' does not exist in authorized templates store.")
                resolved.append(str(cand))
            elif _SAFE_TEMPLATE_ID_RE.match(val):
                # Search shallow safe subdirs for matching <id>.yaml
                matched = None
                for sub in ("http/misconfiguration", "http/exposed-panels", "http/exposures", "ssl", "http/cves"):
                    sub_path = troot / sub
                    if not sub_path.is_dir():
                        continue
                    for hit in sub_path.rglob(f"{val}.yaml"):
                        matched = hit.resolve()
                        break
                    if matched:
                        break
                if not matched:
                    raise ValueError(f"Template ID '{val}' was not found in safe Nuclei categories.")
                resolved.append(str(matched))
            else:
                raise ValueError(f"Invalid Nuclei template identifier '{raw}'.")
        return resolved

    @staticmethod
    def _resolve_profile_template_paths(
        profile: str,
        templates_dir: Optional[str] = None,
    ) -> List[str]:
        tdir = resolve_templates_dir(templates_dir)
        if not tdir:
            return []
        spec = SAFE_NUCLEI_PROFILES[profile]
        troot = Path(tdir).resolve()
        out: List[str] = []

        if spec.get("use_files_over_subdir") and spec.get("template_files"):
            for rel in spec["template_files"]:
                cand = (troot / rel).resolve()
                if cand.is_file():
                    out.append(str(cand))
            if out:
                return out

        for sub in spec.get("template_subdirs") or []:
            cand = (troot / sub).resolve()
            if cand.exists():
                out.append(str(cand))
        return out

    @staticmethod
    def normalize_target_for_auth(raw_target: str) -> str:
        """Extracts host/IP/domain from host or URL for TargetAuthorizer validation."""
        val = (raw_target or "").strip()
        if not val or _UNSAFE_TARGET_CHARS_RE.search(val):
            raise ValueError(f"Target '{raw_target}' contains disallowed characters or whitespace.")
        if "://" in val:
            parsed = urlparse(val)
            host = parsed.hostname
            if not host:
                raise ValueError(f"Malformed URL target '{raw_target}'.")
            return host.strip().lower()
        # Handle host:port
        if val.count(":") == 1 and not val.startswith("["):
            host_part, port_part = val.split(":", 1)
            if port_part.isdigit():
                return host_part.strip().lower()
        return val.strip().lower()

    @staticmethod
    def build_target_urls(
        target: str,
        discovered_ports: Optional[List[Dict[str, Any]]] = None,
        profile: str = "http-security",
    ) -> List[str]:
        """
        Normalizes an authorized target (URL, domain, IP, or host + Nmap ports)
        into clean, deduplicated concrete endpoints for Nuclei execution.
        """
        raw = (target or "").strip()
        if not raw or _UNSAFE_TARGET_CHARS_RE.search(raw):
            raise ValueError(f"Target '{target}' contains unsafe characters.")

        if "://" in raw:
            parsed = urlparse(raw)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise ValueError(f"Unsupported Nuclei target URL scheme or missing host: '{target}'.")
            return [raw.rstrip("/")]

        # Host:port literal
        if raw.count(":") == 1 and not raw.startswith("["):
            h, p_str = raw.split(":", 1)
            if p_str.isdigit():
                port_num = int(p_str)
                if not (1 <= port_num <= 65535):
                    raise ValueError(f"Invalid TCP port '{port_num}'.")
                if port_num in _COMMON_HTTPS_PORTS:
                    return [f"https://{h}:{port_num}"]
                if profile == "ssl-tls":
                    return [f"https://{h}:{port_num}"]
                return [f"http://{h}:{port_num}"]

        endpoints: List[str] = []
        matching_ports = [
            p for p in (discovered_ports or [])
            if str(p.get("target_ip") or p.get("ip") or p.get("host") or raw).strip().lower() == raw.lower()
            or not (p.get("target_ip") or p.get("ip"))
        ]

        for p in matching_ports:
            try:
                port_num = int(p.get("port"))
            except (TypeError, ValueError):
                continue
            if not (1 <= port_num <= 65535):
                continue
            svc = str(p.get("service") or "").lower()
            ver = str(p.get("service_version") or "").lower()
            if "https" in svc or "ssl" in svc or "tls" in svc or "ssl/" in ver or port_num in _COMMON_HTTPS_PORTS:
                url = f"https://{raw}" if port_num == 443 else f"https://{raw}:{port_num}"
                if url not in endpoints:
                    endpoints.append(url)
            elif "http" in svc or port_num in _COMMON_HTTP_PORTS:
                url = f"http://{raw}" if port_num == 80 else f"http://{raw}:{port_num}"
                if url not in endpoints:
                    endpoints.append(url)

        if not endpoints:
            if profile == "ssl-tls":
                endpoints = [f"https://{raw}"]
            else:
                endpoints = [f"https://{raw}", f"http://{raw}"]

        return endpoints

    @staticmethod
    def build_cli_arguments(
        binary_path: str,
        target_urls: List[str],
        jsonl_output_path: str,
        target_list_path: Optional[str] = None,
        profile: str = "http-security",
        severities: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        template_ids: Optional[List[str]] = None,
        templates_dir: Optional[str] = None,
        rate_limit: int = 30,
        concurrency: int = 10,
        request_timeout: int = 5,
    ) -> Tuple[List[str], Dict[str, Any]]:
        """
        Builds strict shell=False argv for Nuclei with enforced exclusion policies.
        Returns (argv, applied_policy_metadata).
        """
        prof = NucleiPolicyService.validate_profile(profile)
        tdir = resolve_templates_dir(templates_dir)
        if not tdir:
            raise ValueError("Nuclei templates store is not available on this host.")
        ensure_nuclei_ignore_file(tdir)

        sev_list = NucleiPolicyService.validate_severities(severities, prof)
        tag_list = NucleiPolicyService.validate_tags(tags)
        explicit_templates = NucleiPolicyService.validate_template_ids(template_ids, tdir)
        template_sources = explicit_templates or NucleiPolicyService._resolve_profile_template_paths(prof, tdir)
        if not template_sources:
            raise ValueError(f"No Nuclei templates found for profile '{prof}' in '{tdir}'.")

        safe_rl = max(1, min(int(rate_limit or 30), 100))
        safe_conc = max(1, min(int(concurrency or 10), 20))
        safe_req_to = max(2, min(int(request_timeout or 5), 15))

        argv: List[str] = [
            binary_path,
            "-duc",
            "-ni",
            "-silent",
            "-nc",
            "-or",
            "-ud", tdir,
            "-j",
            "-jle", jsonl_output_path,
            "-rl", str(safe_rl),
            "-c", str(safe_conc),
            "-timeout", str(safe_req_to),
            "-etags", ",".join(EXCLUDED_NUCLEI_TAGS),
            "-ept", ",".join(EXCLUDED_NUCLEI_PROTOCOLS),
            "-s", ",".join(sev_list),
        ]

        if len(target_urls) == 1:
            argv.extend(["-u", target_urls[0]])
        elif target_list_path:
            argv.extend(["-l", target_list_path])
        else:
            for u in target_urls:
                argv.extend(["-u", u])

        for tpath in template_sources:
            argv.extend(["-t", tpath])

        if tag_list:
            argv.extend(["-tags", ",".join(tag_list)])

        meta = {
            "profile": prof,
            "profile_label": SAFE_NUCLEI_PROFILES[prof]["label"],
            "templates_dir": tdir,
            "template_sources": template_sources,
            "severities": sev_list,
            "tags": tag_list,
            "excluded_tags": list(EXCLUDED_NUCLEI_TAGS),
            "excluded_protocols": list(EXCLUDED_NUCLEI_PROTOCOLS),
            "rate_limit": safe_rl,
            "concurrency": safe_conc,
            "target_urls": list(target_urls),
        }
        return argv, meta

