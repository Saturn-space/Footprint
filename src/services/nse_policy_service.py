"""
FootprintIQ - NSE Script Policy Service
Maintains approved script allowlists, enforces execution tiers (safe, discovery, vuln),
and prevents command injection or arbitrary intrusive script execution.
"""

import os
import re
from typing import List, Dict, Any, Tuple

# Approved scripts categorized by risk and purpose
APPROVED_NSE_SCRIPTS: Dict[str, Dict[str, Any]] = {
    # Discovery & Service Information (Safe)
    "banner": {
        "category": "discovery",
        "risk_tier": "safe",
        "safety_classification": "Safe Passive/Banner Read",
        "ports": "all",
        "description": "Reads initial service greeting banners from listening TCP ports.",
        "purpose": "Identify software names and exposed versions without exploit probes.",
        "expected_output": "Raw service banner text per open port."
    },
    "http-title": {
        "category": "discovery",
        "risk_tier": "safe",
        "safety_classification": "Safe Read-Only Probe",
        "ports": "80,443,8080,8180,3000",
        "description": "Fetches HTTP web root page <title> element.",
        "purpose": "Identify hosted web applications, admin consoles, or default pages.",
        "expected_output": "HTML page title and redirect target."
    },
    "http-headers": {
        "category": "discovery",
        "risk_tier": "safe",
        "safety_classification": "Safe Read-Only Probe",
        "ports": "80,443,8080,8180,3000",
        "description": "Inspects HTTP response headers.",
        "purpose": "Reveal server software, frameworks, cookies, and header configuration.",
        "expected_output": "HTTP status line and response headers."
    },
    "http-security-headers": {
        "category": "discovery",
        "risk_tier": "safe",
        "safety_classification": "Safe Read-Only Probe",
        "ports": "80,443,8080,8180",
        "description": "Checks presence and configuration of HTTP security headers (HSTS, CSP, XFO).",
        "purpose": "Identify missing browser defense headers on exposed web interfaces.",
        "expected_output": "Configured vs missing HTTP security headers."
    },
    "http-methods": {
        "category": "discovery",
        "risk_tier": "safe",
        "safety_classification": "Safe Enumeration",
        "ports": "80,443,8080,8180,3000",
        "description": "Finds supported HTTP request methods via OPTIONS probe.",
        "purpose": "Detect potentially risky enabled methods such as PUT, DELETE, or TRACE.",
        "expected_output": "Allowed HTTP methods per endpoint."
    },
    "ssl-cert": {
        "category": "discovery",
        "risk_tier": "safe",
        "safety_classification": "Safe Handshake Check",
        "ports": "443,8443,993,995",
        "description": "Retrieves SSL/TLS X.509 certificate metadata.",
        "purpose": "Inspect subject CN, issuer, expiration, self-signed status, and SANs.",
        "expected_output": "Certificate subject, issuer, validity dates, and fingerprint."
    },
    "ssl-enum-ciphers": {
        "category": "discovery",
        "risk_tier": "safe",
        "safety_classification": "Safe Handshake Check",
        "ports": "443,8443",
        "description": "Enumerates supported TLS/SSL protocol versions and cipher suites.",
        "purpose": "Identify deprecated SSLv3/TLS 1.0/1.1 protocols or weak ciphers.",
        "expected_output": "Supported protocols, cipher list, and security grade."
    },
    "dns-nsid": {
        "category": "discovery",
        "risk_tier": "safe",
        "safety_classification": "Safe Service Query",
        "ports": "53",
        "description": "Queries DNS Name Server Identifier (NSID) and version details.",
        "purpose": "Fingerprint DNS resolver/authoritative daemon metadata safely.",
        "expected_output": "DNS server version string / NSID identifier."
    },
    "dns-recursion": {
        "category": "discovery",
        "risk_tier": "safe",
        "safety_classification": "Safe Security Check",
        "ports": "53",
        "description": "Checks whether a DNS service permits open recursive queries.",
        "purpose": "Identify DNS resolvers exposed to amplification or cache abuse.",
        "expected_output": "Indicates if recursion appears enabled on port 53."
    },
    "ssh2-enum-algos": {
        "category": "discovery",
        "risk_tier": "safe",
        "safety_classification": "Safe Handshake Check",
        "ports": "22",
        "description": "Enumerates supported SSH key-exchange, encryption, and MAC algorithms.",
        "purpose": "Detect legacy CBC ciphers or weak SHA-1/Diffie-Hellman algorithms.",
        "expected_output": "Lists of SSH algorithms offered by the daemon."
    },
    "ftp-anon": {
        "category": "discovery",
        "risk_tier": "safe",
        "safety_classification": "Safe Configuration Check",
        "ports": "21",
        "description": "Checks whether anonymous FTP authentication is permitted.",
        "purpose": "Detect unauthenticated file server access.",
        "expected_output": "Login status and top-level directory listing if open."
    },
    "smb-os-discovery": {
        "category": "discovery",
        "risk_tier": "safe",
        "safety_classification": "Safe Enumeration",
        "ports": "139,445",
        "description": "Determines target OS, hostname, workgroup, and SMB dialect.",
        "purpose": "Identify Windows/Samba version and domain metadata.",
        "expected_output": "OS name, computer name, workgroup/domain, and SMB time."
    },
    "smb-security-mode": {
        "category": "discovery",
        "risk_tier": "safe",
        "safety_classification": "Safe Configuration Check",
        "ports": "139,445",
        "description": "Checks SMB message signing requirement and authentication mode.",
        "purpose": "Identify disabled SMB signing susceptible to relay attacks.",
        "expected_output": "Signing required/enabled status and guest account flags."
    },
    "mysql-info": {
        "category": "discovery",
        "risk_tier": "safe",
        "safety_classification": "Safe Handshake Check",
        "ports": "3306",
        "description": "Reads MySQL initial server greeting packet (version and capabilities).",
        "purpose": "Determine database engine version and TLS support.",
        "expected_output": "MySQL server version, protocol, and capability flags."
    },
    "postgresql-info": {
        "category": "discovery",
        "risk_tier": "safe",
        "safety_classification": "Safe Handshake Check",
        "ports": "5432",
        "description": "Reads PostgreSQL greeting status and authentication parameters (requires postgresql-info.nse if installed).",
        "purpose": "Confirm exposed PostgreSQL service configuration.",
        "expected_output": "Supported authentication modes and server status."
    },

    # Safe Vulnerability Detection Checks (Non-destructive)
    "ftp-vsftpd-backdoor": {
        "category": "vuln",
        "risk_tier": "vuln_check",
        "safety_classification": "Safe Non-Destructive Check",
        "ports": "21",
        "cve": "CVE-2011-2523",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Checks for vsftpd 2.3.4 Smiley Face Backdoor condition.",
        "purpose": "Verify known malicious backdoor trigger in compromised vsftpd 2.3.4 builds.",
        "expected_output": "Vulnerable / Not Vulnerable state with CVE reference."
    },
    "ssl-heartbleed": {
        "category": "vuln",
        "risk_tier": "vuln_check",
        "safety_classification": "Safe Non-Destructive Check",
        "ports": "443,8443",
        "cve": "CVE-2014-0160",
        "cvss": 7.5,
        "severity": "High",
        "description": "Checks OpenSSL TLS heartbeat out-of-bounds memory disclosure.",
        "purpose": "Identify Heartbleed vulnerability on TLS-enabled ports.",
        "expected_output": "Vulnerable / Not Vulnerable determination."
    },
    "ssl-poodle": {
        "category": "vuln",
        "risk_tier": "vuln_check",
        "safety_classification": "Safe Handshake Check",
        "ports": "443,8443",
        "cve": "CVE-2014-3566",
        "cvss": 4.3,
        "severity": "Medium",
        "description": "Checks for SSLv3 CBC ciphersuite downgrade vulnerability (POODLE).",
        "purpose": "Detect insecure SSLv3 fallback exposure.",
        "expected_output": "SSLv3 CBC acceptance check result."
    },
    "ssl-ccs-injection": {
        "category": "vuln",
        "risk_tier": "vuln_check",
        "safety_classification": "Safe Handshake Check",
        "ports": "443,8443",
        "cve": "CVE-2014-0224",
        "cvss": 6.8,
        "severity": "Medium",
        "description": "Checks for OpenSSL ChangeCipherSpec early-injection vulnerability.",
        "purpose": "Identify MITM downgrade flaw in legacy OpenSSL services.",
        "expected_output": "Vulnerable / Not Vulnerable result."
    },
    "smb-vuln-ms17-010": {
        "category": "vuln",
        "risk_tier": "vuln_check",
        "safety_classification": "Safe Non-Destructive Check",
        "ports": "445",
        "cve": "CVE-2017-0143",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Checks for SMBv1 remote code execution vulnerability (EternalBlue).",
        "purpose": "Safely test SMB status codes without triggering payload execution.",
        "expected_output": "MS17-010 status report and risk classification."
    },
    "smb-vuln-ms08-067": {
        "category": "vuln",
        "risk_tier": "vuln_check",
        "safety_classification": "Safe Non-Destructive Check",
        "ports": "139,445",
        "cve": "CVE-2008-4250",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Checks for legacy Windows Server RPC path vulnerability (MS08-067).",
        "purpose": "Detect unpatched NetPathCanonicalize SMB RPC exposure.",
        "expected_output": "MS08-067 check state."
    },
    "http-vuln-cve2014-3704": {
        "category": "vuln",
        "risk_tier": "vuln_check",
        "safety_classification": "Safe Non-Destructive Check",
        "ports": "80,443",
        "cve": "CVE-2014-3704",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Checks for Drupalgeddon SQL injection vulnerability.",
        "purpose": "Detect legacy Drupal 7 SQLi vulnerability signature.",
        "expected_output": "Detection indicator for vulnerable Drupal targets."
    }
}

# Strict script identifier regex to prevent command injection
SCRIPT_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]{2,50}$')


class NSEPolicyService:
    @staticmethod
    def get_allowed_scripts(category: str = "all") -> List[str]:
        """
        Returns list of script names in the specified category.
        """
        if category == "all":
            return list(APPROVED_NSE_SCRIPTS.keys())
        return [k for k, v in APPROVED_NSE_SCRIPTS.items() if v.get("category") == category]

    @staticmethod
    def validate_scripts(requested_scripts: List[str], allow_vuln_checks: bool = True) -> Tuple[List[str], List[str]]:
        """
        Validates requested script names against the allowlist and safety policy.
        Returns: (approved_list, rejected_list)
        """
        approved = []
        rejected = []

        for script in requested_scripts:
            clean_name = script.strip().lower()
            if not SCRIPT_NAME_REGEX.match(clean_name):
                rejected.append(f"{script} (invalid script name format)")
                continue

            if clean_name not in APPROVED_NSE_SCRIPTS:
                rejected.append(f"{script} (not on approved allowlist)")
                continue

            script_meta = APPROVED_NSE_SCRIPTS[clean_name]
            if script_meta.get("risk_tier") == "vuln_check" and not allow_vuln_checks:
                rejected.append(f"{script} (vulnerability check requires authorization)")
                continue

            approved.append(clean_name)

        return approved, rejected

    @staticmethod
    def get_script_metadata(script_name: str) -> Dict[str, Any]:
        return APPROVED_NSE_SCRIPTS.get(script_name.strip().lower(), {})

    @staticmethod
    def filter_installed_scripts(
        approved_scripts: List[str],
        scripts_dir: str = "/usr/share/nmap/scripts",
    ) -> Tuple[List[str], List[str]]:
        """
        Filters approved NSE scripts against actual installed `.nse` files when the
        system Nmap scripts directory is present, preventing one missing script from
        causing Nmap's Lua engine to abort all other valid scripts.
        """
        if not os.path.isdir(scripts_dir):
            return list(approved_scripts), []
        installed: List[str] = []
        missing: List[str] = []
        for s in approved_scripts:
            if os.path.isfile(os.path.join(scripts_dir, f"{s}.nse")):
                installed.append(s)
            else:
                missing.append(s)
        return installed, missing

