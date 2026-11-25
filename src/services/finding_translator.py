"""
FootprintIQ - Finding Translator & Plain-Language Intelligence Service
Generates accurate, non-fabricated, human-readable explanations and
prioritized remediations directly from recorded scan findings.
"""

from typing import Dict, Any, List


_CONF_TEXT_MAP = {"confirmed": 0.95, "verified": 0.95, "high": 0.85, "medium": 0.65, "low": 0.35}


def parse_confidence_score(raw: Any, default: float = 0.0) -> float:
    """Converts numeric or textual confidence labels ('high', 'medium', 'low') to 0.0-1.0."""
    if raw is None or raw == "":
        return default
    if isinstance(raw, (int, float)):
        val = float(raw)
        return val / 100.0 if val > 1.0 else val
    s = str(raw).strip().lower()
    if s in _CONF_TEXT_MAP:
        return _CONF_TEXT_MAP[s]
    try:
        val = float(s.rstrip("%"))
        return val / 100.0 if (val > 1.0 or s.endswith("%")) else val
    except ValueError:
        return default


def classify_confidence(finding: Dict[str, Any]) -> str:
    """
    Returns evidence classification label preserving the strict distinction between
    an automated scanner matcher hit ('Observed Scanner Match') and an independently
    verified/confirmed vulnerability ('Confirmed Vulnerability').
    """
    ver = str(finding.get("verification_status") or "").strip().lower()
    sev = str(finding.get("severity") or "Informational").strip().lower()
    src = str(finding.get("detection_source") or "").strip().lower()
    conf = parse_confidence_score(finding.get("confidence"), default=0.0)

    if ver in ("false_positive", "marked_false_positive"):
        return "Marked False Positive"
    if sev in ("informational", "info"):
        return "Informational Observation"
    if ver in ("verified", "confirmed"):
        return "Confirmed Vulnerability"
    if src in ("nessus", "nuclei", "nmap_nse", "nse", "openvas", "greenbone") and (
        ver == "observed" or conf >= 0.80
    ):
        return "Observed Scanner Match"
    if src in ("nessus", "nuclei", "nmap_nse", "nse", "openvas", "greenbone") and conf >= 0.50:
        return "Potential Vulnerability"
    return "Unverified / Informational"


def explain_finding_plain_language(finding: Dict[str, Any]) -> Dict[str, str]:
    """
    Translates any vulnerability or service finding into the 5 clear questions
    required by executives and beginners without fabricating missing specifics.
    """
    title = str(finding.get("title") or "Security Observation")
    target = str(finding.get("target_ip") or "target host")
    port = finding.get("port")
    proto = str(finding.get("protocol") or "tcp").upper()
    service = str(finding.get("service") or "network service")
    version = str(finding.get("service_version") or "").strip()
    sev = str(finding.get("severity") or "Medium")
    cve = str(finding.get("cve_identifiers") or "").strip()
    desc = str(finding.get("description") or "").strip()
    remed = str(finding.get("remediation") or "").strip()
    confidence_label = classify_confidence(finding)

    port_phrase = f"on {proto} port {port}" if port else "on the target system"
    svc_phrase = f"{service} ({version})" if version else service

    # 1. What was discovered
    if confidence_label == "Observed Scanner Match":
        discovered = (
            f"Automated scanner signature matched {title} on {target} {port_phrase} running {svc_phrase} "
            "(matcher hit recorded; independent exploitability has not yet been manually verified)."
        )
    elif confidence_label == "Confirmed Vulnerability":
        discovered = f"Verified vulnerability {title} on {target} {port_phrase} running {svc_phrase}."
    else:
        discovered = f"{title} was observed on {target} {port_phrase} running {svc_phrase}."
    if cve:
        discovered += f" Associated CVE reference: {cve}."

    # 2. Why it is important
    t_low = f"{title} {service} {desc}".lower()
    if any(k in t_low for k in ("backdoor", "remote code execution", "rce", "command execution", "shell", "eternalblue", "ms17-010")):
        why = "This issue can let an attacker execute commands remotely on the affected system without normal authentication."
    elif any(k in t_low for k in ("cleartext", "telnet", "ftp", "http-only", "unencrypted", "sslv", "tls 1.0", "weak cipher")):
        why = "Unencrypted or deprecated transport protocols allow network observers to intercept credentials or sensitive data."
    elif any(k in t_low for k in ("smb", "mysql", "postgresql", "database", "anonymous", "default credential")):
        why = "Exposed management, file-sharing, or database services create direct entry points for unauthorized data access."
    elif any(k in t_low for k in ("header", "hsts", "csp", "x-frame", "cookie", "clickjacking")):
        why = "Missing defensive HTTP headers weaken browser protections for users interacting with the web service."
    elif sev.lower() == "informational":
        why = "This observation documents exposed functionality or software metadata useful for reducing unnecessary attack surface."
    else:
        why = desc[:220] if desc else "This weakness reduces the defensive boundary around the exposed network service."

    # 3. Potential impact
    if sev.lower() == "critical":
        impact = "Severe risk: Full system compromise, unauthorized administrative control, or exposure of sensitive assets."
    elif sev.lower() == "high":
        impact = "High risk: Unauthorized access to system services, sensitive data disclosure, or significant disruption."
    elif sev.lower() == "medium":
        impact = "Moderate risk: Partial information disclosure, weaker transport protection, or service hardening gap."
    elif sev.lower() == "low":
        impact = "Low risk: Minor configuration leakage that can assist attackers during reconnaissance."
    else:
        impact = "Informational: Direct exploitation is unlikely alone, but reducing unused services improves security posture."

    # 4. Recommended action
    if remed and len(remed) > 8:
        action = remed
    elif any(k in t_low for k in ("telnet", "rlogin", "rsh", "rexec")):
        action = "Disable legacy cleartext remote login daemons and use encrypted SSH instead."
    elif any(k in t_low for k in ("ssl", "tls", "cipher", "heartbleed", "poodle")):
        action = "Upgrade TLS libraries, disable SSLv2/SSLv3/TLS 1.0/1.1 and weak ciphers, and install trusted certificates."
    elif any(k in t_low for k in ("mysql", "postgresql", "database")):
        action = "Bind database listeners to localhost or restrict network access strictly to authorized application hosts."
    else:
        action = f"Review {svc_phrase} exposure {port_phrase}, apply vendor patches or restrict access via host firewall rules."

    return {
        "what_discovered": discovered,
        "why_important": why,
        "potential_impact": impact,
        "seriousness": sev,
        "confidence_label": confidence_label,
        "recommended_action": action
    }


def build_dynamic_remediation_roadmap(findings: List[Dict[str, Any]], failed_scanners: List[str] = None) -> List[str]:
    """Builds dynamic remediation priorities based strictly on actual findings (never hardcoded vsftpd unless present)."""
    roadmap: List[str] = []
    if not findings:
        if failed_scanners:
            roadmap.append(
                f"Incomplete visibility: {', '.join(failed_scanners)} did not complete successfully. Resolve scanner availability and re-run assessment before declaring clean posture."
            )
        else:
            roadmap.append("Maintain periodic scheduled reviews and disable any unnecessary exposed network services.")
        return roadmap

    crit = [f for f in findings if str(f.get("severity", "")).lower() == "critical"]
    high = [f for f in findings if str(f.get("severity", "")).lower() == "high"]
    med = [f for f in findings if str(f.get("severity", "")).lower() == "medium"]

    if crit:
        sample = ", ".join(sorted(set(f.get("title", "Critical issue")[:55] for f in crit[:3])))
        roadmap.append(f"Immediate Priority ({len(crit)} Critical): Isolate or patch critical exposures immediately ({sample}).")
    if high:
        sample = ", ".join(sorted(set(f.get("title", "High issue")[:55] for f in high[:3])))
        roadmap.append(f"High Priority ({len(high)} High): Remediate high-severity vulnerabilities and enforce strict access controls ({sample}).")
    if med:
        roadmap.append(f"Moderate Priority ({len(med)} Medium): Address hardening gaps, TLS/protocol upgrades, and configuration weaknesses.")

    if failed_scanners:
        roadmap.append(f"Coverage Notice: {', '.join(failed_scanners)} reported unavailability or errors; re-verify once resolved.")

    return roadmap

