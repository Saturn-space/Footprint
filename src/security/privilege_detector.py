"""
FootprintIQ - Privilege Consent & Authorization (PSA) Privilege Detector
Provides strict backend-enforced detection of operations requiring elevated privileges
(such as raw socket packet crafting, SYN scans, OS fingerprinting, and UDP scanning),
and computes safe unprivileged fallback configurations (Scenario A).
"""

from typing import Dict, Any, List, Tuple
from dataclasses import dataclass, field
import copy
import logging

logger = logging.getLogger("FootprintIQ.PrivilegeDetector")

# Operations and flags that strictly require elevated raw-socket / network capabilities
PRIVILEGED_OPERATIONS = {
    "tcp_syn": {
        "label": "TCP SYN Stealth Scan (-sS)",
        "flag": "-sS",
        "description": "Raw packet TCP SYN scanning requires elevated packet privileges (cap_net_raw or root).",
        "fallback_option": "tcp_connect",
        "fallback_label": "TCP Connect Scan (-sT)",
    },
    "udp_scan": {
        "label": "UDP Port Scanning (-sU)",
        "flag": "-sU",
        "description": "UDP probe generation and ICMP port-unreachable parsing require raw socket access.",
        "fallback_option": None,
        "fallback_label": "Omit UDP Scan (Safe TCP Only)",
    },
    "os_detection": {
        "label": "TCP/IP OS Fingerprinting (-O)",
        "flag": "-O",
        "description": "Operating system TCP/IP stack fingerprinting requires raw packet inspection.",
        "fallback_option": False,
        "fallback_label": "Skip OS Fingerprinting",
    },
    "arp_discovery": {
        "label": "ARP Host Discovery (-PR)",
        "flag": "-PR",
        "description": "Local data-link layer ARP frames require raw packet injection.",
        "fallback_option": "ping_discovery",
        "fallback_label": "Safe ICMP/TCP Ping Discovery",
    },
}

# Approved NSE scripts requiring raw-socket packet crafting
PRIVILEGED_NSE_SCRIPTS = {
    "traceroute-geolocation",
    "broadcast-ping",
    "broadcast-dhcp-discover",
    "sniffer-detect",
    "ipidseq",
    "firewalk",
}


@dataclass
class PrivilegeAnalysis:
    requires_privilege: bool
    privileged_reasons: List[str] = field(default_factory=list)
    privileged_operations: List[str] = field(default_factory=list)
    sanitized_config: Dict[str, Any] = field(default_factory=dict)
    skipped_operations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requires_privilege": self.requires_privilege,
            "privileged_reasons": self.privileged_reasons,
            "privileged_operations": self.privileged_operations,
            "skipped_operations": self.skipped_operations,
        }


class PrivilegeDetector:
    """
    Evaluates scan configurations strictly on the server side.
    Never trusts frontend claims regarding privilege necessity.
    """

    @classmethod
    def analyze_scan_config(
        cls,
        scan_config: Dict[str, Any],
        scan_type: str = "combined"
    ) -> PrivilegeAnalysis:
        cfg = copy.deepcopy(scan_config or {})
        reasons: List[str] = []
        ops: List[str] = []
        skipped: List[str] = []

        categories = [str(c).lower() for c in (cfg.get("selected_categories") or [])]
        active_cfg = cfg.get("active") or {}
        vuln_cfg = cfg.get("vulnerability") or {}

        # Passive recon never requires elevated privileges
        check_active = ("active" in categories) or (not categories and scan_type in ("network_discovery", "nmap_services", "combined"))
        check_vuln = ("vulnerability" in categories) or (not categories and scan_type in ("nmap_nse", "nuclei", "nessus", "combined"))

        # 1. Active Recon Inspection
        if check_active and isinstance(active_cfg, dict):
            # TCP scan type
            tcp_type = str(active_cfg.get("tcp_scan_type", "")).strip().lower()
            if tcp_type == "tcp_syn":
                reasons.append(PRIVILEGED_OPERATIONS["tcp_syn"]["description"])
                ops.append("tcp_syn")
                active_cfg["tcp_scan_type"] = "tcp_connect"
                skipped.append("TCP SYN scan (-sS) downgraded to unprivileged TCP Connect (-sT)")

            # UDP Scanning
            port_mode = str(active_cfg.get("port_mode", "")).strip().lower()
            udp_mode = str(active_cfg.get("udp_port_mode", "none")).strip().lower()
            udp_enabled = bool(active_cfg.get("udp_scan")) or (udp_mode not in ("", "none", "udp_none")) or (port_mode == "udp_only")

            if udp_enabled:
                reasons.append(PRIVILEGED_OPERATIONS["udp_scan"]["description"])
                ops.append("udp_scan")
                active_cfg["udp_scan"] = False
                active_cfg["udp_port_mode"] = "none"
                if port_mode == "udp_only":
                    active_cfg["port_mode"] = "top_100"
                skipped.append("UDP port scanning (-sU) skipped in unprivileged mode")

            # OS Detection
            if bool(active_cfg.get("os_detection")):
                reasons.append(PRIVILEGED_OPERATIONS["os_detection"]["description"])
                ops.append("os_detection")
                active_cfg["os_detection"] = False
                skipped.append("OS fingerprinting (-O) skipped in unprivileged mode")

            # ARP Discovery
            disco = str(active_cfg.get("host_discovery", "")).strip().lower()
            if disco == "arp_discovery":
                reasons.append(PRIVILEGED_OPERATIONS["arp_discovery"]["description"])
                ops.append("arp_discovery")
                active_cfg["host_discovery"] = "ping_discovery"
                skipped.append("ARP host discovery (-PR) switched to standard ICMP ping")

        # 2. Vulnerability Assessment Inspection (NSE raw scripts)
        if check_vuln and isinstance(vuln_cfg, dict):
            nse_scripts = vuln_cfg.get("nse_scripts") or []
            priv_scripts = [s for s in nse_scripts if str(s).strip().lower() in PRIVILEGED_NSE_SCRIPTS]
            if priv_scripts:
                desc = f"Privileged raw-packet NSE scripts requested: {', '.join(priv_scripts)}"
                reasons.append(desc)
                ops.append("privileged_nse_scripts")
                # Remove privileged scripts from sanitized fallback config
                vuln_cfg["nse_scripts"] = [s for s in nse_scripts if s not in priv_scripts]
                skipped.append(f"Privileged NSE script(s) skipped: {', '.join(priv_scripts)}")

        requires_privilege = len(ops) > 0
        cfg["active"] = active_cfg
        cfg["vulnerability"] = vuln_cfg

        return PrivilegeAnalysis(
            requires_privilege=requires_privilege,
            privileged_reasons=reasons,
            privileged_operations=ops,
            sanitized_config=cfg,
            skipped_operations=skipped
        )
