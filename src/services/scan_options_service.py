"""
FootprintIQ - Manual Reconnaissance Options & Real-Time Scanner Capabilities Catalog
Provides dynamically verified passive, active, NSE, ProjectDiscovery Nuclei, and Tenable Nessus options,
built-in presets, and honest runtime availability statuses.
"""

import os
import shutil
from typing import Dict, Any, List

from src.services.nse_policy_service import APPROVED_NSE_SCRIPTS
from src.services.nuclei_policy_service import NucleiPolicyService
from src.collectors.nmap_collector import NmapCollector, SUPPORTED_PROFILES
from src.collectors.nessus_collector import NessusCollector
from src.collectors.nuclei_collector import NucleiCollector


class ScanOptionsService:
    """Builds live capabilities, presets, and safe configuration catalogs for manual recon."""

    @staticmethod
    def get_passive_catalog() -> Dict[str, Any]:
        shodan_ok = bool((os.getenv("SHODAN_API_KEY") or "").strip())
        vt_ok = bool((os.getenv("VIRUSTOTAL_API_KEY") or "").strip())
        whois_ok = bool(shutil.which("whois"))
        harvester_ok = bool(shutil.which("theHarvester"))

        groups = {
            "domain_intelligence": {
                "title": "A. Domain Intelligence",
                "options": [
                    {
                        "id": "whois_lookup",
                        "label": "WHOIS Lookup",
                        "description": "Queries public registrar ownership records and registration dates.",
                        "expected_output": "Registrar, organization, creation/expiration dates, name servers.",
                        "interaction_type": "Pure Passive",
                        "available": True,
                        "availability_note": "System whois utility ready" if whois_ok else "Uses RDAP fallback"
                    },
                    {
                        "id": "rdap_lookup",
                        "label": "RDAP Lookup",
                        "description": "Queries structured Registration Data Access Protocol records.",
                        "expected_output": "Registry handle, netblock/domain status, entity contacts.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    },
                    {
                        "id": "dns_records",
                        "label": "DNS Record Enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA)",
                        "description": "Resolves authoritative public DNS resource records.",
                        "expected_output": "IP addresses, mail servers, nameservers, TXT policy records.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    },
                    {
                        "id": "dns_enumeration",
                        "label": "Extended DNS Zone Enumeration (SOA, CAA, SRV)",
                        "description": "Queries additional authoritative zone metadata and CAA policies.",
                        "expected_output": "Extended zone records without brute-force transfer attempts.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    },
                    {
                        "id": "nameserver_analysis",
                        "label": "Nameserver Infrastructure Analysis",
                        "description": "Resolves and inspects authoritative nameserver hosts and diversity.",
                        "expected_output": "Authoritative nameservers and their resolved IPv4 addresses.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    },
                    {
                        "id": "subdomains_ct",
                        "label": "Subdomain Discovery via Certificate Transparency",
                        "description": "Searches public Certificate Transparency logs for issued hostnames.",
                        "expected_output": "Subdomains previously appearing in TLS certificates.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    },
                    {
                        "id": "dns_security_posture",
                        "label": "DNS Security Posture (SPF, DMARC, DNSSEC)",
                        "description": "Checks SPF, DMARC, and DNSSEC deployment in DNS.",
                        "expected_output": "Mail authentication posture and DNSSEC status.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    }
                ]
            },
            "osint_intelligence": {
                "title": "B. OSINT Intelligence",
                "options": [
                    {
                        "id": "public_emails",
                        "label": "Public Email & Contact Discovery",
                        "description": "Harvests publicly indexed contact addresses via OSINT sources.",
                        "expected_output": "Domain-associated public email addresses.",
                        "interaction_type": "Pure Passive",
                        "available": True,
                        "availability_note": "External OSINT collector ready" if harvester_ok else "Uses WHOIS contact extraction"
                    },
                    {
                        "id": "search_engine_intel",
                        "label": "Search Engine & Public Host Intelligence",
                        "description": "Collects publicly indexed hostnames and emails via OSINT search connectors.",
                        "expected_output": "Indexed public hosts, subdomains, and public contacts.",
                        "interaction_type": "Pure Passive",
                        "available": True,
                        "availability_note": "OSINT engine ready" if harvester_ok else "Runs baseline OSINT collector"
                    },
                    {
                        "id": "public_org_info",
                        "label": "Public Organization & Registrant Intelligence",
                        "description": "Extracts public registrant entities and TXT site-verification records.",
                        "expected_output": "Organization owner, registrar, country, and verification metadata.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    },
                    {
                        "id": "public_metadata",
                        "label": "Public Certificate & TXT Metadata Collection",
                        "description": "Reviews public DNS TXT disclosures and historical certificate issuers.",
                        "expected_output": "Certificate issuer metadata and public TXT verification hints.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    },
                    {
                        "id": "technology_intel",
                        "label": "Passive Technology Stack Intelligence",
                        "description": "Infers verifiable cloud/mail/CDN platforms from public MX, NS, and TXT signatures.",
                        "expected_output": "Identified mail, DNS, CDN, and hosting platform indicators.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    },
                    {
                        "id": "crtsh_history",
                        "label": "Public Certificate Transparency History",
                        "description": "Collects historical TLS certificate issuers and validity windows.",
                        "expected_output": "Certificate serials, issuers, common names, validity periods.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    },
                    {
                        "id": "external_exposure_apis",
                        "label": "External Exposure Intelligence (Shodan / VirusTotal)",
                        "description": "Queries third-party passive host/domain intelligence feeds when configured.",
                        "expected_output": "Third-party reputation stats and indexed ports.",
                        "interaction_type": "Pure Passive",
                        "available": shodan_ok or vt_ok,
                        "availability_note": "Configured" if (shodan_ok or vt_ok) else "Unavailable — External API keys not configured"
                    },
                    {
                        "id": "public_breach_metadata",
                        "label": "Public Breach Metadata Exposure",
                        "description": "Checks configured breach intelligence sources for domain exposure.",
                        "expected_output": "Breach metadata counts when integrated.",
                        "interaction_type": "Pure Passive",
                        "available": False,
                        "availability_note": "Unavailable — Breach intelligence feed not integrated"
                    }
                ]
            },
            "infrastructure_intelligence": {
                "title": "C. Infrastructure Intelligence",
                "options": [
                    {
                        "id": "ip_intelligence",
                        "label": "IP Resolution & Netblock Intelligence",
                        "description": "Maps resolved IPv4/IPv6 addresses to network blocks and PTR names.",
                        "expected_output": "Resolved IPs, CIDR netblocks, and reverse hostnames.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    },
                    {
                        "id": "reverse_dns",
                        "label": "Reverse DNS (PTR Lookup)",
                        "description": "Resolves IP addresses back to hostnames via PTR records.",
                        "expected_output": "Mapped PTR hostnames for resolved IPs.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    },
                    {
                        "id": "asn_ip_hosting",
                        "label": "ASN, Netblock & Hosting Provider Identification",
                        "description": "Identifies autonomous system numbers, IP blocks, and hosting operators.",
                        "expected_output": "ASN, CIDR netblock, country, and hosting entity.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    },
                    {
                        "id": "ip_geolocation",
                        "label": "Public IP Geolocation Lookup",
                        "description": "Retrieves public geographic and ISP attribution for routable IP addresses.",
                        "expected_output": "Country, region, city, ISP/ASN for public IPs.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    },
                    {
                        "id": "hosting_info",
                        "label": "Hosting Provider & Ownership Summary",
                        "description": "Correlates RDAP netblocks, nameservers, and organization records.",
                        "expected_output": "Hosting provider, ASN handle, network block, and NS hierarchy.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    },
                    {
                        "id": "certificate_info",
                        "label": "Passive TLS Certificate Log Summary",
                        "description": "Retrieves public TLS certificate records from Certificate Transparency without target contact.",
                        "expected_output": "Certificate SANs, common names, issuers, validity windows.",
                        "interaction_type": "Pure Passive",
                        "available": True
                    },
                    {
                        "id": "tls_certificate_inspect",
                        "label": "Live TLS Certificate Inspection",
                        "description": "Directly connects to target port 443 to read active TLS certificate parameters.",
                        "expected_output": "Active TLS version, cipher, subject, issuer, expiry date.",
                        "interaction_type": "Active Target Contact",
                        "available": True,
                        "requires_target_contact": True
                    },
                    {
                        "id": "http_header_inspect",
                        "label": "HTTP Server Banner & Security Header Inspection",
                        "description": "Sends direct HTTP/HTTPS HEAD requests to examine exposed server & defense headers.",
                        "expected_output": "Server banner, HSTS, CSP, X-Frame-Options presence.",
                        "interaction_type": "Active Target Contact",
                        "available": True,
                        "requires_target_contact": True
                    }
                ]
            }
        }

        presets = {
            "quick_passive": {
                "label": "Quick Passive Recon",
                "description": "Essential ownership, RDAP, DNS, and ASN identification (zero target contact).",
                "checks": ["whois_lookup", "rdap_lookup", "dns_records", "asn_ip_hosting"]
            },
            "domain_intel": {
                "label": "Domain Intelligence",
                "description": "Full domain registration, DNS records, subdomains via CT logs, and SPF/DMARC/DNSSEC audit.",
                "checks": ["whois_lookup", "rdap_lookup", "dns_records", "subdomains_ct", "dns_security_posture"]
            },
            "osint_collection": {
                "label": "OSINT Collection",
                "description": "Public contacts, Certificate Transparency history, and configured external OSINT feeds.",
                "checks": ["whois_lookup", "public_emails", "crtsh_history", "subdomains_ct"]
            },
            "infra_intel": {
                "label": "Infrastructure Intelligence",
                "description": "Reverse DNS, netblock/ASN ownership, and DNS resolution mapping.",
                "checks": ["rdap_lookup", "dns_records", "reverse_dns", "asn_ip_hosting"]
            },
            "full_passive": {
                "label": "Full Passive Recon",
                "description": "Runs every available zero-contact Domain, OSINT, and Infrastructure passive check.",
                "checks": [
                    "whois_lookup", "rdap_lookup", "dns_records", "dns_enumeration",
                    "nameserver_analysis", "subdomains_ct", "dns_security_posture",
                    "public_emails", "search_engine_intel", "public_org_info",
                    "public_metadata", "technology_intel", "crtsh_history",
                    "ip_intelligence", "reverse_dns", "asn_ip_hosting",
                    "ip_geolocation", "hosting_info", "certificate_info"
                ]
            }
        }
        return {"groups": groups, "presets": presets}

    @staticmethod
    def get_active_catalog() -> Dict[str, Any]:
        nmap = NmapCollector()
        caps = nmap.capabilities
        has_raw = caps.get("has_raw_socket", False)
        nmap_ok = caps.get("binary_found", False)

        groups = {
            "host_discovery": {
                "title": "A. Host Discovery",
                "options": [
                    {"id": "skip_discovery", "label": "Treat Target as Online (-Pn)", "description": "Scans target ports directly even when ICMP echo is firewalled.", "available": nmap_ok, "interaction_type": "Active"},
                    {"id": "ping_discovery", "label": "ICMP Ping Discovery (-PE)", "description": "Standard host reachability check via ICMP echo request before scanning.", "available": nmap_ok, "interaction_type": "Active"},
                    {"id": "ping_only", "label": "Live Host Ping Discovery Only (-sn)", "description": "Checks reachability without running port scans.", "available": nmap_ok, "interaction_type": "Active"},
                    {"id": "tcp_ping", "label": "TCP Discovery Probe (-PA22,80,443)", "description": "Probes standard TCP ports to determine host liveness.", "available": nmap_ok, "interaction_type": "Active"},
                    {"id": "network_discovery", "label": "Network Discovery Sweep (-sn)", "description": "Enumerates responsive hosts across an authorized network segment.", "available": nmap_ok, "interaction_type": "Active"},
                    {"id": "ip_range_discovery", "label": "IP Range Host Sweep (-sn)", "description": "Discovers active hosts inside a specified authorized IP range.", "available": nmap_ok, "interaction_type": "Active"},
                    {"id": "arp_discovery", "label": "Local Network ARP Discovery (-PR)", "description": "Fast Layer-2 discovery on local subnet.", "available": nmap_ok and has_raw, "availability_note": None if has_raw else "Requires elevated raw-socket privileges"}
                ]
            },
            "port_scanning": {
                "title": "B. Port Scanning",
                "tcp_scan_types": [
                    {"id": "tcp_connect", "label": "TCP Connect Scan (-sT)", "description": "Reliable full TCP three-way handshake scan works without elevated permissions.", "available": nmap_ok},
                    {"id": "tcp_syn", "label": "TCP SYN Stealth Scan (-sS)", "description": "Half-open SYN probe scan.", "available": nmap_ok and has_raw, "availability_note": None if has_raw else "Unavailable in standard user privilege mode (use TCP Connect)"}
                ],
                "port_scopes": [
                    {"id": "top_100", "label": "Common TCP Ports (Top 100)", "description": "Fast scan of the 100 most frequently exposed services (~5–20 seconds)."},
                    {"id": "service_common", "label": "Common Enterprise & Service Ports (36 ports)", "description": "Targeted infrastructure, web, SMB, mail, SSH, DB, and management ports (~5–15 seconds)."},
                    {"id": "top_1000", "label": "Top 1000 Standard TCP Ports", "description": "Comprehensive default port range (~30–90 seconds)."},
                    {"id": "port_range", "label": "TCP Port Range (Start–End)", "description": "Scan a validated contiguous TCP range (e.g. 1-1024 or 8000-8999)."},
                    {"id": "all_ports", "label": "Full TCP Port Scan 1–65535 (-p-)", "description": "Exhaustive TCP port sweep (may take several minutes)."},
                    {"id": "custom", "label": "Custom TCP Ports / Mixed List", "description": "Specify validated comma-separated ports or ranges (e.g. 22,80,443,3306,8080 or 1-1024)."}
                ],
                "udp_scan": {
                    "id": "udp_scan",
                    "label": "Include UDP Discovery (--top-ports / -sU)",
                    "description": "Scans UDP services such as DNS (53), SNMP (161), NTP (123).",
                    "available": nmap_ok and has_raw,
                    "availability_note": None if has_raw else "UDP raw scanning requires elevated privileges on this host"
                },
                "udp_port_modes": [
                    {"id": "none", "label": "No UDP Scan", "available": True},
                    {"id": "udp_common", "label": "Common UDP Ports (DNS, DHCP, NTP, SNMP)", "available": nmap_ok and has_raw, "availability_note": None if has_raw else "Requires elevated raw-socket privileges"},
                    {"id": "udp_selected", "label": "Selected / Custom UDP Ports or Range", "available": nmap_ok and has_raw, "availability_note": None if has_raw else "Requires elevated raw-socket privileges"},
                    {"id": "udp_full", "label": "Full UDP Port Scan (1–65535)", "available": nmap_ok and has_raw, "availability_note": None if has_raw else "Requires elevated raw-socket privileges"}
                ]
            },
            "nmap_options": {
                "title": "C. Nmap Scanning & Fingerprinting Options",
                "options": [
                    {"id": "service_version", "label": "Service & Version Detection (-sV)", "description": "Probes open ports to determine daemon software and exact version.", "available": nmap_ok, "default": True},
                    {"id": "banner_grab", "label": "Service Banner Capture", "description": "Captures raw initial greetings from open TCP listeners.", "available": nmap_ok},
                    {"id": "default_scripts", "label": "Safe Default Discovery Scripts (-sC)", "description": "Executes Nmap built-in default safe service info scripts.", "available": nmap_ok},
                    {"id": "os_detection", "label": "OS Detection (-O)", "description": "Estimates remote operating system family.", "available": nmap_ok and has_raw, "availability_note": None if has_raw else "Requires elevated raw-socket privileges"}
                ],
                "approved_profiles": [
                    {"id": k, "label": k.replace("-", " ").title(), "description": v.get("description", ""), "available": nmap_ok}
                    for k, v in SUPPORTED_PROFILES.items()
                ],
                "timing_profiles": [
                    {"id": "T2", "label": "Polite (T2)", "description": "Slow, low-bandwidth pacing to reduce network load."},
                    {"id": "T3", "label": "Normal Balanced (T3)", "description": "Standard recommended timing for authorized assessments."},
                    {"id": "T4", "label": "Fast Scan (T4)", "description": "Faster timeouts suitable for responsive low-latency hosts."}
                ]
            },
            "service_enumeration": {
                "title": "D. Targeted Service Enumeration",
                "options": [
                    {"id": "ssh_enum", "label": "SSH Algorithm Enumeration", "nse_scripts": ["ssh2-enum-algos"], "available": nmap_ok},
                    {"id": "web_enum", "label": "HTTP / Web Service Enumeration", "nse_scripts": ["http-title", "http-headers", "http-methods", "http-security-headers"], "available": nmap_ok},
                    {"id": "smb_enum", "label": "SMB Dialect, OS & Signing Audit", "nse_scripts": ["smb-os-discovery", "smb-security-mode"], "available": nmap_ok},
                    {"id": "ftp_enum", "label": "FTP Anonymous Access Check", "nse_scripts": ["ftp-anon"], "available": nmap_ok},
                    {"id": "db_enum", "label": "Database Service Enumeration (MySQL)", "nse_scripts": ["mysql-info"], "available": nmap_ok},
                    {"id": "dns_enum", "label": "DNS Service & Recursion Enumeration", "nse_scripts": ["dns-nsid", "dns-recursion"], "available": nmap_ok},
                    {"id": "ssl_enum", "label": "SSL/TLS Certificate & Cipher Enumeration", "nse_scripts": ["ssl-cert", "ssl-enum-ciphers"], "available": nmap_ok}
                ]
            }
        }

        presets = {
            "quick_network_scan": {
                "label": "Quick Network Scan",
                "description": "Fast live-host probe and top 100 common ports (~5–15 sec).",
                "config": {"host_discovery": "tcp_ping", "tcp_scan_type": "tcp_connect", "port_mode": "top_100", "service_version": False, "timing": "T4"}
            },
            "basic_nmap_scan": {
                "label": "Basic Nmap Scan",
                "description": "Balanced TCP Connect scan with service & version identification (-sV).",
                "config": {"host_discovery": "skip_discovery", "tcp_scan_type": "tcp_connect", "port_mode": "service_common", "service_version": True, "timing": "T3"}
            },
            "tcp_assessment": {
                "label": "TCP Assessment",
                "description": "Top 1000 TCP port discovery with banner capture and safe version detection.",
                "config": {"host_discovery": "skip_discovery", "tcp_scan_type": "tcp_connect", "port_mode": "top_1000", "service_version": True, "banner_grab": True, "timing": "T3"}
            },
            "udp_assessment": {
                "label": "UDP Assessment",
                "description": "Scans common UDP services (DNS, SNMP, NTP) where host privileges allow.",
                "available": nmap_ok and has_raw,
                "availability_note": None if has_raw else "UDP scanning requires elevated raw-socket privileges",
                "config": {"host_discovery": "skip_discovery", "tcp_scan_type": "tcp_connect", "port_mode": "top_100", "udp_scan": True, "udp_port_mode": "udp_common", "service_version": False, "timing": "T3"}
            },
            "service_enumeration_preset": {
                "label": "Service Enumeration",
                "description": "Enumerates HTTP, SSH, SMB, FTP, DNS, database, and TLS services on common ports.",
                "config": {"host_discovery": "skip_discovery", "tcp_scan_type": "tcp_connect", "port_mode": "service_common", "service_version": True, "banner_grab": True, "default_scripts": True, "timing": "T3"},
                "service_checks": ["ssh_enum", "web_enum", "smb_enum", "ftp_enum", "db_enum", "dns_enum", "ssl_enum"]
            },
            "full_tcp_assessment": {
                "label": "Full TCP Assessment",
                "description": "All 65,535 TCP ports (-p-) with service/version identification (longer duration).",
                "config": {"host_discovery": "skip_discovery", "tcp_scan_type": "tcp_connect", "port_mode": "all_ports", "service_version": True, "timing": "T4"}
            },
            "fast_discovery": {
                "label": "Fast Host Discovery",
                "description": "Quick live host verification + Top 100 ports without deep scripts (~5–15 sec).",
                "config": {"host_discovery": "skip_discovery", "tcp_scan_type": "tcp_connect", "port_mode": "top_100", "service_version": False, "timing": "T4"}
            },
            "standard_port_service": {
                "label": "Standard Port & Service Scan",
                "description": "Balanced TCP Connect scan on common enterprise ports with version detection (~15–45 sec).",
                "config": {"host_discovery": "skip_discovery", "tcp_scan_type": "tcp_connect", "port_mode": "service_common", "service_version": True, "timing": "T3"}
            },
            "web_app_enum": {
                "label": "Web & TLS Service Enumeration",
                "description": "Targets web/TLS ports (80, 443, 8009, 8080, 8180, 8443) with HTTP & SSL inspection (~10–25 sec).",
                "config": {"host_discovery": "skip_discovery", "tcp_scan_type": "tcp_connect", "port_mode": "custom", "custom_ports": "80,443,3000,8000,8009,8080,8180,8443", "service_version": True, "timing": "T3"},
                "service_checks": ["web_enum", "ssl_enum"]
            },
            "deep_service_enum": {
                "label": "Deep Infrastructure & Service Enumeration",
                "description": "Top 1000 TCP ports, full version identification, banners, and all safe service checks (~1–3 min).",
                "config": {"host_discovery": "skip_discovery", "tcp_scan_type": "tcp_connect", "port_mode": "top_1000", "service_version": True, "banner_grab": True, "default_scripts": True, "timing": "T3"},
                "service_checks": ["ssh_enum", "web_enum", "smb_enum", "ftp_enum", "db_enum", "dns_enum", "ssl_enum"]
            }
        }

        return {
            "capabilities": caps,
            "nmap_version": nmap.version,
            "groups": groups,
            "presets": presets
        }

    @staticmethod
    def get_vulnerability_catalog() -> Dict[str, Any]:
        # 1. NSE Scripts grouped cleanly (plus thematic sub-groups)
        nse_discovery = []
        nse_vuln = []
        nse_groups: Dict[str, List[Dict[str, Any]]] = {
            "safe_discovery": [],
            "http": [],
            "ssl_tls": [],
            "smb": [],
            "dns": [],
            "ssh_ftp": [],
            "approved_vuln": []
        }
        for sid, meta in APPROVED_NSE_SCRIPTS.items():
            entry = {
                "id": sid,
                "category": meta.get("category"),
                "risk_tier": meta.get("risk_tier"),
                "safety_classification": meta.get("safety_classification", "Approved"),
                "ports": meta.get("ports", "all"),
                "description": meta.get("description", ""),
                "purpose": meta.get("purpose", ""),
                "expected_output": meta.get("expected_output", ""),
                "cve": meta.get("cve"),
                "cvss": meta.get("cvss"),
                "severity": meta.get("severity")
            }
            if meta.get("category") == "vuln":
                nse_vuln.append(entry)
                nse_groups["approved_vuln"].append(entry)
            else:
                nse_discovery.append(entry)
                if sid.startswith("http-"):
                    nse_groups["http"].append(entry)
                elif sid.startswith("ssl-"):
                    nse_groups["ssl_tls"].append(entry)
                elif sid.startswith("smb-"):
                    nse_groups["smb"].append(entry)
                elif sid.startswith("dns-"):
                    nse_groups["dns"].append(entry)
                elif sid.startswith(("ssh", "ftp-")):
                    nse_groups["ssh_ftp"].append(entry)
                else:
                    nse_groups["safe_discovery"].append(entry)

        # 2. Live Tenable Nessus check (honest Read-Only vs Launch capability)
        nessus_status: Dict[str, Any]
        nessus_templates: List[Dict[str, Any]] = []
        try:
            nc = NessusCollector()
            n_conn = nc.test_connection()
            if n_conn.get("connected"):
                all_tpls = nc.get_scan_templates()
                nessus_templates = [t for t in all_tpls if t.get("is_available")]
                scan_api_ok = bool(n_conn.get("scan_api_enabled", False))
                nessus_status = {
                    "available": scan_api_ok,
                    "connected": True,
                    "read_only": not scan_api_ok,
                    "status": "READY" if scan_api_ok else "READ_ONLY_LICENSE",
                    "scan_api_enabled": scan_api_ok,
                    "nessus_type": n_conn.get("nessus_type") or ("Nessus Professional" if scan_api_ok else "Nessus Essentials"),
                    "reason": None if scan_api_ok else (
                        n_conn.get("limitations") or "Connected to Nessus Essentials (Read-Only mode: auth, scanner info, scan listing, results & report import supported; programmatic scan launch disabled by license)."
                    ),
                    "server_version": n_conn.get("server_version") or n_conn.get("version"),
                    "template_count": len(nessus_templates),
                    "total_templates_discovered": len(all_tpls),
                    "templates": nessus_templates if scan_api_ok else []
                }
            else:
                nessus_status = {
                    "available": False,
                    "connected": False,
                    "read_only": True,
                    "status": "UNAVAILABLE",
                    "reason": n_conn.get("error") or "Nessus API credentials or server unavailable.",
                    "templates": []
                }
        except Exception as e:
            nessus_status = {
                "available": False,
                "connected": False,
                "read_only": True,
                "status": "UNAVAILABLE",
                "reason": str(e),
                "templates": []
            }

        # 3. Live ProjectDiscovery Nuclei check (real local binary + verified templates)
        nuclei_info = NucleiCollector().check_readiness()
        nuclei_ready = bool(nuclei_info.get("ready"))
        nuclei_status: Dict[str, Any] = {
            "available": nuclei_ready,
            "ready": nuclei_ready,
            "status": "READY" if nuclei_ready else "UNAVAILABLE",
            "version": nuclei_info.get("version"),
            "templates_installed": bool(nuclei_info.get("templates_installed")),
            "templates_count": nuclei_info.get("templates_count", 0),
            "template_categories": nuclei_info.get("template_categories") or {},
            "profiles": nuclei_info.get("profiles") or NucleiPolicyService.list_profiles(),
            "reason": nuclei_info.get("reason"),
        }

        nse_ok = bool(shutil.which("nmap") or os.path.exists("/usr/bin/nmap"))
        available_engines: List[str] = []
        if nse_ok:
            available_engines.append("nse")
        if nuclei_ready:
            available_engines.append("nuclei")
        if nessus_status.get("available"):
            available_engines.append("nessus")
        combined_ready = bool(nse_ok and nuclei_ready)

        presets = {
            "quick_vuln_check": {
                "label": "Quick Vulnerability Check",
                "description": "Fast non-destructive exposure check across common web, SSL/TLS, SMB, and service banners.",
                "engine": "nse",
                "engines": ["nse"],
                "available": nse_ok,
                "scripts": ["banner", "http-security-headers", "ssl-cert", "ssl-heartbleed", "smb-vuln-ms17-010"]
            },
            "nse_assessment": {
                "label": "NSE Assessment",
                "description": "Full allowlisted Nmap Scripting Engine assessment across discovery and approved vulnerability checks.",
                "engine": "nse",
                "engines": ["nse"],
                "available": nse_ok,
                "scripts": ["banner", "ftp-anon", "ftp-vsftpd-backdoor", "smb-os-discovery", "smb-security-mode", "smb-vuln-ms17-010", "http-title", "http-security-headers", "ssl-cert", "ssl-enum-ciphers", "ssl-heartbleed", "ssl-poodle"]
            },
            "nuclei_assessment": {
                "label": "ProjectDiscovery Nuclei Web & CVE Audit",
                "description": "Safe template-driven CVE, HTTP security posture, SSL/TLS, and exposed panel scanning via Nuclei.",
                "engine": "nuclei",
                "engines": ["nuclei"],
                "nuclei_profile": "safe-all",
                "available": nuclei_ready,
                "availability_note": None if nuclei_ready else nuclei_status.get("reason")
            },
            "nessus_assessment": {
                "label": "Nessus Assessment",
                "description": "Executes live Tenable Nessus vulnerability assessment when scan launch API is licensed.",
                "engine": "nessus",
                "engines": ["nessus"],
                "available": nessus_status["available"],
                "availability_note": None if nessus_status["available"] else nessus_status.get("reason")
            },
            "combined_assessment": {
                "label": "Combined Assessment (NSE + Nuclei)",
                "description": "Runs allowlisted Nmap NSE and ProjectDiscovery Nuclei together without silent fallback.",
                "engine": "combined",
                "engines": available_engines,
                "nuclei_profile": "safe-all",
                "available": len(available_engines) >= 1,
                "availability_note": f"Active engines: {', '.join(e.upper() for e in available_engines)}"
            },
            "nse_safe_web": {
                "label": "Safe Web & TLS Vulnerability Check (NSE)",
                "description": "Runs non-destructive HTTP security headers, SSL certificate, cipher, Heartbleed, and POODLE checks.",
                "engine": "nse",
                "engines": ["nse"],
                "scripts": ["http-title", "http-security-headers", "ssl-cert", "ssl-enum-ciphers", "ssl-heartbleed", "ssl-poodle"]
            },
            "nse_service_audit": {
                "label": "Service Vulnerability Audit (NSE)",
                "description": "Checks exposed services (FTP, SSH, SMB, HTTP, SSL) using all approved non-destructive NSE checks.",
                "engine": "nse",
                "engines": ["nse"],
                "scripts": ["banner", "ftp-anon", "ftp-vsftpd-backdoor", "smb-os-discovery", "smb-security-mode", "smb-vuln-ms17-010", "http-title", "http-security-headers", "ssl-cert", "ssl-heartbleed"]
            },
            "nessus_vuln_scan": {
                "label": "Tenable Nessus Deep Vulnerability Scan",
                "description": "Executes real Tenable Nessus vulnerability assessment when scan_api is licensed.",
                "engine": "nessus",
                "engines": ["nessus"],
                "available": nessus_status["available"],
                "availability_note": None if nessus_status["available"] else nessus_status.get("reason")
            },
            "nuclei_vuln_scan": {
                "label": "Nuclei Safe CVE & Misconfiguration Scan",
                "description": "Runs curated ProjectDiscovery Nuclei templates across CVEs, HTTP headers, SSL/TLS, and exposed panels.",
                "engine": "nuclei",
                "engines": ["nuclei"],
                "nuclei_profile": "safe-all",
                "available": nuclei_ready,
                "availability_note": None if nuclei_ready else nuclei_status.get("reason")
            },
            "combined_vuln_scan": {
                "label": "Combined Multi-Engine Assessment (NSE + Nuclei)",
                "description": "Correlates findings from allowlisted Nmap NSE and ProjectDiscovery Nuclei without silent fallback.",
                "engine": "combined",
                "engines": [e for e in ("nse", "nuclei") if e in available_engines] or available_engines,
                "nuclei_profile": "safe-all",
                "available": combined_ready,
                "availability_note": None if combined_ready else "Requires Nmap NSE and ProjectDiscovery Nuclei to be available."
            }
        }

        return {
            "nse": {
                "available": nse_ok,
                "discovery_scripts": nse_discovery,
                "vulnerability_scripts": nse_vuln,
                "groups": nse_groups
            },
            "nuclei": nuclei_status,
            "nessus": nessus_status,
            "combined": {
                "available": combined_ready,
                "operational_engines": available_engines,
                "reason": None if combined_ready else "Combined multi-engine scanning requires Nmap NSE and ProjectDiscovery Nuclei."
            },
            "presets": presets
        }

    @classmethod
    def get_full_catalog(cls) -> Dict[str, Any]:
        passive = cls.get_passive_catalog()
        active = cls.get_active_catalog()
        vuln = cls.get_vulnerability_catalog()
        return {
            "categories": [
                {
                    "id": "passive",
                    "title": "PASSIVE RECONNAISSANCE",
                    "cta": "Explore Passive Recon",
                    "description": "Collect publicly available ownership, DNS, certificate, OSINT, and infrastructure intelligence with clearly separated passive vs target-contact checks."
                },
                {
                    "id": "active",
                    "title": "ACTIVE RECONNAISSANCE",
                    "cta": "Explore Active Recon",
                    "description": "Verify live hosts, scan custom or standard TCP ports, identify exposed services, and enumerate protocols cleanly."
                },
                {
                    "id": "vulnerability",
                    "title": "VULNERABILITY ASSESSMENT",
                    "cta": "Explore Vulnerability Assessment",
                    "description": "Execute allowlisted Nmap NSE security checks, ProjectDiscovery Nuclei scans, or inspect Tenable Nessus capabilities."
                }
            ],
            "passive": passive,
            "active": active,
            "vulnerability": vuln
        }

