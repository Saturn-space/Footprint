"""
FootprintIQ - Extended Passive & Infrastructure Intelligence Collector
Executes real, honest passive OSINT, domain, DNS security, certificate transparency,
and infrastructure checks without fabricating unavailable data.
"""

import os
import re
import ssl
import socket
import logging
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import requests
import dns.resolver
import dns.reversename

from src.collectors.whois_collector import WhoisCollector
from src.collectors.dns_collector import DNSCollector
from src.collectors.rdap_collector import RDAPCollector
from src.collectors.theharvester_collector import TheHarvesterCollector

logger = logging.getLogger("FootprintIQ.PassiveIntel")


class PassiveIntelCollector:
    """
    Modular passive reconnaissance executor that runs ONLY user-selected checks,
    separates pure passive lookups from optional target-contact checks, and
    never simulates missing API feeds.
    """

    def __init__(self, timeout: int = 12):
        self.timeout = timeout
        self.whois_collector = WhoisCollector(timeout=timeout)
        self.dns_collector = DNSCollector(timeout=timeout)
        self.rdap_collector = RDAPCollector(timeout=timeout)
        self.harvester = TheHarvesterCollector(limit=50, timeout=max(20, timeout))

    @staticmethod
    def _is_ip(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    @staticmethod
    def _classify_ip_scope(target: str) -> Dict[str, Any]:
        """Determines whether an IP address is private/special-use vs publicly routable."""
        try:
            ip_obj = ipaddress.ip_address(target.strip())
        except ValueError:
            return {"is_ip": False, "is_non_public": False, "scope_label": "Domain / Hostname", "note": ""}

        cgnat = ipaddress.ip_network("100.64.0.0/10")
        doc_nets = (
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        )
        is_v4 = isinstance(ip_obj, ipaddress.IPv4Address)
        is_cgnat = is_v4 and ip_obj in cgnat
        is_doc = is_v4 and any(ip_obj in net for net in doc_nets)
        is_non_public = bool(
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or is_cgnat
            or is_doc
        )
        if ip_obj.is_loopback:
            label = "Loopback Address Space (RFC 1122)"
        elif ip_obj.is_link_local:
            label = "Link-Local Address Space (RFC 3927)"
        elif is_cgnat:
            label = "Shared CGNAT Address Space (RFC 6598)"
        elif is_doc:
            label = "Documentation / Test Network (RFC 5737)"
        elif ip_obj.is_private:
            label = "Private / Internal Network (RFC 1918)"
        elif ip_obj.is_reserved or ip_obj.is_multicast:
            label = "Reserved / Special-Use Address Space"
        else:
            label = "Publicly Routable IP Address"
        return {
            "is_ip": True,
            "is_non_public": is_non_public,
            "scope_label": label,
            "note": (
                f"{label}: private/special-use IP addresses are not registered to external organizations in public RIR WHOIS."
                if is_non_public
                else ""
            ),
        }

    @staticmethod
    def _extract_emails(text: str) -> List[str]:
        if not text:
            return []
        found = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)
        return sorted(set(found))

    def _query_crtsh(self, domain: str) -> Dict[str, Any]:
        """Queries crt.sh Certificate Transparency logs for passive subdomain and cert history."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            resp = requests.get(url, timeout=self.timeout, headers={"User-Agent": "FootprintIQ-OSINT/2.0"})
            if resp.status_code != 200:
                return {
                    "status": "ERROR",
                    "error": f"crt.sh returned HTTP {resp.status_code}",
                    "subdomains": [],
                    "certificates": []
                }
            data = resp.json()
            if not isinstance(data, list):
                return {"status": "SUCCESS", "subdomains": [], "certificates": []}

            subdomains = set()
            certs = []
            seen_serials = set()
            for item in data[:200]:
                name_val = item.get("name_value", "")
                for line in str(name_val).splitlines():
                    clean_name = line.strip().lower().lstrip("*.")
                    if clean_name and (clean_name == domain.lower() or clean_name.endswith("." + domain.lower())):
                        subdomains.add(clean_name)

                serial = item.get("serial_number")
                if serial and serial not in seen_serials and len(certs) < 20:
                    seen_serials.add(serial)
                    certs.append({
                        "common_name": item.get("common_name"),
                        "issuer": item.get("issuer_name"),
                        "not_before": item.get("not_before"),
                        "not_after": item.get("not_after"),
                        "serial_number": serial
                    })

            return {
                "status": "SUCCESS",
                "subdomains": sorted(subdomains),
                "certificates": certs
            }
        except Exception as e:
            return {
                "status": "UNAVAILABLE",
                "error": f"Certificate Transparency lookup unavailable: {str(e)}",
                "subdomains": [],
                "certificates": []
            }

    def _inspect_dns_security(self, domain: str, existing_txt: Optional[List[str]] = None) -> Dict[str, Any]:
        """Inspects real SPF, DMARC, and DNSSEC records without altering domain DNS."""
        spf_records = []
        dmarc_records = []
        dnssec_enabled = False
        notes = []

        resolver = dns.resolver.Resolver()
        resolver.lifetime = float(min(self.timeout, 6))

        try:
            if existing_txt is None:
                ans = resolver.resolve(domain, "TXT")
                existing_txt = [r.to_text().strip('"') for r in ans]
            spf_records = [t for t in existing_txt if "v=spf1" in t.lower()]
        except Exception:
            pass

        try:
            dmarc_ans = resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_records = [r.to_text().strip('"') for r in dmarc_ans]
        except Exception:
            pass

        try:
            ds_ans = resolver.resolve(domain, "DS")
            if len(ds_ans) > 0:
                dnssec_enabled = True
        except Exception:
            try:
                dk_ans = resolver.resolve(domain, "DNSKEY")
                if len(dk_ans) > 0:
                    dnssec_enabled = True
            except Exception:
                dnssec_enabled = False

        if not spf_records:
            notes.append("No SPF (v=spf1) record detected in domain TXT records.")
        if not dmarc_records:
            notes.append("No DMARC (_dmarc) policy record detected.")
        if not dnssec_enabled:
            notes.append("No DNSSEC DS/DNSKEY chain observed.")

        return {
            "spf_configured": bool(spf_records),
            "spf_records": spf_records,
            "dmarc_configured": bool(dmarc_records),
            "dmarc_records": dmarc_records,
            "dnssec_configured": dnssec_enabled,
            "notes": notes
        }

    def _reverse_dns_lookup(self, target_ip: str) -> Dict[str, Any]:
        """Resolves PTR reverse DNS record for an IPv4/IPv6 address."""
        ptr_names = []
        try:
            rev_name = dns.reversename.from_address(target_ip)
            resolver = dns.resolver.Resolver()
            resolver.lifetime = float(min(self.timeout, 5))
            ans = resolver.resolve(rev_name, "PTR")
            ptr_names = [str(r).rstrip(".") for r in ans]
            return {"status": "SUCCESS", "ip": target_ip, "ptr_records": ptr_names}
        except Exception:
            try:
                host, _, _ = socket.gethostbyaddr(target_ip)
                if host:
                    ptr_names = [host]
                    return {"status": "SUCCESS", "ip": target_ip, "ptr_records": ptr_names}
            except Exception as e:
                return {"status": "NO_PTR", "ip": target_ip, "ptr_records": [], "note": str(e)}
        return {"status": "NO_PTR", "ip": target_ip, "ptr_records": []}

    def _inspect_tls_certificate(self, target: str, port: int = 443) -> Dict[str, Any]:
        """
        ACTIVE TARGET CONTACT: Establishes a read-only TLS handshake to port 443
        only when explicitly authorized and requested by user.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((target, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert(binary_form=False) or {}
                    cipher = ssock.cipher()
                    proto = ssock.version()
                    return {
                        "interaction_type": "Active Target Contact",
                        "status": "SUCCESS",
                        "port": port,
                        "tls_version": proto,
                        "cipher_suite": cipher[0] if cipher else None,
                        "subject": str(cert.get("subject", "")),
                        "issuer": str(cert.get("issuer", "")),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter")
                    }
        except Exception as e:
            return {
                "interaction_type": "Active Target Contact",
                "status": "UNREACHABLE_OR_NO_TLS",
                "port": port,
                "note": f"Port {port} did not accept TLS handshake: {str(e)}"
            }

    def _inspect_http_headers(self, target: str) -> List[Dict[str, Any]]:
        """
        ACTIVE TARGET CONTACT: Sends read-only HTTP/HTTPS HEAD requests
        to inspect server banner and HTTP security headers.
        """
        results = []
        sec_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]
        for scheme in ("http", "https"):
            url = f"{scheme}://{target}"
            try:
                resp = requests.head(url, timeout=5, allow_redirects=True, verify=False)
                present = {h: resp.headers[h] for h in sec_headers if h in resp.headers}
                missing = [h for h in sec_headers if h not in resp.headers]
                results.append({
                    "interaction_type": "Active Target Contact",
                    "url": url,
                    "status": "SUCCESS",
                    "http_status": resp.status_code,
                    "server_header": resp.headers.get("Server", "Not disclosed"),
                    "powered_by": resp.headers.get("X-Powered-By", "Not disclosed"),
                    "security_headers_present": present,
                    "security_headers_missing": missing
                })
            except Exception as e:
                results.append({
                    "interaction_type": "Active Target Contact",
                    "url": url,
                    "status": "NO_RESPONSE",
                    "note": str(e)
                })
        return results

    def _query_external_exposure_apis(self, target: str, is_ip: bool) -> Dict[str, Any]:
        """Checks optional Shodan / VirusTotal passive API integrations honestly."""
        shodan_key = (os.getenv("SHODAN_API_KEY") or "").strip()
        vt_key = (os.getenv("VIRUSTOTAL_API_KEY") or "").strip()
        res: Dict[str, Any] = {
            "shodan": {"status": "UNAVAILABLE", "reason": "Shodan API key not configured."},
            "virustotal": {"status": "UNAVAILABLE", "reason": "VirusTotal API key not configured."}
        }

        if shodan_key and is_ip:
            try:
                r = requests.get(f"https://api.shodan.io/shodan/host/{target}?key={shodan_key}", timeout=8)
                if r.status_code == 200:
                    data = r.json()
                    res["shodan"] = {
                        "status": "SUCCESS",
                        "org": data.get("org"),
                        "isp": data.get("isp"),
                        "ports": data.get("ports", []),
                        "vulns": data.get("vulns", [])
                    }
                else:
                    res["shodan"] = {"status": "ERROR", "reason": f"HTTP {r.status_code}"}
            except Exception as e:
                res["shodan"] = {"status": "ERROR", "reason": str(e)}

        if vt_key:
            ep = f"https://www.virustotal.com/api/v3/{'ip_addresses' if is_ip else 'domains'}/{target}"
            try:
                r = requests.get(ep, headers={"x-apikey": vt_key}, timeout=8)
                if r.status_code == 200:
                    attrs = r.json().get("data", {}).get("attributes", {})
                    res["virustotal"] = {
                        "status": "SUCCESS",
                        "reputation": attrs.get("reputation"),
                        "last_analysis_stats": attrs.get("last_analysis_stats", {})
                    }
                else:
                    res["virustotal"] = {"status": "ERROR", "reason": f"HTTP {r.status_code}"}
            except Exception as e:
                res["virustotal"] = {"status": "ERROR", "reason": str(e)}

        return res

    def _enumerate_extended_dns(self, domain: str) -> Dict[str, List[str]]:
        """Resolves extended DNS record types (SOA, CAA, SRV, A, AAAA, MX, NS, TXT, CNAME)."""
        resolver = dns.resolver.Resolver()
        resolver.lifetime = float(min(self.timeout, 6))
        enum_results: Dict[str, List[str]] = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"):
            try:
                ans = resolver.resolve(domain, rtype)
                enum_results[rtype] = [r.to_text().strip('"') for r in ans]
            except Exception:
                pass
        return enum_results

    def _analyze_nameservers(self, domain: str, ns_records: Optional[List[str]] = None) -> Dict[str, Any]:
        """Analyzes authoritative nameservers and their resolved IP addresses."""
        resolver = dns.resolver.Resolver()
        resolver.lifetime = float(min(self.timeout, 5))
        ns_hosts = [str(n).rstrip(".") for n in (ns_records or []) if str(n).strip()]
        if not ns_hosts:
            try:
                ans = resolver.resolve(domain, "NS")
                ns_hosts = [str(r).rstrip(".") for r in ans]
            except Exception:
                ns_hosts = []
        details = []
        for host in ns_hosts[:8]:
            ips: List[str] = []
            try:
                a_ans = resolver.resolve(host, "A")
                ips = [str(r) for r in a_ans]
            except Exception:
                pass
            details.append({"nameserver": host, "ipv4": ips})
        return {"count": len(ns_hosts), "nameservers": details}

    def _detect_passive_technologies(self, domain_intel: Dict[str, Any], http_headers: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Derives verifiable SaaS/CDN/mail/server technologies solely from observed DNS and header records."""
        detected: List[Dict[str, str]] = []
        seen = set()

        def _add(tech: str, category: str, evidence: str):
            key = (tech, category)
            if key not in seen:
                seen.add(key)
                detected.append({"technology": tech, "category": category, "evidence": evidence})

        records = domain_intel.get("dns_records") or {}
        mx_vals = " ".join(records.get("MX", [])).lower()
        ns_vals = " ".join(records.get("NS", [])).lower()
        txt_vals = " ".join(records.get("TXT", [])).lower()
        cname_vals = " ".join(records.get("CNAME", [])).lower()

        sig_rules = [
            ("cloudflare", "Cloudflare", "CDN / DNS", f"NS/CNAME match: {ns_vals[:80]}"),
            ("awsdns", "Amazon Route 53", "DNS Hosting", "NS contains awsdns"),
            ("google.com", "Google Workspace / DNS", "Mail / Cloud", "MX/NS references google.com"),
            ("aspmx.l.google", "Google Workspace", "Email Hosting", "MX record matches aspmx.l.google.com"),
            ("outlook.com", "Microsoft 365", "Email Hosting", "MX record matches outlook.com"),
            ("protection.outlook", "Microsoft Exchange Online Protection", "Email Security", "MX contains protection.outlook"),
            ("google-site-verification", "Google Search Console Verified", "Site Verification", "DNS TXT verification record"),
            ("v=spf1", "SPF Email Authentication", "Email Security", "DNS TXT v=spf1 policy"),
            ("amazonaws.com", "Amazon Web Services", "Cloud Infrastructure", f"CNAME/MX references amazonaws.com ({cname_vals[:60]})"),
            ("azure", "Microsoft Azure", "Cloud Infrastructure", "DNS record references Azure"),
            ("fastly", "Fastly", "CDN", "CNAME/NS references Fastly"),
        ]
        combined = f"{mx_vals} {ns_vals} {txt_vals} {cname_vals}"
        for needle, tech, cat, ev in sig_rules:
            if needle in combined:
                _add(tech, cat, ev)

        for hdr in (http_headers or []):
            srv = hdr.get("server_header")
            if srv and srv != "Not disclosed":
                _add(srv, "Web Server Banner", f"HTTP Server header ({hdr.get('url')})")
            pwr = hdr.get("powered_by")
            if pwr and pwr != "Not disclosed":
                _add(pwr, "Application Framework", f"X-Powered-By header ({hdr.get('url')})")

        return detected

    def _lookup_ip_geolocation(self, ip_addr: str) -> Dict[str, Any]:
        """Queries public IP geolocation for non-private routable IPs, falling back cleanly if private or offline."""
        try:
            ip_obj = ipaddress.ip_address(ip_addr)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                return {
                    "ip": ip_addr,
                    "status": "NOT_APPLICABLE",
                    "scope": "Private / Non-Routable Address",
                    "note": "Private RFC1918 / loopback addresses do not have public Internet geolocation."
                }
        except ValueError:
            return {"ip": ip_addr, "status": "INVALID"}
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip_addr}?fields=status,country,regionName,city,isp,org,as,query", timeout=min(self.timeout, 5))
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "ip": ip_addr,
                        "status": "SUCCESS",
                        "country": data.get("country"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "asn": data.get("as"),
                    }
            return {"ip": ip_addr, "status": "UNAVAILABLE", "reason": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"ip": ip_addr, "status": "UNAVAILABLE", "reason": str(e)}

    def run_selected_checks(
        self,
        target: str,
        selected_checks: List[str],
        allow_target_contact: bool = False,
        progress_cb=None
    ) -> Dict[str, Any]:
        """
        Executes only the explicitly chosen passive reconnaissance checks and
        compiles clean, non-fabricated structured intelligence.
        """
        clean = target.strip()
        ip_scope = self._classify_ip_scope(clean)
        is_ip = ip_scope["is_ip"]
        is_non_public_ip = ip_scope["is_non_public"]
        checks_set = set(selected_checks or [])

        domain_only_reasons = {
            "dns_records": "Domain DNS record lookup (A/AAAA/MX/NS/TXT/CNAME) applies to domains, not bare IP targets.",
            "dns_enumeration": "Extended domain DNS enumeration applies to domains, not bare IP targets.",
            "nameserver_analysis": "Authoritative nameserver analysis applies to domains, not bare IP targets.",
            "dns_security_posture": "SPF/DMARC/DNSSEC domain posture checks apply to domains, not bare IP targets.",
            "subdomains_ct": "Certificate Transparency subdomain enumeration requires a domain target.",
            "crtsh_history": "Certificate Transparency domain history (crt.sh) requires a domain target.",
            "public_emails": "Public email harvesting (theHarvester) requires a domain target.",
            "theharvester": "Search-engine OSINT (theHarvester) requires a domain target.",
            "search_engine_intel": "Search-engine domain intelligence applies to domain names, not bare IP targets.",
            "public_metadata": "Domain TXT metadata & CT issuer profiling requires a domain target.",
        }

        output: Dict[str, Any] = {
            "target": clean,
            "target_kind": "ip" if is_ip else "domain",
            "ip_scope": ip_scope["scope_label"] if is_ip else None,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "checks_requested": list(checks_set),
            "checks_executed": [],
            "checks_skipped": [],
            "unavailable_checks": [],
            "domain_intel": {
                "whois": None,
                "rdap": None,
                "dns_records": {},
                "dns_enumeration": {},
                "nameserver_analysis": None,
                "subdomains": [],
                "dns_security": None
            },
            "osint_intel": {
                "emails": [],
                "crtsh_certificates": [],
                "public_org_info": None,
                "public_metadata": None,
                "search_engine_intel": None,
                "technology_intel": [],
                "external_apis": {}
            },
            "infrastructure_intel": {
                "resolved_ips": [clean] if is_ip else [],
                "ip_intelligence": None,
                "reverse_dns": [],
                "asn_hosting": None,
                "ip_geolocation": None,
                "hosting_info": None,
                "tls_certificates": None,
                "http_headers": []
            },
            "errors": []
        }

        if is_ip:
            skipped_domain_ids = sorted(cid for cid in checks_set if cid in domain_only_reasons)
            for cid in skipped_domain_ids:
                reason = domain_only_reasons[cid]
                output["checks_executed"].append({
                    "id": cid,
                    "interaction_type": "Pure Passive",
                    "status": "SKIPPED",
                    "reason": reason,
                })
                output["checks_skipped"].append({"id": cid, "reason": reason})
            if skipped_domain_ids:
                output["unavailable_checks"].append({
                    "id": "domain_only_checks",
                    "skipped_ids": skipped_domain_ids,
                    "reason": (
                        f"Skipped {len(skipped_domain_ids)} domain-only passive module(s) inapplicable to IP target "
                        f"'{clean}' ({', '.join(skipped_domain_ids)})."
                    ),
                })

        def _notify(msg: str):
            if progress_cb:
                try:
                    progress_cb(msg)
                except Exception:
                    pass

        # 1. WHOIS
        if "whois_lookup" in checks_set:
            _notify(f"Running WHOIS lookup for {clean}...")
            try:
                if not is_ip:
                    w_rec = self.whois_collector.collect(clean)
                    wd = w_rec.whois_data
                    output["checks_executed"].append({"id": "whois_lookup", "interaction_type": "Pure Passive", "status": w_rec.scan_status})
                    output["domain_intel"]["whois"] = {
                        "registrar": getattr(wd, "registrar", None) if wd else None,
                        "organization": getattr(wd, "registrant_organization", None) if wd else None,
                        "creation_date": getattr(wd, "creation_date", None) if wd else None,
                        "expiration_date": getattr(wd, "expiration_date", None) if wd else None,
                        "name_servers": getattr(wd, "name_servers", []) if wd else [],
                        "status": w_rec.scan_status
                    }
                    if getattr(w_rec, "email_addresses", None):
                        output["osint_intel"]["emails"].extend(w_rec.email_addresses)
                elif is_non_public_ip:
                    # RFC 1918 / loopback / special-use IPs must NOT be attributed to IANA via public RIR whois
                    output["checks_executed"].append({
                        "id": "whois_lookup",
                        "interaction_type": "Pure Passive",
                        "status": "NOT_APPLICABLE",
                        "reason": ip_scope["note"],
                    })
                    output["checks_skipped"].append({"id": "whois_lookup", "reason": ip_scope["note"]})
                    output["domain_intel"]["whois"] = {
                        "scope": ip_scope["scope_label"],
                        "ownership_status": "Private / Unregistered Local Address Space (No Public RIR Assignment)",
                        "registrar": None,
                        "rir": None,
                        "organization": None,
                        "country": "LOCAL",
                        "status": "NOT_APPLICABLE",
                        "note": ip_scope["note"],
                    }
                else:
                    # Public IP WHOIS via CLI whois (filter out IANA special-purpose boilerplate)
                    import subprocess
                    proc = subprocess.run(["whois", clean], capture_output=True, text=True, timeout=self.timeout)
                    raw_w = proc.stdout or ""
                    org_m = re.search(r"^(?:OrgName|org-name|descr|owner|netname):\s*(.+)$", raw_w, re.MULTILINE | re.IGNORECASE)
                    ctry_m = re.search(r"^Country:\s*([A-Z]{2})$", raw_w, re.MULTILINE | re.IGNORECASE)
                    raw_org = org_m.group(1).strip() if org_m else None
                    is_iana_block = bool(
                        raw_org and ("internet assigned numbers authority" in raw_org.lower() or "iana-blk" in raw_w.lower())
                    )
                    extracted_emails = [
                        e for e in self._extract_emails(raw_w)
                        if not (is_iana_block and e.lower().endswith("@iana.org"))
                    ]
                    rir_name = "Regional Internet Registry"
                    upper_w = raw_w.upper()
                    for cand_rir in ("ARIN", "RIPE", "APNIC", "LACNIC", "AFRINIC"):
                        if cand_rir in upper_w:
                            rir_name = cand_rir
                            break
                    output["checks_executed"].append({
                        "id": "whois_lookup",
                        "interaction_type": "Pure Passive",
                        "status": "NOT_APPLICABLE" if is_iana_block else ("SUCCESS" if raw_w else "PARTIAL"),
                    })
                    output["domain_intel"]["whois"] = {
                        "scope": ip_scope["scope_label"],
                        "ownership_status": (
                            "Special-Purpose Reservation (No Target Organization Attribution)"
                            if is_iana_block
                            else ("Public RIR Netblock" if raw_org else "Undisclosed")
                        ),
                        "rir": rir_name,
                        "registrar": None,
                        "organization": None if is_iana_block else raw_org,
                        "country": None if is_iana_block else (ctry_m.group(1).strip() if ctry_m else None),
                        "status": "NOT_APPLICABLE" if is_iana_block else ("SUCCESS" if proc.returncode == 0 else "PARTIAL"),
                    }
                    output["osint_intel"]["emails"].extend(extracted_emails)
            except Exception as e:
                output["checks_executed"].append({"id": "whois_lookup", "interaction_type": "Pure Passive", "status": "FAILED", "error": str(e)})
                output["errors"].append(f"WHOIS failed: {str(e)}")

        # 2. RDAP
        if "rdap_lookup" in checks_set or "asn_ip_hosting" in checks_set:
            _notify(f"Running RDAP / ASN infrastructure lookup for {clean}...")
            try:
                rdap_data = self.rdap_collector.lookup_ip(clean) if is_ip else self.rdap_collector.lookup_domain(clean)
                raw_rdap_stat = rdap_data.get("status", "UNAVAILABLE") if isinstance(rdap_data, dict) else "UNAVAILABLE"
                if raw_rdap_stat == "LOCAL_PRIVATE_IP":
                    status = "NOT_APPLICABLE"
                elif rdap_data and raw_rdap_stat not in ("ERROR", "NOT_FOUND"):
                    status = "SUCCESS"
                else:
                    status = raw_rdap_stat
                if "rdap_lookup" in checks_set:
                    output["checks_executed"].append({"id": "rdap_lookup", "interaction_type": "Pure Passive", "status": status})
                if "asn_ip_hosting" in checks_set:
                    output["checks_executed"].append({"id": "asn_ip_hosting", "interaction_type": "Pure Passive", "status": status})
                output["domain_intel"]["rdap"] = rdap_data
                if isinstance(rdap_data, dict):
                    output["infrastructure_intel"]["asn_hosting"] = {
                        "handle": rdap_data.get("handle"),
                        "name": rdap_data.get("name"),
                        "scope": rdap_data.get("scope"),
                        "ownership_status": rdap_data.get("ownership_status"),
                        "start_address": rdap_data.get("start_address"),
                        "end_address": rdap_data.get("end_address"),
                        "country": rdap_data.get("country"),
                        "cidr": rdap_data.get("cidr"),
                        "org": rdap_data.get("org") or (output["domain_intel"].get("whois") or {}).get("organization")
                    }
            except Exception as e:
                output["errors"].append(f"RDAP lookup failed: {str(e)}")

        # 3. DNS Records, Enumeration, Nameserver Analysis & DNS Security (Domain targets only)
        dns_needed = ("dns_records", "dns_security_posture", "dns_enumeration", "nameserver_analysis", "ip_intelligence", "hosting_info", "technology_intel", "public_org_info", "public_metadata")
        if not is_ip and any(c in checks_set for c in dns_needed):
            _notify(f"Querying DNS records for {clean}...")
            try:
                d_rec = self.dns_collector.collect(clean, record_types=["A", "AAAA", "MX", "NS", "TXT", "CNAME"])
                records: Dict[str, List[str]] = {}
                for rec in (d_rec.dns_records or []):
                    rt = rec.record_type
                    records.setdefault(rt, []).append(rec.value)
                output["domain_intel"]["dns_records"] = records
                output["infrastructure_intel"]["resolved_ips"].extend(records.get("A", []) + records.get("AAAA", []))
                if "dns_records" in checks_set:
                    output["checks_executed"].append({"id": "dns_records", "interaction_type": "Pure Passive", "status": d_rec.scan_status})

                if "dns_enumeration" in checks_set:
                    enum_res = self._enumerate_extended_dns(clean)
                    output["domain_intel"]["dns_enumeration"] = enum_res
                    output["checks_executed"].append({"id": "dns_enumeration", "interaction_type": "Pure Passive", "status": "SUCCESS" if enum_res else "PARTIAL"})

                if "nameserver_analysis" in checks_set:
                    ns_res = self._analyze_nameservers(clean, ns_records=records.get("NS"))
                    output["domain_intel"]["nameserver_analysis"] = ns_res
                    output["checks_executed"].append({"id": "nameserver_analysis", "interaction_type": "Pure Passive", "status": "SUCCESS"})

                if "dns_security_posture" in checks_set:
                    sec_posture = self._inspect_dns_security(clean, existing_txt=records.get("TXT"))
                    output["domain_intel"]["dns_security"] = sec_posture
                    output["checks_executed"].append({"id": "dns_security_posture", "interaction_type": "Pure Passive", "status": "SUCCESS"})
            except Exception as e:
                output["errors"].append(f"DNS lookup failed: {str(e)}")

        # 4. Certificate Transparency / Subdomains / Passive Certificate Info (Domain targets only)
        if not is_ip and ("subdomains_ct" in checks_set or "crtsh_history" in checks_set or "certificate_info" in checks_set):
            _notify(f"Checking Certificate Transparency logs (crt.sh) for {clean}...")
            ct = self._query_crtsh(clean)
            output["domain_intel"]["subdomains"] = sorted(set(output["domain_intel"]["subdomains"] + ct.get("subdomains", [])))
            output["osint_intel"]["crtsh_certificates"] = ct.get("certificates", [])
            for cid in ("subdomains_ct", "crtsh_history", "certificate_info"):
                if cid in checks_set:
                    output["checks_executed"].append({"id": cid, "interaction_type": "Pure Passive", "status": ct.get("status", "UNKNOWN"), "error": ct.get("error")})
        elif is_ip and "certificate_info" in checks_set and not allow_target_contact:
            cert_reason = "Passive CT log history requires a domain target; direct certificate inspection requires allow_target_contact."
            output["checks_executed"].append({"id": "certificate_info", "interaction_type": "Pure Passive", "status": "SKIPPED", "reason": cert_reason})
            output["checks_skipped"].append({"id": "certificate_info", "reason": cert_reason})

        # 5. theHarvester & Search Engine OSINT (Domain targets only)
        if not is_ip and ("public_emails" in checks_set or "theharvester" in checks_set or "search_engine_intel" in checks_set):
            _notify(f"Running external OSINT collector for {clean}...")
            try:
                h_rec = self.harvester.collect(clean)
                output["domain_intel"]["subdomains"] = sorted(set(output["domain_intel"]["subdomains"] + (h_rec.discovered_domains or [])))
                output["osint_intel"]["emails"] = sorted(set(output["osint_intel"]["emails"] + (h_rec.email_addresses or [])))
                output["infrastructure_intel"]["resolved_ips"] = sorted(set(output["infrastructure_intel"]["resolved_ips"] + (h_rec.ip_addresses or [])))
                if "search_engine_intel" in checks_set:
                    output["osint_intel"]["search_engine_intel"] = {
                        "hosts_found": h_rec.discovered_domains or [],
                        "emails_found": h_rec.email_addresses or [],
                        "ips_found": h_rec.ip_addresses or [],
                        "status": h_rec.scan_status
                    }
                    output["checks_executed"].append({"id": "search_engine_intel", "interaction_type": "Pure Passive", "status": h_rec.scan_status})
                if "public_emails" in checks_set or "theharvester" in checks_set:
                    output["checks_executed"].append({"id": "public_emails", "interaction_type": "Pure Passive", "status": h_rec.scan_status})
            except Exception as e:
                output["errors"].append(f"OSINT harvester error: {str(e)}")

        # 6. Reverse DNS PTR lookups
        if "reverse_dns" in checks_set or "ip_intelligence" in checks_set or "hosting_info" in checks_set:
            ips_to_ptr = sorted(set(output["infrastructure_intel"]["resolved_ips"]))[:10]
            ptr_results = [self._reverse_dns_lookup(ip_addr) for ip_addr in ips_to_ptr]
            output["infrastructure_intel"]["reverse_dns"] = ptr_results
            if "reverse_dns" in checks_set:
                output["checks_executed"].append({"id": "reverse_dns", "interaction_type": "Pure Passive", "status": "SUCCESS"})

        # 7. External Exposure APIs (Shodan / VirusTotal) & Breach APIs
        if "external_exposure_apis" in checks_set:
            ext = self._query_external_exposure_apis(clean, is_ip)
            output["osint_intel"]["external_apis"] = ext
            any_ok = any(v.get("status") == "SUCCESS" for v in ext.values())
            output["checks_executed"].append({
                "id": "external_exposure_apis",
                "interaction_type": "Pure Passive",
                "status": "SUCCESS" if any_ok else "UNAVAILABLE",
                "note": "API keys not configured" if not any_ok else None
            })
            if not any_ok:
                output["unavailable_checks"].append({
                    "id": "external_exposure_apis",
                    "reason": "External exposure API keys (Shodan / VirusTotal) are not configured."
                })

        if "public_breach_metadata" in checks_set:
            output["unavailable_checks"].append({
                "id": "public_breach_metadata",
                "reason": "Third-party breach intelligence API key is not configured."
            })
            output["checks_executed"].append({
                "id": "public_breach_metadata",
                "interaction_type": "Pure Passive",
                "status": "UNAVAILABLE"
            })

        # 8. Optional Active Target Contact Infrastructure Checks (ONLY if permitted and selected)
        if "tls_certificate_inspect" in checks_set or ("certificate_info" in checks_set and allow_target_contact):
            if allow_target_contact:
                _notify(f"Performing read-only TLS certificate check (Active Target Contact) on {clean}:443...")
                tls_res = self._inspect_tls_certificate(clean)
                output["infrastructure_intel"]["tls_certificates"] = tls_res
                if "tls_certificate_inspect" in checks_set:
                    output["checks_executed"].append({"id": "tls_certificate_inspect", "interaction_type": "Active Target Contact", "status": tls_res.get("status")})
            elif "tls_certificate_inspect" in checks_set:
                output["unavailable_checks"].append({"id": "tls_certificate_inspect", "reason": "Direct TLS probe requires explicit target contact authorization."})

        if "http_header_inspect" in checks_set:
            if allow_target_contact:
                _notify(f"Inspecting HTTP headers (Active Target Contact) on {clean}...")
                hdrs = self._inspect_http_headers(clean)
                output["infrastructure_intel"]["http_headers"] = hdrs
                output["checks_executed"].append({"id": "http_header_inspect", "interaction_type": "Active Target Contact", "status": "SUCCESS"})
            else:
                output["unavailable_checks"].append({"id": "http_header_inspect", "reason": "Direct HTTP header inspection requires explicit target contact authorization."})

        # 9. Derived Infrastructure & OSINT Intelligence (no fabricated values)
        if "ip_intelligence" in checks_set or "hosting_info" in checks_set:
            rdap_obj = output["domain_intel"].get("rdap") or {}
            if not rdap_obj and output["infrastructure_intel"]["resolved_ips"]:
                try:
                    rdap_obj = self.rdap_collector.lookup_ip(output["infrastructure_intel"]["resolved_ips"][0]) or {}
                except Exception:
                    rdap_obj = {}
            if "ip_intelligence" in checks_set:
                output["infrastructure_intel"]["ip_intelligence"] = {
                    "resolved_ips": sorted(set(output["infrastructure_intel"]["resolved_ips"])),
                    "reverse_dns": output["infrastructure_intel"]["reverse_dns"],
                    "network_cidr": rdap_obj.get("cidr"),
                    "network_name": rdap_obj.get("name"),
                }
                output["checks_executed"].append({"id": "ip_intelligence", "interaction_type": "Pure Passive", "status": "SUCCESS"})
            if "hosting_info" in checks_set:
                output["infrastructure_intel"]["hosting_info"] = {
                    "organization": rdap_obj.get("org") or (output["domain_intel"].get("whois") or {}).get("organization"),
                    "asn_handle": rdap_obj.get("handle"),
                    "network_name": rdap_obj.get("name"),
                    "country": rdap_obj.get("country"),
                    "nameservers": (output["domain_intel"].get("dns_records") or {}).get("NS", [])
                }
                output["checks_executed"].append({"id": "hosting_info", "interaction_type": "Pure Passive", "status": "SUCCESS"})

        if "ip_geolocation" in checks_set:
            geo_ips = sorted(set(output["infrastructure_intel"]["resolved_ips"]))[:3]
            if geo_ips:
                geo_res = [self._lookup_ip_geolocation(ip_a) for ip_a in geo_ips]
                output["infrastructure_intel"]["ip_geolocation"] = geo_res
                any_geo = any(g.get("status") == "SUCCESS" for g in geo_res)
                any_na = any(g.get("status") == "NOT_APPLICABLE" for g in geo_res)
                geo_stat = "SUCCESS" if any_geo else ("NOT_APPLICABLE" if any_na else "UNAVAILABLE")
                output["checks_executed"].append({"id": "ip_geolocation", "interaction_type": "Pure Passive", "status": geo_stat})
            else:
                output["unavailable_checks"].append({"id": "ip_geolocation", "reason": "No resolved IP address available for geolocation lookup."})

        if "public_org_info" in checks_set:
            whois_d = output["domain_intel"].get("whois") or {}
            rdap_d = output["domain_intel"].get("rdap") or {}
            txt_recs = (output["domain_intel"].get("dns_records") or {}).get("TXT", [])
            verifications = [t for t in txt_recs if "verification=" in t.lower() or "ms=" in t.lower() or "docusign" in t.lower()]
            if is_non_public_ip:
                output["osint_intel"]["public_org_info"] = {
                    "scope": ip_scope["scope_label"],
                    "ownership_status": "Private / Unregistered Local Address Space",
                    "organization": None,
                    "registrar": None,
                    "country": "LOCAL",
                    "verification_tokens": []
                }
                output["checks_executed"].append({"id": "public_org_info", "interaction_type": "Pure Passive", "status": "NOT_APPLICABLE"})
            else:
                output["osint_intel"]["public_org_info"] = {
                    "organization": whois_d.get("organization") or rdap_d.get("org"),
                    "registrar": whois_d.get("registrar") or whois_d.get("rir"),
                    "country": rdap_d.get("country") or whois_d.get("country"),
                    "verification_tokens": verifications
                }
                output["checks_executed"].append({"id": "public_org_info", "interaction_type": "Pure Passive", "status": "SUCCESS"})

        if "public_metadata" in checks_set and not is_ip:
            txt_recs = (output["domain_intel"].get("dns_records") or {}).get("TXT", [])
            certs = output["osint_intel"].get("crtsh_certificates") or []
            output["osint_intel"]["public_metadata"] = {
                "txt_metadata_count": len(txt_recs),
                "txt_records_sample": txt_recs[:10],
                "certificate_issuers": sorted({str(c.get("issuer") or c.get("issuer_name") or "") for c in certs if (c.get("issuer") or c.get("issuer_name"))})[:10]
            }
            output["checks_executed"].append({"id": "public_metadata", "interaction_type": "Pure Passive", "status": "SUCCESS"})

        if "technology_intel" in checks_set:
            http_hdrs = output["infrastructure_intel"].get("http_headers", [])
            techs = self._detect_passive_technologies(output["domain_intel"], http_hdrs)
            output["osint_intel"]["technology_intel"] = techs
            if is_ip and not http_hdrs:
                output["checks_executed"].append({
                    "id": "technology_intel",
                    "interaction_type": "Pure Passive",
                    "status": "SKIPPED",
                    "reason": "Passive DNS technology profiling requires a domain target or HTTP header inspection.",
                })
            else:
                output["checks_executed"].append({"id": "technology_intel", "interaction_type": "Pure Passive", "status": "SUCCESS"})

        output["osint_intel"]["emails"] = sorted(set(output["osint_intel"]["emails"]))
        output["infrastructure_intel"]["resolved_ips"] = sorted(set(output["infrastructure_intel"]["resolved_ips"]))
        output["domain_intel"]["subdomains"] = sorted(set(output["domain_intel"]["subdomains"]))
        return output
