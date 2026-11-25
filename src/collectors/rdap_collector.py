"""
FootprintIQ - RDAP (Registration Data Access Protocol) Collector
Modern RESTful IP, ASN, and Domain registration data collector.
Complements and enhances traditional WHOIS reconnaissance.
"""

import ipaddress
import logging
from typing import Dict, Any, Optional
import requests

logger = logging.getLogger("FootprintIQ.RDAP")

DEFAULT_RDAP_TIMEOUT = 10


class RDAPCollector:
    def __init__(self, timeout: int = DEFAULT_RDAP_TIMEOUT):
        self.timeout = timeout

    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Queries RDAP for an IPv4 or IPv6 address.
        Recognizes private/reserved/local address space cleanly without public RIR misattribution.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_address.strip())
            cgnat = ipaddress.ip_network("100.64.0.0/10")
            is_cgnat = isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in cgnat
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
                or is_cgnat
            ):
                if ip_obj.is_loopback:
                    scope = "Loopback Address Space (RFC 1122)"
                elif ip_obj.is_link_local:
                    scope = "Link-Local Address Space (RFC 3927)"
                elif is_cgnat:
                    scope = "Carrier-Grade NAT Space (RFC 6598)"
                else:
                    scope = "Private / Internal Address Space (RFC 1918)"
                return {
                    "status": "LOCAL_PRIVATE_IP",
                    "ip": ip_address,
                    "name": scope,
                    "scope": scope,
                    "ownership_status": "Private / Unregistered Local Address Space",
                    "cidr": str(ip_address),
                    "country": "LOCAL",
                    "org": "Private / Internal Lab Network (Not Publicly Assigned)",
                    "remarks": [f"{scope}; public RIR RDAP queries were not sent."]
                }
        except ValueError:
            pass

        url = f"https://rdap.arin.net/registry/ip/{ip_address}"
        try:
            resp = requests.get(url, headers={"Accept": "application/rdap+json"}, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                return self._parse_rdap_response(data, ip_address)
            return {"status": "NOT_FOUND", "http_code": resp.status_code, "ip": ip_address}
        except Exception as e:
            logger.warning(f"RDAP query failed for IP {ip_address}: {e}")
            return {"status": "ERROR", "error": str(e), "ip": ip_address}

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Queries RDAP for a domain name.
        """
        url = f"https://rdap.org/domain/{domain}"
        try:
            resp = requests.get(url, headers={"Accept": "application/rdap+json"}, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                return self._parse_rdap_response(data, domain)
            return {"status": "NOT_FOUND", "http_code": resp.status_code, "domain": domain}
        except Exception as e:
            logger.warning(f"RDAP query failed for domain {domain}: {e}")
            return {"status": "ERROR", "error": str(e), "domain": domain}

    def _parse_rdap_response(self, data: Dict[str, Any], query: str) -> Dict[str, Any]:
        name = data.get("name") or data.get("handle", "")
        entities = []
        for ent in data.get("entities", []):
            handle = ent.get("handle")
            roles = ent.get("roles", [])
            entities.append({"handle": handle, "roles": roles})

        return {
            "status": "SUCCESS",
            "query": query,
            "handle": data.get("handle"),
            "name": name,
            "start_address": data.get("startAddress"),
            "end_address": data.get("endAddress"),
            "ip_version": data.get("ipVersion"),
            "country": data.get("country"),
            "entities": entities,
            "status_list": data.get("status", [])
        }

