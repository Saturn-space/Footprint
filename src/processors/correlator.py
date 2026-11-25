"""
OSINT-RECON Correlator Module
Correlates passive reconnaissance findings, calculates asset metrics,
evaluates defensive posture indicators, and suggests defensive actions.
"""

from typing import List, Dict, Any, Tuple
from src.schema import NormalizedFinding, ReconRecord


class FindingCorrelator:
    """
    Correlates findings across WHOIS, DNS, and search engine harvesting.
    Derives defensive observations and generates footprint metrics.
    """

    def __init__(self):
        pass

    def correlate(
        self,
        target_domain: str,
        findings: List[NormalizedFinding],
        records: List[ReconRecord]
    ) -> Tuple[Dict[str, Any], List[str], List[str]]:
        """
        Correlates deduplicated findings and collector records.
        Returns: (summary_dict, defensive_observations, recommended_actions)
        """
        subdomains = [f.finding_value for f in findings if f.finding_type == "subdomain"]
        ip_addresses = [f.finding_value for f in findings if f.finding_type == "ip_address"]
        emails = [f.finding_value for f in findings if f.finding_type == "email"]
        nameservers = [f.finding_value for f in findings if f.finding_type == "nameserver"]
        registrars = [f.finding_value for f in findings if f.finding_type == "registrar"]
        dns_records = [f for f in findings if f.finding_type == "dns_record"]

        txt_records = [
            f.finding_value for f in dns_records
            if f.source_details.get("record_type") == "TXT"
        ]
        mx_records = [
            f.finding_value for f in dns_records
            if f.source_details.get("record_type") == "MX"
        ]

        # Extract WHOIS data if present
        whois_rec = next((r for r in records if r.recon_category == "whois" and r.whois_data), None)
        whois_data = whois_rec.whois_data if whois_rec else None

        # 1. Summary Statistics
        summary = {
            "target": target_domain,
            "total_normalized_findings": len(findings),
            "subdomains_count": len(subdomains),
            "ip_addresses_count": len(ip_addresses),
            "email_addresses_count": len(emails),
            "nameservers_count": len(nameservers),
            "mail_servers_count": len(mx_records),
            "registrar": registrars[0] if registrars else (whois_data.registrar if whois_data else "Unknown"),
            "creation_date": whois_data.creation_date if whois_data else None,
            "expiration_date": whois_data.expiration_date if whois_data else None,
            "dnssec_status": whois_data.dnssec if whois_data else "Unknown"
        }

        # 2. Defensive Observations
        observations: List[str] = []
        actions: List[str] = []

        # Check SPF in TXT records
        has_spf = any("v=spf1" in txt.lower() for txt in txt_records)
        if has_spf:
            observations.append("Email Authentication: SPF record detected in public DNS TXT records.")
        else:
            observations.append("Email Authentication: No valid SPF record detected in public DNS.")
            actions.append("Publish a strict Sender Policy Framework (SPF) TXT record to mitigate unauthorized domain spoofing.")

        # Check DMARC
        has_dmarc = any("v=dmarc1" in txt.lower() for txt in txt_records)
        if has_dmarc:
            observations.append("Email Security: DMARC policy specification detected.")
        else:
            observations.append("Email Security: No DMARC configuration found in queried TXT records.")
            actions.append("Deploy a DMARC policy (recommend starting with p=quarantine) to authenticate outbound mail streams.")

        # Check DNSSEC
        if whois_data and whois_data.dnssec and "signed" in whois_data.dnssec.lower():
            observations.append(f"Domain Integrity: DNSSEC is active ({whois_data.dnssec}).")
        else:
            observations.append("Domain Integrity: DNSSEC appears unsigned or status is unconfirmed.")
            actions.append("Enable DNSSEC signing at the registrar and DNS provider to protect against DNS cache poisoning.")

        # Check Public Email Exposure
        if emails:
            observations.append(f"Information Exposure: {len(emails)} public email address(es) discovered across search engines and registration data.")
            actions.append("Replace personal employee contact addresses with centralized role-based aliases (e.g., security@, hostmaster@) and enforce privacy redaction.")
        else:
            observations.append("Information Exposure: No public email addresses exposed across passive search engine queries.")

        # Check Subdomain Footprint
        if len(subdomains) > 5:
            observations.append(f"Perimeter Surface: Broad digital footprint with {len(subdomains)} publicly discoverable hostnames/subdomains.")
            actions.append("Regularly audit external DNS zones to prune stale subdomains and prevent subdomain takeover vulnerabilities.")
        elif subdomains:
            observations.append(f"Perimeter Surface: Compact digital footprint with {len(subdomains)} discovered hostnames.")

        return summary, observations, actions

