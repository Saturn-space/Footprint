"""
FootprintIQ — Regression Tests for Combined Report Accuracy & Data Integrity Audit
Covers all 12 audited defects using exact test-3 (192.168.56.111 / SCAN-20261111-195010-1d03)
structures, raw NSE XML error output, raw Nuclei JSONL CVE-2012-1823 payload,
RFC 1918 passive target handling, idempotent evidence registration, and PDF vector/table consistency.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import unittest
import zlib
from unittest.mock import MagicMock, patch

from src.collectors.nse_collector import NSECollector
from src.collectors.nuclei_collector import NucleiCollector
from src.collectors.passive_intel_collector import PassiveIntelCollector
from src.collectors.rdap_collector import RDAPCollector
from src.db.repository import FootprintIQRepository
from src.reporting.unified_report import UnifiedReportGenerator
from src.services.exposure_scoring import ExposureScoringEngine
from src.services.finding_translator import classify_confidence, explain_finding_plain_language
from src.services.nse_policy_service import NSEPolicyService
from src.services.report_analysis_service import build_report_analysis


CVE_2012_1823_JSONL = json.dumps({
    "template": "http/cves/2012/CVE-2012-1823.yaml",
    "template-url": "https://cloud.projectdiscovery.io/public/CVE-2012-1823",
    "template-id": "CVE-2012-1823",
    "info": {
        "name": "PHP CGI v5.3.12/5.4.2 Remote Code Execution",
        "description": (
            "sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when "
            "configured as a CGI script (aka php-cgi), does not properly handle query strings."
        ),
        "severity": "high",
        "classification": {
            "cve-id": ["cve-2012-1823"],
            "cwe-id": ["cwe-20"],
            "cvss-metrics": "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "cvss-score": 7.5,
            "epss-score": 0.99998,
        },
        "remediation": "Upgrade to a patched version of PHP or apply the necessary security patches.",
    },
    "type": "http",
    "host": "192.168.56.111",
    "port": "80",
    "scheme": "http",
    "url": "http://192.168.56.111",
    "matched-at": "http://192.168.56.111/index.php?-d+allow_url_include%3don+-d+auto_prepend_file%3dphp%3a//input",
    "ip": "192.168.56.111",
    "curl-command": "curl -X 'POST' -d '<?php echo md5(\"CVE-2012-1823\");?>' 'http://192.168.56.111/...'",
    "matcher-status": True,
})


METASPLOIT_23_PORTS = [
    {"target_ip": "192.168.56.111", "port": port, "protocol": "tcp", "state": "open", "service": svc, "service_version": ver}
    for port, svc, ver in [
        (21, "ftp", "vsftpd 2.3.4"),
        (22, "ssh", "OpenSSH 4.7p1 Debian 8ubuntu1"),
        (23, "telnet", "Linux telnetd"),
        (25, "smtp", "Postfix smtpd"),
        (53, "domain", "ISC BIND 9.4.2"),
        (80, "http", "Apache httpd 2.2.8"),
        (111, "rpcbind", "2"),
        (139, "netbios-ssn", "Samba smbd 3.X - 4.X"),
        (445, "netbios-ssn", "Samba smbd 3.X - 4.X"),
        (512, "exec", "netkit-rsh rexecd"),
        (513, "login", ""),
        (514, "shell", "Netkit rshd"),
        (1099, "java-rmi", "GNU Classpath grmiregistry"),
        (1524, "bindshell", "Metasploitable root shell"),
        (2049, "nfs", "2-4"),
        (2121, "ftp", "ProFTPD 1.3.1"),
        (3306, "mysql", "MySQL 5.0.51a-3ubuntu5"),
        (5432, "postgresql", "PostgreSQL DB 8.3.0 - 8.3.7"),
        (5900, "vnc", "VNC"),
        (6000, "X11", ""),
        (6667, "irc", "UnrealIRCd"),
        (8009, "ajp13", "Apache Jserv"),
        (8180, "http", "Apache Tomcat/Coyote JSP engine 1.1"),
    ]
]


NSE_ABORT_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -Pn --script ... postgresql-info ..." start="1794420640">
<runstats>
  <finished time="1794420640" timestr="2026-11-11 19:50:40 UTC" summary="Nmap done at ...; 0 IP addresses (0 hosts up) scanned in 0.26 seconds" elapsed="0.26" exit="error" errormsg="NSE: failed to initialize the script engine: /usr/share/nmap/nse_main.lua:852: 'postgresql-info' did not match a category, filename, or directory"/>
  <hosts up="0" down="0" total="0"/>
</runstats>
</nmaprun>
"""


def _extract_pdf_text_variants(pdf_path: str) -> tuple[str, str]:
    """Decompresses ReportLab ASCII85+FlateDecode PDF streams into (spaced, compact)."""
    with open(pdf_path, "rb") as pf:
        raw = pf.read()
    chunks = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\n?endstream", raw, flags=re.DOTALL):
        blob = match.group(1).strip()
        content = None
        # ReportLab encodes streams with /ASCII85Decode then /FlateDecode
        if blob.endswith(b"~>"):
            try:
                content = zlib.decompress(base64.a85decode(blob[:-2], adobe=False))
            except Exception:
                content = None
        if content is None:
            try:
                content = zlib.decompress(base64.a85decode(blob, adobe=True))
            except Exception:
                pass
        if content is None:
            try:
                content = zlib.decompress(blob)
            except Exception:
                content = blob
        for lit in re.findall(rb"\(([^()\\]*(?:\\.[^()\\]*)*)\)", content):
            s = lit.decode("latin-1", errors="ignore")
            s = s.replace(r"\(", "(").replace(r"\)", ")").replace(r"\\", "\\")
            if s:
                chunks.append(s)
    spaced = " ".join(chunks)
    compact = "".join(c for c in "".join(chunks) if not c.isspace())
    return spaced, compact


class TestReportDataIntegrityAudit(unittest.TestCase):
    @staticmethod
    def _new_isolated_repo() -> FootprintIQRepository:
        repo = FootprintIQRepository()
        for attr in (
            "_mem_users", "_mem_investigations", "_mem_targets", "_mem_scans",
            "_mem_findings", "_mem_evidence", "_mem_reports", "_mem_recon_campaigns",
            "_mem_scan_events", "_mem_profiles", "_mem_outbox", "_mem_shares",
        ):
            setattr(repo, attr, {})
        repo._mem_audit = []
        repo._mem_remediation = []
        return repo

    def _build_test3_repo_fixture(self) -> tuple[FootprintIQRepository, str, str]:
        repo = self._new_isolated_repo()
        camp = repo.create_recon_campaign(
            name="test 3",
            target_value="192.168.56.111",
            target_type="ipv4",
            purpose="Compliance Readiness Review",
            selected_scan_types="Passive Intelligence (WHOIS/RDAP/DNS/theHarvester),Nmap Active Discovery,Nmap NSE,ProjectDiscovery Nuclei",
            scan_config_json=json.dumps({
                "selected_categories": ["passive", "active", "vulnerability"],
                "passive": {"selected_checks": ["whois_lookup", "rdap_lookup", "dns_records", "reverse_dns", "public_emails"]},
                "active": {"port_mode": "top_1000"},
                "vulnerability": {"engines": ["nse", "nuclei"], "nuclei_profile": "safe-all"},
                "targets": ["192.168.56.111"],
            }),
            creator_id=2,
            initial_status="Partially Completed",
            initial_stage="Partially Completed",
            authorized_by="investigator1",
            authorization_status="Authorized",
        )
        inv_id = camp["recon_id"]
        repo.create_investigation(
            title="test 3",
            description="Compliance audit verification",
            creator_id=2,
            investigation_id=inv_id,
        )
        repo.add_authorized_target(
            investigation_id=inv_id,
            target="192.168.56.111",
            name="test 3 Target",
            scope="192.168.56.111 authorized scope",
            permitted_profiles="lab-basic,default",
            allowed_ports="1-65535",
            authorized_by="investigator1",
        )

        sc = repo.create_scan_execution(
            investigation_id=inv_id,
            recon_id=inv_id,
            scan_type="passive,active,vulnerability",
            target="192.168.56.111",
            profile="lab-basic",
            selected_scanners=["Passive Intelligence", "Nmap Active Discovery", "Nmap NSE", "ProjectDiscovery Nuclei"],
        )
        scan_id = sc["scan_id"]

        # Normalize exact Nuclei finding from real JSONL
        findings = NucleiCollector.parse_jsonl_output(
            CVE_2012_1823_JSONL,
            default_target="192.168.56.111",
            investigation_id=inv_id,
            scan_id=scan_id,
            evidence_reference="4,02844ad90c5973",
        )[0]
        self.assertEqual(len(findings), 1)
        f0 = dict(findings[0])
        repo.add_vulnerability_finding(inv_id, f0, scan_id=scan_id)

        # Register passive IP intel without IANA false attribution
        passive_bundle_item = {
            "target": "192.168.56.111",
            "target_kind": "ip",
            "ip_scope": {
                "is_ip": True,
                "is_non_public": True,
                "scope_label": "Private / Internal Network (RFC 1918)",
            },
            "domain_intel": {
                "whois": {
                    "status": "NOT_APPLICABLE",
                    "ownership_status": "private_ip_rfc1918",
                    "scope": "Private / Internal Network (RFC 1918)",
                    "isp": "Local / Unregistered Private Network",
                },
                "rdap": {
                    "status": "LOCAL_PRIVATE_IP",
                    "ip": "192.168.56.111",
                    "scope": "Private / Internal Network (RFC 1918)",
                    "org": "Private / Internal Lab Network (Not Publicly Assigned)",
                    "country": "LOCAL",
                },
                "reverse_dns": [],
                "dns_records": {},
                "subdomains": [],
            },
            "osint_intel": {"emails": []},
            "infrastructure_intel": {"resolved_ips": ["192.168.56.111"], "reverse_dns": []},
            "unavailable_checks": [
                {
                    "id": "domain_only_checks",
                    "status": "SKIPPED",
                    "reason": "Skipped domain-only passive modules inapplicable to IP target '192.168.56.111' (dns_records, subdomains_ct, public_emails, theharvester, search_engine_intel).",
                }
            ],
        }

        result_summary = {
            "target": "192.168.56.111",
            "targets": ["192.168.56.111"],
            "status": "Partially Completed",
            "findings_count": 1,
            "exposure_score": 31.8,
            "exposure_level": "Low",
            "scanners_executed": ["passive_recon", "nmap_services", "nmap_nse", "nuclei"],
            "scanner_statuses": [
                {
                    "scanner": "Passive Intelligence",
                    "target": "192.168.56.111",
                    "status": "COMPLETED",
                    "findings": 0,
                    "detail": "IP target 192.168.56.111 (RFC 1918 Private Network); domain-only checks skipped.",
                },
                {
                    "scanner": "Active Port & Service Scan",
                    "target": "192.168.56.111",
                    "status": "COMPLETED",
                    "findings": 0,
                    "detail": "Hosts UP: 1, Open ports: 23",
                },
                {
                    "scanner": "Nmap NSE Assessment",
                    "target": "192.168.56.111",
                    "status": "FAILED",
                    "findings": 0,
                    "detail": "NSE engine error: postgresql-info script failed to initialize (hosts up: 0).",
                },
                {
                    "scanner": "ProjectDiscovery Nuclei",
                    "target": "192.168.56.111",
                    "status": "PARTIAL",
                    "findings": 1,
                    "detail": "Profile: safe-all | Findings: 1 | Timeout at 180s (remaining templates skipped)",
                },
            ],
            "failed_stages": ["Nmap NSE Assessment"],
            "partial_stages": ["ProjectDiscovery Nuclei"],
            "passive_results": [passive_bundle_item],
            "active_hosts": [{"ip": "192.168.56.111", "status": "up", "open_ports_count": 23}],
            "discovered_ports": METASPLOIT_23_PORTS,
        }

        repo.update_scan_execution(
            scan_id=scan_id,
            status="partially_completed",
            result_summary_json=json.dumps(result_summary),
        )
        return repo, inv_id, scan_id

    def test_01_risk_score_formula_transparency_and_open_ports_context(self):
        findings = NucleiCollector.parse_jsonl_output(
            CVE_2012_1823_JSONL,
            default_target="192.168.56.111",
            investigation_id="FIQ-INV-1",
            scan_id="SCAN-1",
        )[0]
        exp = ExposureScoringEngine.calculate_investigation_exposure(
            findings,
            discovered_ports=METASPLOIT_23_PORTS,
        )
        # Observed High CVSS 7.5 at 0.90 confidence -> 75 * 0.85 * 0.90 = 57.375 -> 100*(1-exp(-57.4/150)) = 31.8
        self.assertEqual(exp["exposure_score"], 31.8)
        self.assertEqual(exp["exposure_level"], "Low")
        self.assertEqual(exp["scoring_breakdown"]["scale_divisor"], 150.0)
        self.assertEqual(exp["scoring_breakdown"]["observed_or_unverified_count"], 1)
        self.assertEqual(exp["scoring_breakdown"]["verified_count"], 0)
        self.assertEqual(exp["scoring_breakdown"]["open_ports_count"], 23)
        self.assertFalse(exp["scoring_breakdown"]["open_ports_scored_directly"])
        self.assertIn("1 - exp", exp["scoring_formula"])

        repo, inv_id, scan_id = self._build_test3_repo_fixture()
        analysis = build_report_analysis(inv_id, repo, scan_id=scan_id)
        ri = analysis["risk_interpretation"]
        self.assertEqual(ri["exposure_score"], 31.8)
        self.assertIn("1 - exp", ri["formula_note"])
        self.assertNotIn("Critical=30", ri["formula_note"])
        self.assertEqual(ri["confirmed_findings"], 0)
        self.assertEqual(ri["observed_findings"], 1)
        self.assertTrue(any("23 open port" in d for d in ri["drivers"]))
        self.assertTrue(any("Incomplete scanner execution" in d for d in ri["drivers"]))

    def test_02_03_04_charts_tables_and_affected_hosts_stay_unified(self):
        repo, inv_id, scan_id = self._build_test3_repo_fixture()
        analysis = build_report_analysis(inv_id, repo, scan_id=scan_id)

        hosts = analysis["vulnerability_analysis"]["affected_hosts"]
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["host"], "192.168.56.111")
        self.assertEqual(hosts[0]["finding_count"], 1)
        self.assertEqual(hosts[0]["findings_count"], 1)

        contrib_map = {r["tool_key"]: r for r in analysis["analytics"]["scanner_contribution"]}
        self.assertEqual(contrib_map["nuclei"]["execution_state"], "partial")
        self.assertEqual(contrib_map["nuclei"]["status_badge"], "PARTIAL")
        self.assertEqual(contrib_map["nuclei"]["unique_count"], 1)
        self.assertEqual(contrib_map["nuclei"]["unique_findings"], 1)
        self.assertEqual(contrib_map["nmap_nse"]["execution_state"], "failed")
        self.assertEqual(contrib_map["nmap_nse"]["status_badge"], "FAILED")
        self.assertEqual(contrib_map["nmap"]["execution_state"], "executed_zero_findings")
        self.assertEqual(contrib_map["nmap"]["status_badge"], "COMPLETED WITH ZERO FINDINGS")
        self.assertEqual(contrib_map["theharvester"]["execution_state"], "skipped")
        self.assertEqual(contrib_map["whois_rdap_dns"]["execution_state"], "executed_zero_findings")

        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_path = os.path.join(tmpdir, "test_3_fixed.pdf")
            gen = UnifiedReportGenerator(storage_client=MagicMock())
            scan_rec = repo.get_scan(scan_id)
            summary_json = json.loads(scan_rec["result_summary_json"])
            gen.generate_pdf_report(
                investigation=repo.get_recon_campaign(inv_id),
                targets=repo.list_authorized_targets(inv_id),
                findings=repo.list_findings(inv_id, scan_id=scan_id),
                evidence=[],
                output_path=pdf_path,
                report_format="combined",
                results_bundle={
                    "passive_results": summary_json["passive_results"],
                    "active_hosts": summary_json["active_hosts"],
                    "discovered_ports": METASPLOIT_23_PORTS,
                    "scanner_statuses": summary_json["scanner_statuses"],
                    "failed_stages": ["Nmap NSE Assessment"],
                    "partial_stages": ["ProjectDiscovery Nuclei"],
                },
                analysis=analysis,
                scan_run=scan_rec,
            )
            spaced, _ = _extract_pdf_text_variants(pdf_path)
            self.assertIn("ProjectDiscovery Nuclei [PARTIAL]", spaced)
            self.assertNotIn("nuclei [OK]", spaced)
            self.assertIn("Nmap NSE [FAILED]", spaced)
            self.assertIn("theHarvester [SKIP]", spaced)
            self.assertIn("192.168.56.111", spaced)
            self.assertIn("COMPLETED WITH ZERO FINDINGS", spaced)
            self.assertIn("Observed Scanner Match", spaced)

    def test_05_idempotent_evidence_and_finding_registration(self):
        repo = self._new_isolated_repo()
        inv_id = "FIQ-REC-IDEMP"
        scan_id = "SCAN-IDEMP-1"
        digest = hashlib.sha256(CVE_2012_1823_JSONL.encode()).hexdigest()

        r1 = repo.add_evidence_record(
            investigation_id=inv_id,
            scan_id=scan_id,
            evidence_type="nuclei_jsonl",
            file_name=f"nuclei_{scan_id}_safe-all.jsonl",
            file_size=len(CVE_2012_1823_JSONL),
            sha256_hash=digest,
            seaweed_fid="4,02844ad90c5973",
            scanner_source="nuclei",
        )
        r2 = repo.add_evidence_record(
            investigation_id=inv_id,
            scan_id=scan_id,
            evidence_type="nuclei_jsonl",
            file_name=f"nuclei_{scan_id}_safe-all.jsonl",
            file_size=len(CVE_2012_1823_JSONL),
            sha256_hash=digest,
            seaweed_fid="",
            scanner_source="nuclei",
        )
        self.assertEqual(r1["evidence_id"], r2["evidence_id"])
        all_ev = repo.list_evidence(inv_id, scan_id=scan_id)
        self.assertEqual(len(all_ev), 1)
        self.assertEqual(all_ev[0]["seaweed_fid"], "4,02844ad90c5973")

        # Findings registration must also be idempotent per (investigation_id, scan_id, finding_id)
        f = NucleiCollector.parse_jsonl_output(CVE_2012_1823_JSONL, "192.168.56.111", inv_id, scan_id)[0][0]
        repo.add_vulnerability_finding(inv_id, f, scan_id=scan_id)
        repo.add_vulnerability_finding(inv_id, f, scan_id=scan_id)
        self.assertEqual(len(repo.list_findings(inv_id, scan_id=scan_id)), 1)

    def test_06_nse_and_nuclei_partial_failed_audit(self):
        # Verify uninstalled script postgresql-info is cleanly filtered when /usr/share/nmap/scripts exists
        if os.path.isdir("/usr/share/nmap/scripts") and not os.path.isfile("/usr/share/nmap/scripts/postgresql-info.nse"):
            valid, missing = NSEPolicyService.filter_installed_scripts(["banner", "mysql-info", "postgresql-info"])
            self.assertIn("postgresql-info", missing)
            self.assertNotIn("postgresql-info", valid)
            self.assertEqual(valid, ["banner", "mysql-info"])

        # Verify NSECollector parses <runstats><finished exit="error" .../> honestly as FAILED
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as tf:
            tf.write(NSE_ABORT_XML)
            xml_path = tf.name
        try:
            meta = NSECollector._extract_nse_runstats(xml_path)
            self.assertEqual(meta["exit"], "error")
            self.assertEqual(meta["hosts_up"], 0)
            self.assertIn("postgresql-info", meta["errormsg"])
        finally:
            os.remove(xml_path)

        # Verify NucleiCollector marks partial findings + timed-out process as PARTIAL (never COMPLETED)
        collector = NucleiCollector()
        fake_proc = MagicMock()
        fake_proc.poll.return_value = None
        fake_proc.returncode = -15
        fake_proc.communicate.return_value = (CVE_2012_1823_JSONL + "\n", "timeout partial")

        with patch.object(collector, "check_readiness", return_value={"ready": True, "binary_path": "/usr/bin/nuclei", "templates_dir": "/tmp"}), \
             patch.object(collector.authorizer, "authorize_target", return_value=MagicMock(authorized=True)), \
             patch("src.collectors.nuclei_collector.NucleiPolicyService.build_target_urls", return_value=["http://192.168.56.111"]), \
             patch("src.collectors.nuclei_collector.NucleiPolicyService.build_cli_arguments", return_value=(["nuclei"], {"profile": "safe-all", "template_subdirs": ["http/cves"], "rate_limit": 30, "concurrency": 10})), \
             patch("src.collectors.nuclei_collector.subprocess.Popen", return_value=fake_proc), \
             patch("src.collectors.nuclei_collector.time.monotonic", side_effect=[0.0, 200.0, 200.1]), \
             patch.object(collector.storage, "upload_content", return_value={"seaweed_fid": "4,02844ad90c5973", "file_name": "nuclei.jsonl"}):
            res = collector.run_scan("192.168.56.111", "FIQ-INV", scan_id="SCAN-1", profile="safe-all", timeout=15)
        self.assertEqual(res["status"], "PARTIAL")
        self.assertTrue(res["timed_out"])
        self.assertEqual(len(res["findings"]), 1)
        self.assertEqual(res["execution_meta"]["returncode"], -15)
        self.assertIn("Timeout reached", res["error"])
        self.assertTrue(len(res["skipped_checks"]) >= 1)

    def test_07_cve_2012_1823_observed_scanner_match_never_overstated(self):
        findings, raw_count, parse_err = NucleiCollector.parse_jsonl_with_stats(
            CVE_2012_1823_JSONL,
            default_target="192.168.56.111",
            investigation_id="FIQ-INV",
            scan_id="SCAN-1",
        )
        self.assertEqual(raw_count, 1)
        self.assertEqual(parse_err, 0)
        f = findings[0]
        self.assertEqual(f["verification_status"], "Observed")
        self.assertEqual(f["cve_identifiers"], "CVE-2012-1823")
        self.assertEqual(f["cvss_score"], 7.5)
        self.assertIn("matcher-status: true", f["description"].lower())
        self.assertIn("non-destructive", f["description"].lower())

        self.assertEqual(classify_confidence(f), "Observed Scanner Match")
        exp = explain_finding_plain_language(f)
        self.assertEqual(exp["confidence_label"], "Observed Scanner Match")
        self.assertNotIn("Confirmed Vulnerability", exp["confidence_label"])

        verified_f = dict(f, verification_status="Verified")
        self.assertEqual(classify_confidence(verified_f), "Confirmed Vulnerability")

    def test_08_09_passive_ip_scope_and_validation_no_iana_no_dups(self):
        rdap = RDAPCollector().lookup_ip("192.168.56.111")
        self.assertEqual(rdap["status"], "LOCAL_PRIVATE_IP")
        self.assertNotIn("Internet Assigned Numbers Authority", json.dumps(rdap))

        pic = PassiveIntelCollector(timeout=2)
        with patch.object(pic, "_reverse_dns_lookup", return_value={"status": "NO_PTR", "ip": "192.168.56.111", "ptr_records": []}), \
             patch.object(pic, "_inspect_tls_certificate", return_value={"status": "SKIPPED"}), \
             patch.object(pic, "_inspect_http_headers", return_value=[]):
            out = pic.run_selected_checks(
                "192.168.56.111",
                selected_checks=["whois_lookup", "rdap_lookup", "dns_records", "subdomains_ct", "public_emails", "theharvester", "ip_geolocation", "public_org_info"],
                allow_target_contact=False,
            )
        dump = json.dumps(out)
        self.assertEqual(out["target_kind"], "ip")
        self.assertEqual(out["ip_scope"], "Private / Internal Network (RFC 1918)")
        self.assertNotIn("Internet Assigned Numbers Authority", dump)
        self.assertNotIn("abuse@iana.org", dump)
        self.assertEqual(out["osint_intel"]["emails"], [])
        self.assertEqual(len(out["unavailable_checks"]), 1)
        self.assertEqual(out["unavailable_checks"][0]["id"], "domain_only_checks")

    def test_10_11_12_untruncated_evidence_dedup_limitations_and_run_isolation(self):
        repo, inv_id, scan_id = self._build_test3_repo_fixture()

        # Register long-named evidence records under Run 001
        ev_names = [
            ("passive_intel_json", f"passive_intel_192.168.56.111_{scan_id}.json", "2,02844ad9110022"),
            ("nuclei_jsonl", f"nuclei_{scan_id}_safe-all.jsonl", "4,02844ad90c5973"),
        ]
        for etype, fname, fid in ev_names:
            digest = hashlib.sha256(fname.encode()).hexdigest()
            repo.add_evidence_record(
                investigation_id=inv_id,
                scan_id=scan_id,
                evidence_type=etype,
                file_name=fname,
                file_size=2202,
                sha256_hash=digest,
                seaweed_fid=fid,
            )

        # Add a second scan run AND a second investigation to verify strict isolation
        sc2 = repo.create_scan_execution(
            investigation_id=inv_id,
            recon_id=inv_id,
            scan_type="active",
            target="192.168.56.111",
        )
        scan2_id = sc2["scan_id"]
        repo.update_scan_execution(
            scan_id=scan2_id,
            status="completed",
            result_summary_json=json.dumps({
                "scanner_statuses": [{"scanner": "Nessus", "target": "192.168.56.111", "status": "COMPLETED", "findings": 1}],
                "discovered_ports": [{"target_ip": "192.168.56.111", "port": 9999, "protocol": "tcp", "state": "open", "service": "leak-test"}],
            }),
        )
        repo.add_vulnerability_finding(
            inv_id,
            {
                "finding_id": "RUN2-LEAK-CHECK",
                "target_ip": "10.99.99.99",
                "port": 9999,
                "title": "Synthetic Run 002 Finding Must Not Leak Into Run 001",
                "severity": "Critical",
                "cvss_score": 9.8,
                "detection_source": "nessus",
            },
            scan_id=scan2_id,
        )
        repo.add_evidence_record(
            investigation_id=inv_id,
            scan_id=scan2_id,
            evidence_type="nessus_xml",
            file_name="should_not_appear_in_run1.nessus",
            file_size=100,
            sha256_hash="a" * 64,
            seaweed_fid="9,99999999",
        )

        analysis = build_report_analysis(inv_id, repo, scan_id=scan_id)
        self.assertEqual(analysis["executive_analysis"]["findings_count"], 1)
        self.assertNotIn("10.99.99.99", json.dumps(analysis["vulnerability_analysis"]["affected_hosts"]))

        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_path = os.path.join(tmpdir, "run1_isolated_combined.pdf")
            summary_json = json.loads(repo.get_scan(scan_id)["result_summary_json"])
            gen = UnifiedReportGenerator(storage_client=MagicMock())
            gen.generate_pdf_report(
                investigation=repo.get_recon_campaign(inv_id),
                targets=repo.list_authorized_targets(inv_id),
                findings=repo.list_findings(inv_id, scan_id=scan_id),
                evidence=repo.list_evidence(inv_id, scan_id=scan_id),
                output_path=pdf_path,
                report_format="combined",
                results_bundle={
                    "passive_results": summary_json["passive_results"],
                    "active_hosts": summary_json["active_hosts"],
                    "discovered_ports": summary_json["discovered_ports"],
                    "scanner_statuses": summary_json["scanner_statuses"],
                    "failed_stages": summary_json["failed_stages"],
                    "partial_stages": summary_json["partial_stages"],
                },
                analysis=analysis,
                scan_run=repo.get_scan(scan_id),
            )
            spaced, compact = _extract_pdf_text_variants(pdf_path)
            # Full filenames and SeaweedFS FIDs preserved cleanly without truncation
            self.assertIn(f"passive_intel_192.168.56.111_{scan_id}.json", compact)
            self.assertIn(f"nuclei_{scan_id}_safe-all.jsonl", compact)
            self.assertIn("4,02844ad90c5973", compact)
            self.assertNotIn("should_not_appear_in_run1.nessus", compact)
            self.assertNotIn("Synthetic Run 002 Finding", spaced)
            self.assertNotIn("Internet Assigned Numbers Authority", spaced)
            self.assertEqual(spaced.count("domain_only_checks"), 1)


if __name__ == "__main__":
    unittest.main()
