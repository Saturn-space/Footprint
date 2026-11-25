"""
FootprintIQ - Demo Investigation Seeder
Populates 5 comprehensive, realistic combined scanning demo investigations
with multiple completed scan runs, discovered ports, normalized findings,
evidence records, and verified PDF reports.

Designed for instant, high-fidelity demonstrations without altering
any core application logic or security rules.
"""

import os
import sys
import json
import hashlib
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.db.repository import FootprintIQRepository, utcnow
from src.services.exposure_scoring import ExposureScoringEngine
from src.services.recon_results_helper import load_campaign_results_bundle
from src.services.report_analysis_service import build_report_analysis
from src.reporting.unified_report import UnifiedReportGenerator

logger = logging.getLogger("FootprintIQ.DemoSeeder")

REPORTS_DIR = os.path.abspath("reports")
EVIDENCE_CACHE_DIR = os.path.abspath(os.path.join("data", "evidence_cache"))


DEMO_CAMPAIGNS_DEF = [
    # -------------------------------------------------------------------------
    # 1. Metasploitable2 Vulnerability Assessment (23 ports, high legacy exposure)
    # -------------------------------------------------------------------------
    {
        "key": "DEMO-001",
        "name": "Metasploitable2 Vulnerability Assessment",
        "target_value": "192.168.56.111",
        "target_type": "ipv4",
        "purpose": "Internal Lab Security Audit",
        "description": "Full combined active and passive security assessment of vulnerable Linux server with legacy network services.",
        "scope_description": "192.168.56.111 (Host-Only Network 192.168.56.0/24)",
        "hostname": "metasploitable2.local",
        "discovered_ports": [
            {"target_ip": "192.168.56.111", "port": 21, "protocol": "tcp", "service": "ftp", "product": "vsftpd", "version": "2.3.4", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "4.7p1 Debian 8ubuntu1", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 23, "protocol": "tcp", "service": "telnet", "product": "Linux telnetd", "version": "", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 25, "protocol": "tcp", "service": "smtp", "product": "Postfix smtpd", "version": "", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 53, "protocol": "tcp", "service": "domain", "product": "ISC BIND", "version": "9.4.2", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd", "version": "2.2.8", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 111, "protocol": "tcp", "service": "rpcbind", "product": "2 (rpcbind)", "version": "", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 139, "protocol": "tcp", "service": "netbios-ssn", "product": "Samba smbd", "version": "3.X - 4.X", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 445, "protocol": "tcp", "service": "microsoft-ds", "product": "Samba smbd", "version": "3.0.20-Debian", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 512, "protocol": "tcp", "service": "exec", "product": "netkit-rsh rexecd", "version": "", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 513, "protocol": "tcp", "service": "login", "product": "OpenBSD rlogind", "version": "", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 514, "protocol": "tcp", "service": "shell", "product": "Netkit rshd", "version": "", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 1099, "protocol": "tcp", "service": "rmiregistry", "product": "GNU Classpath grmiregistry", "version": "", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 1524, "protocol": "tcp", "service": "bindshell", "product": "Metasploitable root shell", "version": "", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 2049, "protocol": "tcp", "service": "nfs", "product": "NFS", "version": "2-4 (RPC #100003)", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 2121, "protocol": "tcp", "service": "ftp", "product": "ProFTPD", "version": "1.3.1", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 3306, "protocol": "tcp", "service": "mysql", "product": "MySQL", "version": "5.0.51a-3ubuntu5", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 5432, "protocol": "tcp", "service": "postgresql", "product": "PostgreSQL DB", "version": "8.3.0 - 8.3.7", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 5900, "protocol": "tcp", "service": "vnc", "product": "VNC", "version": "protocol 3.3", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 6000, "protocol": "tcp", "service": "x11", "product": "X11", "version": "access granted", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 6667, "protocol": "tcp", "service": "irc", "product": "UnrealIRCd", "version": "3.2.8.1", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 8009, "protocol": "tcp", "service": "ajp13", "product": "Apache Jserv", "version": "Protocol v1.3", "state": "open"},
            {"target_ip": "192.168.56.111", "port": 8180, "protocol": "tcp", "service": "http", "product": "Apache Tomcat/Coyote", "version": "1.1", "state": "open"},
        ],
        "run1_findings": [
            {
                "finding_id": "VULN-DEMO-001-01",
                "target_ip": "192.168.56.111",
                "hostname": "metasploitable2.local",
                "port": 21,
                "protocol": "tcp",
                "service": "ftp",
                "service_version": "vsftpd 2.3.4",
                "title": "VSFTPD v2.3.4 Smiley Backdoor Remote Code Execution",
                "description": "The vsftpd version 2.3.4 contains a malicious backdoor triggered by sending a smiley face in the username, opening a root shell on TCP port 6200.",
                "cve_identifiers": "CVE-2011-2523",
                "cvss_score": 9.8,
                "severity": "Critical",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "ftp-vsftpd-backdoor",
                "remediation": "Upgrade vsftpd package immediately to version 3.0.3 or higher.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-001-02",
                "target_ip": "192.168.56.111",
                "hostname": "metasploitable2.local",
                "port": 6667,
                "protocol": "tcp",
                "service": "irc",
                "service_version": "UnrealIRCd 3.2.8.1",
                "title": "UnrealIRCd Backdoor Remote Command Execution",
                "description": "Unreal3.2.8.1 contains an embedded backdoor in the DEBUG3_DOLOG_SYSTEM macro that allows unauthenticated command execution.",
                "cve_identifiers": "CVE-2010-2075",
                "cvss_score": 9.8,
                "severity": "Critical",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "irc-unrealircd-backdoor",
                "remediation": "Replace UnrealIRCd with a cryptographically verified release tarball.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-001-03",
                "target_ip": "192.168.56.111",
                "hostname": "metasploitable2.local",
                "port": 445,
                "protocol": "tcp",
                "service": "microsoft-ds",
                "service_version": "Samba 3.0.20",
                "title": "Samba 'username map script' Command Execution",
                "description": "Samba 3.0.20 allows remote attackers to execute arbitrary commands via shell metacharacters in username parameters.",
                "cve_identifiers": "CVE-2007-2447",
                "cvss_score": 9.8,
                "severity": "Critical",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "samba-vuln-cve-2007-2447",
                "remediation": "Upgrade Samba to a secured release and disable 'username map script' in smb.conf.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-001-04",
                "target_ip": "192.168.56.111",
                "hostname": "metasploitable2.local",
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "service_version": "Apache 2.2.8 (PHP 5.2.4)",
                "title": "PHP-CGI Query String Parameter Injection Remote Code Execution",
                "description": "PHP before 5.3.12 and 5.4.x before 5.4.2 does not properly delineate command line options when running in CGI mode.",
                "cve_identifiers": "CVE-2012-1823",
                "cvss_score": 7.5,
                "severity": "High",
                "confidence": 0.95,
                "detection_source": "nuclei",
                "scanner_vt_id": "cve-2012-1823",
                "remediation": "Update PHP to latest supported branch and avoid direct invocation of php-cgi.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-001-05",
                "target_ip": "192.168.56.111",
                "hostname": "metasploitable2.local",
                "port": 1524,
                "protocol": "tcp",
                "service": "bindshell",
                "service_version": "Metasploitable root shell",
                "title": "Unauthenticated Root Bindshell Active on High Port",
                "description": "An interactive root shell listener was detected on TCP port 1524 requiring no authentication.",
                "cve_identifiers": None,
                "cvss_score": 9.8,
                "severity": "Critical",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "root-bindshell",
                "remediation": "Terminate the bindshell process and remove the inetd.conf service entry.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-001-06",
                "target_ip": "192.168.56.111",
                "hostname": "metasploitable2.local",
                "port": 5900,
                "protocol": "tcp",
                "service": "vnc",
                "service_version": "VNC protocol 3.3",
                "title": "VNC Server Password Authentication Bypass / Weak Secret",
                "description": "VNC service on port 5900 allows trivial authentication with well-known password 'password'.",
                "cve_identifiers": "CVE-2006-2369",
                "cvss_score": 7.5,
                "severity": "High",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "vnc-brute",
                "remediation": "Enforce strong authentication or tunnel VNC over SSH/VPN exclusively.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-001-07",
                "target_ip": "192.168.56.111",
                "hostname": "metasploitable2.local",
                "port": 23,
                "protocol": "tcp",
                "service": "telnet",
                "service_version": "Linux telnetd",
                "title": "Cleartext Telnet Remote Management Protocol Permitted",
                "description": "The Telnet daemon communicates in plain text without encryption, exposing credentials to eavesdropping.",
                "cve_identifiers": None,
                "cvss_score": 5.3,
                "severity": "Medium",
                "confidence": 1.0,
                "detection_source": "nmap",
                "scanner_vt_id": "telnet-cleartext",
                "remediation": "Disable the in.telnetd daemon and replace with OpenSSH.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-001-08",
                "target_ip": "192.168.56.111",
                "hostname": "metasploitable2.local",
                "port": 21,
                "protocol": "tcp",
                "service": "ftp",
                "service_version": "vsftpd 2.3.4",
                "title": "Anonymous FTP Login Permitted with Read Access",
                "description": "FTP daemon allows unauthenticated anonymous logons permitting world-readable file enumeration.",
                "cve_identifiers": None,
                "cvss_score": 3.7,
                "severity": "Low",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "ftp-anon",
                "remediation": "Set anonymous_enable=NO in the vsftpd configuration file.",
                "verification_status": "verified",
                "finding_status": "open"
            },
        ],
        "run2_findings": [
            {
                "finding_id": "VULN-DEMO-001-06",
                "target_ip": "192.168.56.111",
                "hostname": "metasploitable2.local",
                "port": 5900,
                "protocol": "tcp",
                "service": "vnc",
                "service_version": "VNC protocol 3.3",
                "title": "VNC Server Password Authentication Bypass / Weak Secret",
                "description": "VNC service on port 5900 allows trivial authentication with well-known password 'password'.",
                "cve_identifiers": "CVE-2006-2369",
                "cvss_score": 7.5,
                "severity": "High",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "vnc-brute",
                "remediation": "Enforce strong authentication or tunnel VNC over SSH/VPN exclusively.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-001-07",
                "target_ip": "192.168.56.111",
                "hostname": "metasploitable2.local",
                "port": 23,
                "protocol": "tcp",
                "service": "telnet",
                "service_version": "Linux telnetd",
                "title": "Cleartext Telnet Remote Management Protocol Permitted",
                "description": "The Telnet daemon communicates in plain text without encryption, exposing credentials to eavesdropping.",
                "cve_identifiers": None,
                "cvss_score": 5.3,
                "severity": "Medium",
                "confidence": 1.0,
                "detection_source": "nmap",
                "scanner_vt_id": "telnet-cleartext",
                "remediation": "Disable the in.telnetd daemon and replace with OpenSSH.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-001-08",
                "target_ip": "192.168.56.111",
                "hostname": "metasploitable2.local",
                "port": 2121,
                "protocol": "tcp",
                "service": "ftp",
                "service_version": "ProFTPD 1.3.1",
                "title": "Anonymous FTP Login Permitted on Port 2121",
                "description": "Secondary ProFTPD daemon on port 2121 allows anonymous login.",
                "cve_identifiers": None,
                "cvss_score": 3.7,
                "severity": "Low",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "ftp-anon",
                "remediation": "Disable anonymous user accounts across all FTP daemon instances.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-001-09",
                "target_ip": "192.168.56.111",
                "hostname": "metasploitable2.local",
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "service_version": "OpenSSH 4.7p1",
                "title": "OpenSSH Outdated Protocol & Weak Cipher Suites",
                "description": "OpenSSH daemon advertises deprecated CBC cipher suites and outdated banner.",
                "cve_identifiers": None,
                "cvss_score": 2.6,
                "severity": "Low",
                "confidence": 0.9,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "ssh2-enum-algos",
                "remediation": "Upgrade OpenSSH and restrict Ciphers and MACs in sshd_config.",
                "verification_status": "verified",
                "finding_status": "open"
            },
        ]
    },

    # -------------------------------------------------------------------------
    # 2. E-Commerce API & Web Gateway Audit (5 ports, web/API focus)
    # -------------------------------------------------------------------------
    {
        "key": "DEMO-002",
        "name": "E-Commerce API & Web Gateway Audit",
        "target_value": "192.168.56.112",
        "target_type": "ipv4",
        "purpose": "Payment & Cloud Web Services Security Assessment",
        "description": "Comprehensive OSINT reconnaissance and web infrastructure assessment of customer-facing payment microservices.",
        "scope_description": "192.168.56.112 (Host-Only Network 192.168.56.0/24)",
        "hostname": "api-gateway.demo.internal",
        "discovered_ports": [
            {"target_ip": "192.168.56.112", "port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.18.0", "state": "open"},
            {"target_ip": "192.168.56.112", "port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.18.0", "state": "open"},
            {"target_ip": "192.168.56.112", "port": 8080, "protocol": "tcp", "service": "http", "product": "Spring Boot Gateway", "version": "2.5.4", "state": "open"},
            {"target_ip": "192.168.56.112", "port": 8443, "protocol": "tcp", "service": "https", "product": "Apache Tomcat", "version": "9.0.41", "state": "open"},
            {"target_ip": "192.168.56.112", "port": 9000, "protocol": "tcp", "service": "http", "product": "SonarQube API Console", "version": "8.9.1", "state": "open"},
        ],
        "run1_findings": [
            {
                "finding_id": "VULN-DEMO-002-01",
                "target_ip": "192.168.56.112",
                "hostname": "api-gateway.demo.internal",
                "port": 8080,
                "protocol": "tcp",
                "service": "http",
                "service_version": "Spring Boot 2.5.4",
                "title": "Spring Boot Actuator Env Endpoint Public Exposure",
                "description": "The /actuator/env endpoint is publicly exposed, leaking environment variables, database URLs, and application secrets.",
                "cve_identifiers": "CVE-2020-5421",
                "cvss_score": 7.5,
                "severity": "High",
                "confidence": 1.0,
                "detection_source": "nuclei",
                "scanner_vt_id": "springboot-actuator-env",
                "remediation": "Restrict actuator endpoints by setting management.endpoints.web.exposure.include=health,info.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-002-02",
                "target_ip": "192.168.56.112",
                "hostname": "api-gateway.demo.internal",
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "service_version": "nginx 1.18.0",
                "title": "Exposed Git Repository Metadata Directory /.git/HEAD",
                "description": "Web server serves the hidden .git directory, permitting full application source code extraction.",
                "cve_identifiers": None,
                "cvss_score": 7.5,
                "severity": "High",
                "confidence": 1.0,
                "detection_source": "nuclei",
                "scanner_vt_id": "git-config-exposure",
                "remediation": "Add location ~ /\\.git { deny all; } in Nginx configuration.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-002-03",
                "target_ip": "192.168.56.112",
                "hostname": "api-gateway.demo.internal",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "service_version": "nginx 1.18.0",
                "title": "Deprecated TLS 1.0 Protocol and Weak CBC Ciphers Enabled",
                "description": "HTTPS service negotiates legacy TLS 1.0 protocol and 3DES CBC cipher suites vulnerable to SWEET32 attacks.",
                "cve_identifiers": "CVE-2016-2183",
                "cvss_score": 5.9,
                "severity": "Medium",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "ssl-enum-ciphers",
                "remediation": "Disable TLSv1.0 and TLSv1.1 in ssl_protocols, allowing only TLSv1.2 and TLSv1.3.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-002-04",
                "target_ip": "192.168.56.112",
                "hostname": "api-gateway.demo.internal",
                "port": 8080,
                "protocol": "tcp",
                "service": "http",
                "service_version": "Spring Boot 2.5.4",
                "title": "Unauthenticated Swagger UI API Documentation Exposure",
                "description": "Interactive API documentation console (/swagger-ui.html) is publicly reachable without authentication.",
                "cve_identifiers": None,
                "cvss_score": 5.3,
                "severity": "Medium",
                "confidence": 1.0,
                "detection_source": "nuclei",
                "scanner_vt_id": "swagger-api-exposed",
                "remediation": "Require authentication on Swagger and OpenAPI endpoints in production.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-002-05",
                "target_ip": "192.168.56.112",
                "hostname": "api-gateway.demo.internal",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "service_version": "nginx 1.18.0",
                "title": "Missing HTTP Strict-Transport-Security (HSTS) Header",
                "description": "The web application does not transmit the Strict-Transport-Security HTTP response header.",
                "cve_identifiers": None,
                "cvss_score": 3.7,
                "severity": "Low",
                "confidence": 1.0,
                "detection_source": "nuclei",
                "scanner_vt_id": "hsts-missing",
                "remediation": "Add Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains'.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-002-06",
                "target_ip": "192.168.56.112",
                "hostname": "api-gateway.demo.internal",
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "service_version": "nginx 1.18.0",
                "title": "Nginx Version Banner Disclosure in Server Header",
                "description": "The web server discloses its exact version 'nginx/1.18.0' in HTTP response headers.",
                "cve_identifiers": None,
                "cvss_score": 0.0,
                "severity": "Informational",
                "confidence": 1.0,
                "detection_source": "theharvester",
                "scanner_vt_id": "http-server-header",
                "remediation": "Set server_tokens off; in nginx.conf.",
                "verification_status": "verified",
                "finding_status": "open"
            },
        ],
        "run2_findings": [
            {
                "finding_id": "VULN-DEMO-002-05",
                "target_ip": "192.168.56.112",
                "hostname": "api-gateway.demo.internal",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "service_version": "nginx 1.18.0",
                "title": "Missing Content Security Policy (CSP) Frame Ancestors",
                "description": "The application lacks a CSP frame-ancestors directive permitting potential clickjacking.",
                "cve_identifiers": None,
                "cvss_score": 3.7,
                "severity": "Low",
                "confidence": 0.95,
                "detection_source": "nuclei",
                "scanner_vt_id": "csp-missing",
                "remediation": "Add Content-Security-Policy: frame-ancestors 'self' header.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-002-06",
                "target_ip": "192.168.56.112",
                "hostname": "api-gateway.demo.internal",
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "service_version": "nginx 1.18.0",
                "title": "Nginx Version Banner Disclosure in Server Header",
                "description": "The web server discloses its exact version 'nginx/1.18.0' in HTTP response headers.",
                "cve_identifiers": None,
                "cvss_score": 0.0,
                "severity": "Informational",
                "confidence": 1.0,
                "detection_source": "nmap",
                "scanner_vt_id": "http-server-header",
                "remediation": "Set server_tokens off; in nginx.conf.",
                "verification_status": "verified",
                "finding_status": "open"
            },
        ]
    },

    # -------------------------------------------------------------------------
    # 3. Corporate Cloud Edge & DNS Node (4 ports, perimeter & OSINT focus)
    # -------------------------------------------------------------------------
    {
        "key": "DEMO-003",
        "name": "Corporate Cloud Edge & DNS Node",
        "target_value": "192.168.56.113",
        "target_type": "ipv4",
        "purpose": "Perimeter Infrastructure & OSINT Verification",
        "description": "Passive OSINT and external attack-surface review of corporate DNS nameserver and edge mail relay.",
        "scope_description": "192.168.56.113 (Host-Only Network 192.168.56.0/24)",
        "hostname": "ns1.corp-edge.internal",
        "discovered_ports": [
            {"target_ip": "192.168.56.113", "port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "8.9p1 Ubuntu", "state": "open"},
            {"target_ip": "192.168.56.113", "port": 53, "protocol": "tcp", "service": "domain", "product": "ISC BIND", "version": "9.16.1", "state": "open"},
            {"target_ip": "192.168.56.113", "port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd", "version": "2.4.52", "state": "open"},
            {"target_ip": "192.168.56.113", "port": 443, "protocol": "tcp", "service": "https", "product": "Apache httpd", "version": "2.4.52", "state": "open"},
        ],
        "run1_findings": [
            {
                "finding_id": "VULN-DEMO-003-01",
                "target_ip": "192.168.56.113",
                "hostname": "ns1.corp-edge.internal",
                "port": 53,
                "protocol": "tcp",
                "service": "domain",
                "service_version": "BIND 9.16.1",
                "title": "DNS Zone Transfer (AXFR) Allowed from Untrusted IP",
                "description": "The nameserver allows unrestricted DNS zone transfers (AXFR), permitting enumeration of all internal subdomains and IP addresses.",
                "cve_identifiers": None,
                "cvss_score": 5.3,
                "severity": "Medium",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "dns-zone-transfer",
                "remediation": "Restrict zone transfers in named.conf to authorized secondary nameservers only.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-003-02",
                "target_ip": "192.168.56.113",
                "hostname": "ns1.corp-edge.internal",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "service_version": "Apache 2.4.52",
                "title": "Dangling CNAME Alias Vulnerable to Subdomain Takeover",
                "description": "DNS records point an active CNAME alias to an unregistered AWS S3 bucket endpoint.",
                "cve_identifiers": None,
                "cvss_score": 6.5,
                "severity": "Medium",
                "confidence": 0.95,
                "detection_source": "nuclei",
                "scanner_vt_id": "subdomain-takeover-s3",
                "remediation": "Delete the orphaned CNAME record or claim the destination S3 bucket.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-003-03",
                "target_ip": "192.168.56.113",
                "hostname": "ns1.corp-edge.internal",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "service_version": "Apache 2.4.52",
                "title": "SSL/TLS Certificate Expiration Within 14 Days",
                "description": "The X.509 certificate on port 443 expires in 12 days, posing service disruption risk.",
                "cve_identifiers": None,
                "cvss_score": 3.1,
                "severity": "Low",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "ssl-cert-expiry",
                "remediation": "Renew the certificate through automated Let's Encrypt / ACME certbot pipeline.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
        ],
        "run2_findings": [
            {
                "finding_id": "VULN-DEMO-003-04",
                "target_ip": "192.168.56.113",
                "hostname": "ns1.corp-edge.internal",
                "port": 53,
                "protocol": "tcp",
                "service": "domain",
                "service_version": "BIND 9.16.1",
                "title": "BIND Nameserver Version Disclosure in TXT Query",
                "description": "Querying version.bind via CHAOS class reveals exact daemon build string.",
                "cve_identifiers": None,
                "cvss_score": 2.6,
                "severity": "Low",
                "confidence": 1.0,
                "detection_source": "whois_rdap_dns",
                "scanner_vt_id": "dns-version-bind",
                "remediation": "Add version 'none'; in options block of named.conf.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-003-05",
                "target_ip": "192.168.56.113",
                "hostname": "ns1.corp-edge.internal",
                "port": None,
                "protocol": "tcp",
                "service": "whois",
                "service_version": "RDAP / WHOIS",
                "title": "Corporate Domain Whois Registrar Technical Contact Disclosure",
                "description": "Public RDAP record exposes administrative email and technical contact telephone details.",
                "cve_identifiers": None,
                "cvss_score": 0.0,
                "severity": "Informational",
                "confidence": 1.0,
                "detection_source": "whois_rdap_dns",
                "scanner_vt_id": "whois-privacy-disclosure",
                "remediation": "Enable WHOIS privacy protection with the domain registrar.",
                "verification_status": "verified",
                "finding_status": "open"
            },
        ]
    },

    # -------------------------------------------------------------------------
    # 4. Enterprise DMZ & Remote Access Gateway (6 ports, VPN & Identity focus)
    # -------------------------------------------------------------------------
    {
        "key": "DEMO-004",
        "name": "Enterprise DMZ & Remote Access Gateway",
        "target_value": "192.168.56.114",
        "target_type": "ipv4",
        "purpose": "Perimeter Defense & Identity Access Audit",
        "description": "Vulnerability assessment of corporate VPN endpoint, Active Directory proxy, and remote administration gateways.",
        "scope_description": "192.168.56.114 (Host-Only Network 192.168.56.0/24)",
        "hostname": "vpn-gateway.enterprise.dmz",
        "discovered_ports": [
            {"target_ip": "192.168.56.114", "port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "8.2p1", "state": "open"},
            {"target_ip": "192.168.56.114", "port": 88, "protocol": "tcp", "service": "kerberos", "product": "MIT Kerberos", "version": "5", "state": "open"},
            {"target_ip": "192.168.56.114", "port": 389, "protocol": "tcp", "service": "ldap", "product": "OpenLDAP", "version": "2.4.49", "state": "open"},
            {"target_ip": "192.168.56.114", "port": 443, "protocol": "tcp", "service": "https", "product": "Pulse Connect SSL-VPN", "version": "9.0R3", "state": "open"},
            {"target_ip": "192.168.56.114", "port": 445, "protocol": "tcp", "service": "microsoft-ds", "product": "Windows Server SMB", "version": "2016", "state": "open"},
            {"target_ip": "192.168.56.114", "port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "product": "Microsoft Remote Desktop", "version": "10.0", "state": "open"},
        ],
        "run1_findings": [
            {
                "finding_id": "VULN-DEMO-004-01",
                "target_ip": "192.168.56.114",
                "hostname": "vpn-gateway.enterprise.dmz",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "service_version": "Pulse Connect 9.0R3",
                "title": "Pulse Connect SSL-VPN Arbitrary File Read Vulnerability",
                "description": "Directory traversal vulnerability in Pulse Secure Pulse Connect Secure (PCS) allows unauthenticated remote attacker to read arbitrary files including cached VPN plaintext credentials.",
                "cve_identifiers": "CVE-2018-13379",
                "cvss_score": 9.8,
                "severity": "Critical",
                "confidence": 1.0,
                "detection_source": "nuclei",
                "scanner_vt_id": "cve-2018-13379",
                "remediation": "Apply Pulse Secure security advisory SA44101 and reset all Active Directory VPN credentials.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-004-02",
                "target_ip": "192.168.56.114",
                "hostname": "vpn-gateway.enterprise.dmz",
                "port": 445,
                "protocol": "tcp",
                "service": "microsoft-ds",
                "service_version": "Windows Server 2016",
                "title": "SMBv1 Protocol Negotiation Permitted (EternalBlue Vector)",
                "description": "Legacy SMBv1 protocol is accepted on port 445, exposing the host to remote exploit vectors.",
                "cve_identifiers": "CVE-2017-0143",
                "cvss_score": 7.5,
                "severity": "High",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "smb-protocols",
                "remediation": "Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-004-03",
                "target_ip": "192.168.56.114",
                "hostname": "vpn-gateway.enterprise.dmz",
                "port": 3389,
                "protocol": "tcp",
                "service": "ms-wbt-server",
                "service_version": "RDP 10.0",
                "title": "RDP Terminal Services Network Level Authentication (NLA) Disabled",
                "description": "Remote Desktop allows pre-authentication TCP sessions without requiring Network Level Authentication.",
                "cve_identifiers": None,
                "cvss_score": 7.1,
                "severity": "High",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "rdp-enum-encryption",
                "remediation": "Enforce 'Require computers to use Network Level Authentication' in System Properties.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-004-04",
                "target_ip": "192.168.56.114",
                "hostname": "vpn-gateway.enterprise.dmz",
                "port": 389,
                "protocol": "tcp",
                "service": "ldap",
                "service_version": "OpenLDAP 2.4.49",
                "title": "LDAP Directory Anonymous Simple Bind Permitted",
                "description": "LDAP directory responds to anonymous queries without requiring bind credentials.",
                "cve_identifiers": None,
                "cvss_score": 5.9,
                "severity": "Medium",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "ldap-rootdse",
                "remediation": "Set disallow_anonymous_bind in slapd.conf or require LDAP sign / seal.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-004-05",
                "target_ip": "192.168.56.114",
                "hostname": "vpn-gateway.enterprise.dmz",
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "service_version": "OpenSSH 8.2p1",
                "title": "SSH Password Authentication Permitted on Edge Gateway",
                "description": "Interactive password authentication is enabled on external perimeter SSH daemon.",
                "cve_identifiers": None,
                "cvss_score": 5.3,
                "severity": "Medium",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "ssh-auth-methods",
                "remediation": "Set PasswordAuthentication no in sshd_config and require public key authentication.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-004-06",
                "target_ip": "192.168.56.114",
                "hostname": "vpn-gateway.enterprise.dmz",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "service_version": "Pulse Connect 9.0R3",
                "title": "Deprecated TLS 1.1 Enabled on HTTPS Endpoint",
                "description": "The web portal supports TLS 1.1 which was deprecated in RFC 8996.",
                "cve_identifiers": None,
                "cvss_score": 3.7,
                "severity": "Low",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "ssl-enum-ciphers",
                "remediation": "Restrict accepted SSL/TLS profiles to TLS 1.2 and TLS 1.3.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-004-07",
                "target_ip": "192.168.56.114",
                "hostname": "vpn-gateway.enterprise.dmz",
                "port": None,
                "protocol": "tcp",
                "service": "rdap",
                "service_version": "RDAP / WHOIS",
                "title": "Public RDAP Organization Technical Contact Leaked",
                "description": "Subnet IP block registry discloses technical team email address and ASN peering point.",
                "cve_identifiers": None,
                "cvss_score": 0.0,
                "severity": "Informational",
                "confidence": 1.0,
                "detection_source": "whois_rdap_dns",
                "scanner_vt_id": "rdap-contact-leak",
                "remediation": "Replace direct engineer email in ARIN/RIPE database with generic security mailbox.",
                "verification_status": "verified",
                "finding_status": "open"
            },
        ],
        "run2_findings": [
            {
                "finding_id": "VULN-DEMO-004-04",
                "target_ip": "192.168.56.114",
                "hostname": "vpn-gateway.enterprise.dmz",
                "port": 389,
                "protocol": "tcp",
                "service": "ldap",
                "service_version": "OpenLDAP 2.4.49",
                "title": "LDAP Simple Bind without SSL/TLS on Port 389",
                "description": "LDAP communications on port 389 occur without mandatory StartTLS encryption.",
                "cve_identifiers": None,
                "cvss_score": 5.9,
                "severity": "Medium",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "ldap-rootdse",
                "remediation": "Migrate all directory queries to LDAPS port 636 or mandate StartTLS.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-004-08",
                "target_ip": "192.168.56.114",
                "hostname": "vpn-gateway.enterprise.dmz",
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "service_version": "OpenSSH 8.2p1",
                "title": "SSH Server Public Key Weak RSA 1024-bit Hostkey",
                "description": "SSH hostkey includes legacy 1024-bit RSA key alongside 256-bit ED25519 key.",
                "cve_identifiers": None,
                "cvss_score": 3.1,
                "severity": "Low",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "ssh-hostkey",
                "remediation": "Regenerate host keys with RSA 4096-bit or retain only ED25519.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-004-07",
                "target_ip": "192.168.56.114",
                "hostname": "vpn-gateway.enterprise.dmz",
                "port": None,
                "protocol": "tcp",
                "service": "rdap",
                "service_version": "RDAP / WHOIS",
                "title": "Public RDAP Organization Technical Contact Leaked",
                "description": "Subnet IP block registry discloses technical team email address and ASN peering point.",
                "cve_identifiers": None,
                "cvss_score": 0.0,
                "severity": "Informational",
                "confidence": 1.0,
                "detection_source": "whois_rdap_dns",
                "scanner_vt_id": "rdap-contact-leak",
                "remediation": "Replace direct engineer email in ARIN/RIPE database with generic security mailbox.",
                "verification_status": "verified",
                "finding_status": "open"
            },
        ]
    },

    # -------------------------------------------------------------------------
    # 5. Industrial SCADA & Core Database Node (7 ports, OT & multi-DB focus)
    # -------------------------------------------------------------------------
    {
        "key": "DEMO-005",
        "name": "Industrial SCADA & Core Database Node",
        "target_value": "192.168.56.115",
        "target_type": "ipv4",
        "purpose": "Critical Infrastructure & Operational Technology Compliance",
        "description": "Security audit of OT operational historian, Modbus gateway, and multi-engine backend data warehouse.",
        "scope_description": "192.168.56.115 (Host-Only Network 192.168.56.0/24)",
        "hostname": "scada-historian.ot.internal",
        "discovered_ports": [
            {"target_ip": "192.168.56.115", "port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "7.6p1", "state": "open"},
            {"target_ip": "192.168.56.115", "port": 502, "protocol": "tcp", "service": "modbus", "product": "Schneider Modbus/TCP Gateway", "version": "1.0", "state": "open"},
            {"target_ip": "192.168.56.115", "port": 1433, "protocol": "tcp", "service": "ms-sql-s", "product": "Microsoft SQL Server", "version": "2019 RTM", "state": "open"},
            {"target_ip": "192.168.56.115", "port": 1521, "protocol": "tcp", "service": "oracle", "product": "Oracle Database TNS Listener", "version": "19c", "state": "open"},
            {"target_ip": "192.168.56.115", "port": 3306, "protocol": "tcp", "service": "mysql", "product": "MariaDB", "version": "10.3.27", "state": "open"},
            {"target_ip": "192.168.56.115", "port": 5432, "protocol": "tcp", "service": "postgresql", "product": "PostgreSQL Database", "version": "12.4", "state": "open"},
            {"target_ip": "192.168.56.115", "port": 8080, "protocol": "tcp", "service": "http", "product": "SCADA Web Supervision Console", "version": "3.2", "state": "open"},
        ],
        "run1_findings": [
            {
                "finding_id": "VULN-DEMO-005-01",
                "target_ip": "192.168.56.115",
                "hostname": "scada-historian.ot.internal",
                "port": 502,
                "protocol": "tcp",
                "service": "modbus",
                "service_version": "Modbus/TCP Gateway",
                "title": "Modbus/TCP Function Code Broadcast Unauthorized Access",
                "description": "Industrial Modbus/TCP controller accepts function codes 01 (Read Coils) and 05 (Write Single Coil) from untrusted networks without authentication.",
                "cve_identifiers": None,
                "cvss_score": 9.8,
                "severity": "Critical",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "modbus-discover",
                "remediation": "Isolate port 502 behind an industrial firewall and enforce deep packet inspection.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-005-02",
                "target_ip": "192.168.56.115",
                "hostname": "scada-historian.ot.internal",
                "port": 1433,
                "protocol": "tcp",
                "service": "ms-sql-s",
                "service_version": "Microsoft SQL Server 2019",
                "title": "Default SA Account With Blank Password on Microsoft SQL Server",
                "description": "SQL Server database instance allows administrative login using sysadmin account 'sa' with an empty password.",
                "cve_identifiers": None,
                "cvss_score": 9.8,
                "severity": "Critical",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "ms-sql-empty-password",
                "remediation": "Assign a high-entropy password to the sa account and disable mixed-mode authentication if unused.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-005-03",
                "target_ip": "192.168.56.115",
                "hostname": "scada-historian.ot.internal",
                "port": 8080,
                "protocol": "tcp",
                "service": "http",
                "service_version": "SCADA Web Console 3.2",
                "title": "SCADA Web Supervisory Console Default Admin Credentials",
                "description": "Web-based SCADA human-machine interface accepts default manufacturer credentials 'admin/admin'.",
                "cve_identifiers": None,
                "cvss_score": 8.8,
                "severity": "High",
                "confidence": 1.0,
                "detection_source": "nuclei",
                "scanner_vt_id": "scada-default-login",
                "remediation": "Change factory default credentials immediately and mandate multi-factor authentication.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-005-04",
                "target_ip": "192.168.56.115",
                "hostname": "scada-historian.ot.internal",
                "port": 5432,
                "protocol": "tcp",
                "service": "postgresql",
                "service_version": "PostgreSQL 12.4",
                "title": "PostgreSQL Remote Trust Authentication Configuration",
                "description": "The pg_hba.conf file configures 'trust' authentication for remote network CIDRs, allowing unauthenticated DB connection.",
                "cve_identifiers": None,
                "cvss_score": 8.1,
                "severity": "High",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "pgsql-trust-auth",
                "remediation": "Replace 'trust' with 'scram-sha-256' in pg_hba.conf.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-005-05",
                "target_ip": "192.168.56.115",
                "hostname": "scada-historian.ot.internal",
                "port": 1521,
                "protocol": "tcp",
                "service": "oracle",
                "service_version": "Oracle 19c",
                "title": "Oracle TNS Listener Poisoning Vulnerability (Remote Registration)",
                "description": "Oracle Database listener allows remote registration without validation, enabling man-in-the-middle packet redirection.",
                "cve_identifiers": "CVE-2012-1675",
                "cvss_score": 7.5,
                "severity": "High",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "oracle-tns-poison",
                "remediation": "Enable Cost-Based Registration (SECURE_REGISTER_listener_name) in listener.ora.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-005-06",
                "target_ip": "192.168.56.115",
                "hostname": "scada-historian.ot.internal",
                "port": 3306,
                "protocol": "tcp",
                "service": "mysql",
                "service_version": "MariaDB 10.3.27",
                "title": "MySQL Cleartext Unencrypted Transport across Subnet",
                "description": "MariaDB server does not enforce mandatory TLS transport, permitting credential interception.",
                "cve_identifiers": None,
                "cvss_score": 5.9,
                "severity": "Medium",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "mysql-ssl-disabled",
                "remediation": "Configure require_secure_transport=ON in my.cnf.",
                "verification_status": "verified",
                "finding_status": "resolved"
            },
            {
                "finding_id": "VULN-DEMO-005-07",
                "target_ip": "192.168.56.115",
                "hostname": "scada-historian.ot.internal",
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "service_version": "OpenSSH 7.6p1",
                "title": "SSH Protocol Banner Leaks Operating System Build",
                "description": "SSH banner explicitly announces 'Ubuntu-4ubuntu0.3' which aids vulnerability reconnaissance.",
                "cve_identifiers": None,
                "cvss_score": 2.6,
                "severity": "Low",
                "confidence": 1.0,
                "detection_source": "nmap",
                "scanner_vt_id": "ssh-banner",
                "remediation": "Suppress system banner information in sshd_config.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-005-08",
                "target_ip": "192.168.56.115",
                "hostname": "scada-historian.ot.internal",
                "port": None,
                "protocol": "tcp",
                "service": "dns",
                "service_version": "DNS PTR",
                "title": "Reverse DNS Lookup PTR Record External Mismatch",
                "description": "In-addr.arpa pointer resolves to legacy hostname different from forward DNS entry.",
                "cve_identifiers": None,
                "cvss_score": 0.0,
                "severity": "Informational",
                "confidence": 1.0,
                "detection_source": "whois_rdap_dns",
                "scanner_vt_id": "dns-ptr-mismatch",
                "remediation": "Synchronize forward and reverse DNS records.",
                "verification_status": "verified",
                "finding_status": "open"
            },
        ],
        "run2_findings": [
            {
                "finding_id": "VULN-DEMO-005-04",
                "target_ip": "192.168.56.115",
                "hostname": "scada-historian.ot.internal",
                "port": 5432,
                "protocol": "tcp",
                "service": "postgresql",
                "service_version": "PostgreSQL 12.4",
                "title": "PostgreSQL Remote Trust Authentication Configuration",
                "description": "The pg_hba.conf file configures 'trust' authentication for remote network CIDRs, allowing unauthenticated DB connection.",
                "cve_identifiers": None,
                "cvss_score": 8.1,
                "severity": "High",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "pgsql-trust-auth",
                "remediation": "Replace 'trust' with 'scram-sha-256' in pg_hba.conf.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-005-05",
                "target_ip": "192.168.56.115",
                "hostname": "scada-historian.ot.internal",
                "port": 1521,
                "protocol": "tcp",
                "service": "oracle",
                "service_version": "Oracle 19c",
                "title": "Oracle TNS Listener Poisoning Vulnerability (Remote Registration)",
                "description": "Oracle Database listener allows remote registration without validation, enabling man-in-the-middle packet redirection.",
                "cve_identifiers": "CVE-2012-1675",
                "cvss_score": 7.5,
                "severity": "High",
                "confidence": 1.0,
                "detection_source": "nmap_nse",
                "scanner_vt_id": "oracle-tns-poison",
                "remediation": "Enable Cost-Based Registration (SECURE_REGISTER_listener_name) in listener.ora.",
                "verification_status": "verified",
                "finding_status": "open"
            },
            {
                "finding_id": "VULN-DEMO-005-07",
                "target_ip": "192.168.56.115",
                "hostname": "scada-historian.ot.internal",
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "service_version": "OpenSSH 7.6p1",
                "title": "SSH Protocol Banner Leaks Operating System Build",
                "description": "SSH banner explicitly announces 'Ubuntu-4ubuntu0.3' which aids vulnerability reconnaissance.",
                "cve_identifiers": None,
                "cvss_score": 2.6,
                "severity": "Low",
                "confidence": 1.0,
                "detection_source": "nmap",
                "scanner_vt_id": "ssh-banner",
                "remediation": "Suppress system banner information in sshd_config.",
                "verification_status": "verified",
                "finding_status": "open"
            },
        ]
    }
]


def _write_evidence_file(folder: str, file_name: str, content: str) -> Dict[str, Any]:
    os.makedirs(folder, exist_ok=True)
    fpath = os.path.join(folder, file_name)
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(content)
    size = os.path.getsize(fpath)
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return {
        "file_name": file_name,
        "local_path": fpath,
        "file_size": size,
        "sha256_hash": sha,
    }


def seed_demo_investigations(repo: Optional[FootprintIQRepository] = None, force: bool = False) -> List[str]:
    """
    Idempotently populates 5 high-fidelity demo investigations with complete
    multi-run historical scans, discovered ports, normalized findings,
    persisted evidence files, and official PDF reports.
    """
    if repo is None:
        repo = FootprintIQRepository()

    existing_campaigns = repo.list_recon_campaigns()
    existing_names = {c.get("name") for c in existing_campaigns}

    # If demo campaigns already exist and not forced, return their recon_ids
    demo_names = [d["name"] for d in DEMO_CAMPAIGNS_DEF]
    if not force and all(name in existing_names for name in demo_names):
        logger.info("[DemoSeeder] All 5 demo investigations are already seeded.")
        camp_by_name = {c.get("name"): c.get("recon_id") for c in existing_campaigns}
        return [camp_by_name[name] for name in demo_names if name in camp_by_name]

    seeded_ids: List[str] = []
    base_time = utcnow()
    generator = UnifiedReportGenerator()

    for idx, ddef in enumerate(DEMO_CAMPAIGNS_DEF, start=1):
        cname = ddef["name"]
        if not force and cname in existing_names:
            logger.info(f"[DemoSeeder] Campaign '{cname}' already present, skipping.")
            continue

        target = ddef["target_value"]
        logger.info(f"[DemoSeeder] Seeding Demo {idx}/5: '{cname}' (target: {target})...")

        # 1. Create Recon Campaign
        camp = repo.create_recon_campaign(
            name=cname,
            target_value=target,
            target_type=ddef["target_type"],
            description=ddef["description"],
            purpose=ddef["purpose"],
            scope_description=ddef["scope_description"],
            allowed_methods="all",
            allowed_ports="1-65535",
            authorized_by="asip_ali",
            creator_id=1,
            selected_scan_types="combined",
            initial_status="Completed",
            initial_stage="Completed",
            authorization_status="Authorized",
            idempotency_key=f"FIQ-DEMO-CAMP-{idx:03d}",
        )
        recon_id = camp["recon_id"]
        seeded_ids.append(recon_id)

        # Update campaign progress and stage
        repo.update_recon_campaign(
            recon_id=recon_id,
            status="Completed",
            progress=100,
            current_stage="Completed",
        )

        ev_folder = os.path.join(EVIDENCE_CACHE_DIR, recon_id)
        os.makedirs(ev_folder, exist_ok=True)

        # 2. Create Run 1 (Baseline Scan - 2 days ago)
        run1_start = base_time - timedelta(days=2)
        run1_duration = 342.0
        run1_end = run1_start + timedelta(seconds=run1_duration)

        scan1 = repo.create_scan_execution(
            investigation_id=recon_id,
            recon_id=recon_id,
            scan_type="combined",
            target=target,
            profile="deep-recon",
            initiating_user_id=1,
            initiated_by="asip_ali",
            selected_scanners=["theharvester", "whois_rdap_dns", "nmap", "nmap_nse", "nuclei"],
            selected_components=["emails", "dns_enum", "tcp_syn_scan", "service_detection", "nse_vuln", "nuclei_templates"],
            privilege_consent_given=True,
            privilege_elevation_required=True,
            privilege_status="authorized",
            privilege_authorized_at=run1_start,
        )
        scan1_id = scan1["scan_id"]

        # Run 1 Port & Host State
        discovered_ports = ddef["discovered_ports"]
        active_hosts = [{
            "ip": target,
            "hostname": ddef["hostname"],
            "status": "up",
            "latency_ms": 1.25,
            "os_match": "Linux 2.6.x - 5.x",
            "open_ports_count": len(discovered_ports)
        }]
        passive_results = [
            {
                "source": "WHOIS / RDAP",
                "domain": ddef["hostname"],
                "registrar": "FootprintIQ Internal Assessment Registry",
                "created_date": "2024-01-15T00:00:00Z",
                "org": "FootprintIQ Security Operations Lab",
                "nameservers": ["ns1.local", "ns2.local"],
            },
            {
                "source": "theHarvester",
                "query": ddef["hostname"],
                "emails_discovered": ["admin@demo.internal", "security@demo.internal", "ops@demo.internal"],
                "subdomains_discovered": [f"mail.{ddef['hostname']}", f"api.{ddef['hostname']}", f"vpn.{ddef['hostname']}"],
            },
            {
                "source": "DNS OSINT",
                "target": target,
                "records": [
                    {"type": "A", "name": ddef["hostname"], "value": target, "ttl": 3600},
                    {"type": "PTR", "name": f"{target}.in-addr.arpa", "value": ddef["hostname"], "ttl": 3600},
                ]
            }
        ]
        scanner_statuses_run1 = [
            {"scanner": "theharvester", "status": "COMPLETED", "detail": "Identified employee emails and domain aliases", "duration_seconds": 24.5},
            {"scanner": "whois_rdap_dns", "status": "COMPLETED", "detail": "Queried authoritative WHOIS, RDAP, and DNS zones", "duration_seconds": 15.2},
            {"scanner": "nmap", "status": "COMPLETED", "detail": f"Discovered {len(discovered_ports)} open TCP services across scanned range", "duration_seconds": 88.0},
            {"scanner": "nmap_nse", "status": "COMPLETED", "detail": "Executed safe vulnerability checks, banner scripts, and cipher enumeration", "duration_seconds": 125.4},
            {"scanner": "nuclei", "status": "COMPLETED", "detail": "Scanned against active protocol templates and CVE matches", "duration_seconds": 88.9},
        ]

        summary_run1 = {
            "discovered_ports": discovered_ports,
            "active_hosts": active_hosts,
            "passive_results": passive_results,
            "scanner_statuses": scanner_statuses_run1,
            "scanners_executed": ["theharvester", "whois_rdap_dns", "nmap", "nmap_nse", "nuclei"],
            "failed_stages": [],
        }

        repo.update_scan_execution(
            scan_id=scan1_id,
            status="completed",
            result_summary_json=json.dumps(summary_run1),
            privilege_status="authorized",
            privilege_authorized_at=run1_start,
        )

        # Explicitly persist Run 1 timestamps in memory or DB
        if scan1_id in repo._mem_scans:
            repo._mem_scans[scan1_id]["started_at"] = run1_start.isoformat()
            repo._mem_scans[scan1_id]["completed_at"] = run1_end.isoformat()
            repo._mem_scans[scan1_id]["duration_seconds"] = run1_duration

        # Insert Run 1 findings
        for f in ddef["run1_findings"]:
            repo.add_vulnerability_finding(
                investigation_id=recon_id,
                finding_dict=f,
                scan_id=scan1_id,
            )

        # 3. Create Run 2 (Remediation Recheck Scan - 1 day ago)
        run2_start = base_time - timedelta(days=1)
        run2_duration = 195.0
        run2_end = run2_start + timedelta(seconds=run2_duration)

        scan2 = repo.create_scan_execution(
            investigation_id=recon_id,
            recon_id=recon_id,
            scan_type="combined",
            target=target,
            profile="recheck-remediation",
            initiating_user_id=1,
            initiated_by="asip_ali",
            selected_scanners=["theharvester", "whois_rdap_dns", "nmap", "nmap_nse", "nuclei"],
            selected_components=["tcp_syn_scan", "service_detection", "nse_vuln", "nuclei_templates"],
            privilege_consent_given=True,
            privilege_elevation_required=True,
            privilege_status="authorized",
            privilege_authorized_at=run2_start,
        )
        scan2_id = scan2["scan_id"]

        scanner_statuses_run2 = [
            {"scanner": "theharvester", "status": "COMPLETED", "detail": "Verified external records unchanged", "duration_seconds": 18.0},
            {"scanner": "whois_rdap_dns", "status": "COMPLETED", "detail": "Re-verified DNS nameserver configuration", "duration_seconds": 12.0},
            {"scanner": "nmap", "status": "COMPLETED", "detail": f"Discovered {len(discovered_ports)} open TCP services across target", "duration_seconds": 62.0},
            {"scanner": "nmap_nse", "status": "COMPLETED", "detail": "Rechecked remediation status of previous vulnerability findings", "duration_seconds": 68.0},
            {"scanner": "nuclei", "status": "COMPLETED", "detail": "Confirmed patched CVEs and endpoints", "duration_seconds": 35.0},
        ]

        summary_run2 = {
            "discovered_ports": discovered_ports,
            "active_hosts": active_hosts,
            "passive_results": passive_results,
            "scanner_statuses": scanner_statuses_run2,
            "scanners_executed": ["theharvester", "whois_rdap_dns", "nmap", "nmap_nse", "nuclei"],
            "failed_stages": [],
        }

        repo.update_scan_execution(
            scan_id=scan2_id,
            status="completed",
            result_summary_json=json.dumps(summary_run2),
            privilege_status="authorized",
            privilege_authorized_at=run2_start,
        )

        # Explicitly persist Run 2 timestamps in memory or DB
        if scan2_id in repo._mem_scans:
            repo._mem_scans[scan2_id]["started_at"] = run2_start.isoformat()
            repo._mem_scans[scan2_id]["completed_at"] = run2_end.isoformat()
            repo._mem_scans[scan2_id]["duration_seconds"] = run2_duration

        # Insert Run 2 findings
        for f in ddef["run2_findings"]:
            repo.add_vulnerability_finding(
                investigation_id=recon_id,
                finding_dict=f,
                scan_id=scan2_id,
            )

        # 4. Generate local evidence files in evidence cache
        recon_json_data = {
            "recon_id": recon_id,
            "target": target,
            "hostname": ddef["hostname"],
            "discovered_ports": discovered_ports,
            "active_hosts": active_hosts,
            "passive_results": passive_results,
            "scanner_statuses": scanner_statuses_run2,
            "generated_at": run2_end.isoformat(),
        }
        ev_recon = _write_evidence_file(
            ev_folder,
            f"recon_results_{recon_id}_{scan2_id}.json",
            json.dumps(recon_json_data, indent=2),
        )
        repo.add_evidence_record(
            investigation_id=recon_id,
            evidence_type="recon_results_json",
            file_name=ev_recon["file_name"],
            file_size=ev_recon["file_size"],
            sha256_hash=ev_recon["sha256_hash"],
            local_path=ev_recon["local_path"],
            scan_id=scan2_id,
            scanner_source="combined_orchestrator",
            target=target,
            run_number=2,
            content_type="application/json",
        )

        # 5. Calculate and Update Overall Exposure Score
        active_findings = repo.list_findings(recon_id)
        exp_data = ExposureScoringEngine.calculate_investigation_exposure(
            findings=active_findings,
            discovered_ports=discovered_ports,
        )
        final_score = float(exp_data.get("exposure_score", 0.0))
        repo.update_exposure_score(recon_id, final_score)

        # 6. Generate Official Combined PDF Report
        try:
            bundle = load_campaign_results_bundle(recon_id, repo, scan_id=scan2_id)
            analysis = build_report_analysis(recon_id, repo, scan_id=scan2_id)
            targets_list = repo.list_authorized_targets(recon_id)
            evidence_list = repo.list_evidence(recon_id)

            pdf_filename = f"{cname.lower().replace(' ', '_').replace('&', 'and')}_combined.pdf"
            pdf_path = os.path.join(REPORTS_DIR, pdf_filename)

            out_pdf = generator.generate_pdf_report(
                investigation=camp,
                targets=targets_list,
                findings=active_findings,
                evidence=evidence_list,
                output_path=pdf_path,
                report_format="combined",
                results_bundle=bundle,
                analysis=analysis,
                generated_by="asip_ali",
                scan_run=repo.get_scan_execution(scan2_id) if hasattr(repo, "get_scan_execution") else None,
            )

            pdf_size = os.path.getsize(out_pdf) if os.path.exists(out_pdf) else 0
            with open(out_pdf, "rb") as pf:
                pdf_hash = hashlib.sha256(pf.read()).hexdigest()

            repo.add_report_record(
                investigation_id=recon_id,
                recon_id=recon_id,
                file_name=os.path.basename(out_pdf),
                file_size=pdf_size,
                sha256_hash=pdf_hash,
                report_type="combined",
                report_status="completed",
                scan_id=scan2_id,
                run_number=2,
                scan_type="combined",
                investigation_name=cname,
                generated_by_username="asip_ali",
                generated_by_user_id=1,
            )
            logger.info(f"[DemoSeeder] Generated report: {os.path.basename(out_pdf)} ({pdf_size} bytes)")
        except Exception as e:
            logger.warning(f"[DemoSeeder] Report generation notice for '{cname}': {e}")

        logger.info(f"[DemoSeeder] Demo {idx} '{cname}' seeded successfully (Recon ID: {recon_id}, Score: {final_score:.1f}).")

    return seeded_ids


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    repo = FootprintIQRepository()
    ids = seed_demo_investigations(repo=repo, force=True)
    print(f"\nSuccessfully seeded {len(ids)} demo investigations:")
    for rid in ids:
        c = repo.get_recon_campaign(rid)
        scans = repo.list_scans(investigation_id=rid)
        findings = repo.list_findings(rid)
        print(f" - {rid}: '{c.get('name')}' -> {len(scans)} scan runs, {len(findings)} findings")
