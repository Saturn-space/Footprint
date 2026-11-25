#!/usr/bin/env python3
"""
OSINT-RECON: Digital Footprint Investigator
CLI Entry Point for W2 Passive & W3 Active Reconnaissance Engines.
"""

import os
import sys
import json
import argparse
from typing import Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.orchestration.passive_pipeline import PassiveReconPipeline
from src.orchestration.active_pipeline import ActiveReconPipeline
from src.correlation.correlation_engine import CorrelationEngine
from src.orchestration.vulnerability_pipeline import VulnerabilityPipeline
from src.collectors.nuclei_collector import NucleiCollector


def print_passive_banner():
    banner = r"""
========================================================================
   ___  ____ ___ _   _ _____     ____  _____ ____ ___  _   _ 
  / _ \/ ___|_ _| \ | |_   _|   |  _ \| ____/ ___/ _ \| \ | |
 | | | \___ \| ||  \| | | |_____| |_) |  _|| |  | | | |  \| |
 | |_| |___) | || |\  | | |_____|  _ <| |__| |__| |_| | |\  |
  \___/|____/___|_| \_| |_|     |_| \_\_____\____\___/|_| \_|
       Digital Footprint Investigator — W2 Passive Engine
========================================================================
"""
    print(banner)


def print_active_banner():
    banner = r"""
========================================================================
   ___  ____ ___ _   _ _____        _    ____ _____ _____     _______ 
  / _ \/ ___|_ _| \ | |_   _|      / \  / ___|_   _|_ _\ \   / / ____|
 | | | \___ \| ||  \| | | | _____ / _ \| |     | |  | | \ \ / /|  _|  
 | |_| |___) | || |\  | | ||_____/ ___ \ |___  | |  | |  \ V / | |___ 
  \___/|____/___|_| \_| |_|     /_/   \_\____| |_| |___|  \_/  |_____|
       Digital Footprint Investigator — W3 Controlled Active Engine
========================================================================
"""
    print(banner)


def print_correlation_banner():
    banner = r"""
========================================================================
   ___  ____ ___ _   _ _____        ____ ___  ____  ____  
  / _ \/ ___|_ _| \ | |_   _|      / ___/ _ \|  _ \|  _ \ 
 | | | \___ \| ||  \| | | | _____ | |  | | | | |_) | |_) |
 | |_| |___) | || |\  | | ||_____|| |__| |_| |  _ <|  _ < 
  \___/|____/___|_| \_| |_|        \____\___/|_| \_\_| \_\
       Digital Footprint Investigator — W4 Correlation Engine
========================================================================
"""
    print(banner)


def print_vulnerability_banner():
    banner = r"""
========================================================================
   ___  ____ ___ _   _ _____       __     ___   _ _     _   _ 
  / _ \/ ___|_ _| \ | |_   _|      \ \   / / | | | |   | \ | |
 | | | \___ \| ||  \| | | | _____   \ \ / /| | | | |   |  \| |
 | |_| |___) | || |\  | | ||_____|   \ V / | |_| | |___| |\  |
  \___/|____/___|_| \_| |_|           \_/   \___/|_____|_| \_|
       Digital Footprint Investigator — W5 Vulnerability Engine
========================================================================
"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description="OSINT-RECON: Digital Footprint Investigator (W2 Passive, W3 Active, W4 Correlation & W5 Vulnerability Assessment)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Passive Reconnaissance (WHOIS, DNS, search engines):
  python main.py example.com
  python main.py --target example.com --timeout 25
  python main.py example.com --json-only

  # Active Reconnaissance (Controlled Nmap lab scanning):
  python main.py --active --target 192.168.56.111
  python main.py --active --target 192.168.56.111 --profile lab-basic
  python main.py --active --target 192.168.56.111 --json-only

  # Intelligence Correlation (Cross-source intelligence synthesis):
  python main.py --correlate
  python main.py --correlate --passive-input data/processed/SCAN-PASSIVE_report.json --active-input data/processed/SCAN-ACTIVE_report.json
  python main.py --correlate --json-only

  # Vulnerability & Unified Assessment (Nuclei, Nmap NSE, Nessus):
  python main.py --unified-scan nuclei --target 127.0.0.1
  python main.py --vulnerability-scan --target 192.168.56.111 --import-report scans/historical.xml
  python main.py --check-readiness
        """
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="Target domain or IP address (e.g. example.com or 192.168.56.111)"
    )
    parser.add_argument(
        "-t", "--target",
        dest="target_flag",
        help="Target domain or IP address (alternative to positional argument)"
    )
    parser.add_argument(
        "--active",
        action="store_true",
        help="Enable controlled active reconnaissance mode (Nmap)"
    )
    parser.add_argument(
        "--correlate",
        action="store_true",
        help="Enable multi-source intelligence correlation engine (W4)"
    )
    parser.add_argument(
        "--vulnerability-scan",
        dest="vulnerability_scan",
        action="store_true",
        help="Correlate historical vulnerability XML reports (--import-report) or check legacy status"
    )
    parser.add_argument(
        "--scan-config",
        dest="scan_config",
        default="Full and fast",
        help="Historical report metadata configuration label"
    )
    parser.add_argument(
        "--import-report",
        dest="import_report",
        default=None,
        help="Path to a historical Greenbone/OpenVAS XML report file to import and correlate"
    )
    parser.add_argument(
        "--check-readiness",
        dest="check_readiness",
        action="store_true",
        help="Perform Nuclei, Nessus, Nmap, OSINT, and Entity Graph readiness diagnostics"
    )
    parser.add_argument(
        "--passive-input",
        nargs="+",
        dest="passive_inputs",
        default=None,
        help="One or more processed W2 passive report JSON file paths"
    )
    parser.add_argument(
        "--active-input",
        nargs="+",
        dest="active_inputs",
        default=None,
        help="One or more processed W3 active scan report JSON file paths"
    )
    parser.add_argument(
        "--report-dir",
        dest="report_dir",
        default=None,
        help="Directory to store correlation reports"
    )
    parser.add_argument(
        "--profile",
        dest="profile",
        default="lab-basic",
        choices=["lab-basic", "lab-safe-minimal", "lab-common-services"],
        help="Active scan profile (default: lab-basic)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Execution timeout in seconds (default: 30s for passive, 60s for active)"
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        default=None,
        help="Optional base directory to store evidence, processed JSON, and reports"
    )
    parser.add_argument(
        "--server",
        action="store_true",
        help="Launch the FootprintIQ Enterprise FastAPI web application and UI dashboard"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host interface to bind the FootprintIQ web server (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind the FootprintIQ web server (default: 8000)"
    )
    parser.add_argument(
        "--health",
        action="store_true",
        help="Perform comprehensive health check of all platform subsystems, databases, and scanners"
    )
    parser.add_argument(
        "--unified-scan",
        dest="unified_scan",
        choices=["passive", "network_discovery", "nmap_services", "nmap_nse", "nuclei", "nessus", "combined"],
        help="Execute unified multi-scanner assessment across authorized engines"
    )
    parser.add_argument(
        "--no-pdf",
        action="store_true",
        help="Disable preliminary PDF report generation"
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Output raw JSON to stdout"
    )

    args = parser.parse_args()

    # Determine execution mode and target
    if args.server:
        import uvicorn
        print("=" * 72)
        print("   FootprintIQ Enterprise Platform — Starting FastAPI & Dashboard Server")
        print(f"   Listening on: http://{args.host}:{args.port}")
        print(f"   API Documentation: http://{args.host}:{args.port}/docs")
        print("=" * 72)
        uvicorn.run("src.api.app:app", host=args.host, port=args.port, reload=False, server_header=False)
        sys.exit(0)

    elif args.health:
        from src.api.routers.health import get_system_health
        health_data = get_system_health()
        print(json.dumps(health_data, indent=2))
        sys.exit(0)

    elif args.unified_scan:
        from src.orchestration.unified_orchestrator import UnifiedScanOrchestrator
        target = args.domain or args.target_flag or "192.168.56.111"
        print(f"[*] Launching FootprintIQ Unified Scan: {args.unified_scan} on target: {target}")
        orchestrator = UnifiedScanOrchestrator()
        result = orchestrator.execute_scan(
            investigation_id="INV-CLI-001",
            scan_type=args.unified_scan,
            target=target,
            profile=args.profile or "lab-basic"
        )
        print(json.dumps(result, indent=2, default=str))
        sys.exit(0 if result.get("status") in ("COMPLETED", "SUCCESS") else 1)

    elif args.check_readiness:
        # Scanner & Tool Ecosystem Readiness Diagnostics Mode
        print_vulnerability_banner()
        print("[*] Running ProjectDiscovery Nuclei, Tenable Nessus, and Entity Graph diagnostics...")
        nuc = NucleiCollector().check_readiness()
        from src.collectors.nessus_collector import NessusCollector
        from src.services.graph_intelligence_service import GraphIntelligenceService
        nessus_caps = NessusCollector().get_api_capabilities()
        graph_rt = GraphIntelligenceService.get_maltego_runtime_status()

        print("\n" + "=" * 72)
        print("  FOOTPRINTIQ VULNERABILITY & GRAPH READINESS AUDIT")
        print("=" * 72)
        print(f"  Nuclei Ready:         {'READY' if nuc.get('ready') else 'UNAVAILABLE'} ({nuc.get('version')})")
        print(f"  Nuclei Templates:     {nuc.get('templates_count', 0)} loaded")
        print(f"  Nessus Status:        {nessus_caps.get('status')} ({nessus_caps.get('nessus_type') or 'Unconfigured'})")
        print(f"  Nessus Scan Launch:   {'Enabled' if nessus_caps['capabilities']['scan_launch'] else 'Read-Only (scan_api=false)'}")
        print(f"  Graph / Maltego:      {graph_rt.get('mode')}")
        print("-" * 72 + "\n")
        sys.exit(0 if nuc.get("ready") else 2)

    elif args.vulnerability_scan:
        # Vulnerability Assessment Mode (W5)
        target = args.domain or args.target_flag or "192.168.56.111"
        timeout = args.timeout or 1800
        scan_cfg = args.scan_config or "Full and fast"

        if not args.json_only:
            print_vulnerability_banner()
            print(f"[*] Target specified:     {target}")
            print(f"[*] Scan configuration:   {scan_cfg}")
            print(f"[*] Assessment timeout:   {timeout}s")
            if args.import_report:
                print(f"[*] Importing XML report: {args.import_report}")
            print("[*] Enforcing target scope authorization...")

        pipeline = VulnerabilityPipeline(
            base_dir=args.output_dir or PROJECT_ROOT,
            timeout=timeout,
            enable_pdf=not args.no_pdf
        )

        result = pipeline.run(
            target=target,
            config_name=scan_cfg,
            import_xml_path=args.import_report
        )

        if args.json_only:
            print(result.model_dump_json(indent=2))
            if result.overall_status == "SUCCESS":
                sys.exit(0)
            elif result.overall_status in ("BLOCKED", "PARTIAL"):
                sys.exit(2)
            else:
                sys.exit(1)

        # Human-readable W5 Vulnerability CLI summary
        print("\n" + "=" * 72)
        print("  VULNERABILITY ASSESSMENT EXECUTION SUMMARY")
        print("=" * 72)
        print(f"  Assessment ID:      {result.assessment_id}")
        print(f"  Execution Mode:     {result.execution_mode}")
        print(f"  Target Host:        {result.target}")
        print(f"  Overall Status:     {result.overall_status}")
        print(f"  Scan Configuration: {result.metadata.config_name if result.metadata else scan_cfg}")
        print(f"  Execution Window:   {result.start_time_utc[:19]}Z -> {result.end_time_utc[:19]}Z")
        print("-" * 72)

        auth = result.authorization_record
        print("  TARGET AUTHORIZATION RECORD:")
        print(f"   • Authorization:   {auth.authorization_status}")
        print(f"   • Target Category: {auth.category}")
        print(f"   • Scope:           {auth.scope}")
        print(f"   • Authorizer:      {auth.operator}")
        print("-" * 72)

        print("  VULNERABILITY SEVERITY SUMMARY:")
        sev = result.severity_summary or {}
        print(f"   • Total Findings:   {len(result.findings)}")
        print(f"   • Critical (9.0+):  {sev.get('Critical', 0)}")
        print(f"   • High (7.0-8.9):   {sev.get('High', 0)}")
        print(f"   • Medium (4.0-6.9): {sev.get('Medium', 0)}")
        print(f"   • Low (0.1-3.9):    {sev.get('Low', 0)}")
        print(f"   • Log / Info (0.0): {sev.get('Log', 0)}")
        print("-" * 72)

        if result.findings:
            print("  TOP VULNERABILITY FINDINGS:")
            for f in result.findings[:8]:
                port_str = f"{f.port}/{f.protocol}" if f.port > 0 else "host"
                cves_str = f"[{', '.join(f.cve_ids[:2])}]" if f.cve_ids else ""
                print(f"   • {f.threat.upper():8} ({f.severity:4.1f}) : [{port_str:10}] {f.name[:38]} {cves_str}")
            print("-" * 72)

        if result.correlated_nmap_services:
            print("  CORRELATED NMAP ACTIVE SERVICES:")
            for c in result.correlated_nmap_services[:6]:
                ep = f"{c.get('host')}:{c.get('port')}/{c.get('protocol')}"
                print(f"   • {ep:22} : {c.get('service_name')} -> {c.get('vulnerability_name')[:30]}")
            print("-" * 72)

        if result.defensive_observations:
            print("  DEFENSIVE OBSERVATIONS:")
            for obs in result.defensive_observations:
                print(f"   • {obs}")
            print("-" * 72)

        if result.recommended_actions:
            print("  PRIORITIZED REMEDIATION ACTIONS:")
            for act in result.recommended_actions:
                print(f"   • {act}")
            print("-" * 72)

        if result.errors:
            print("  ERRORS / NOTICES:")
            for err in result.errors:
                print(f"   [!] {err}")
            print("-" * 72)

        print("  OUTPUT ARTIFACTS:")
        if result.json_report_path:
            print(f"   • JSON Report:      {result.json_report_path}")
        if result.pdf_report_path:
            print(f"   • PDF Report:       {result.pdf_report_path}")
        print("=" * 72 + "\n")

        if result.overall_status == "SUCCESS":
            sys.exit(0)
        elif result.overall_status in ("BLOCKED", "PARTIAL"):
            sys.exit(2)
        else:
            sys.exit(1)

    elif args.correlate:
        # Intelligence Correlation Engine Mode (W4)
        base_dir = args.output_dir or PROJECT_ROOT
        processed_dir = os.path.join(base_dir, "data", "processed")

        passive_inputs = list(args.passive_inputs or [])
        active_inputs = list(args.active_inputs or [])

        # Auto-discover if inputs were not explicitly provided
        if not passive_inputs and os.path.isdir(processed_dir):
            for fname in sorted(os.listdir(processed_dir), reverse=True):
                if fname.startswith("SCAN-") and fname.endswith("_report.json"):
                    fpath = os.path.join(processed_dir, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        if "target_domain" in data or "collector_records" in data:
                            passive_inputs.append(fpath)
                            break
                    except Exception:
                        pass

        if not active_inputs and os.path.isdir(processed_dir):
            for fname in sorted(os.listdir(processed_dir), reverse=True):
                if fname.startswith("SCAN-") and fname.endswith("_report.json"):
                    fpath = os.path.join(processed_dir, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        if "hosts" in data and "authorization_record" in data:
                            active_inputs.append(fpath)
                            break
                    except Exception:
                        pass

        if not args.json_only:
            print_correlation_banner()
            print("[*] Initializing Intelligence Correlation Engine (W4)...")
            if passive_inputs:
                print(f"[*] Passive scan input(s): {passive_inputs}")
            else:
                print("[!] No passive scan inputs specified or found.")
            if active_inputs:
                print(f"[*] Active scan input(s):  {active_inputs}")
            else:
                print("[!] No active scan inputs specified or found.")

        engine = CorrelationEngine(
            base_dir=base_dir,
            enable_pdf=not args.no_pdf
        )

        if not args.json_only:
            print("[*] Ingesting evidence, normalizing assets, and synthesizing graph...")

        result = engine.correlate(
            passive_files=passive_inputs,
            active_files=active_inputs
        )

        if args.json_only:
            print(result.model_dump_json(indent=2))
            sys.exit(0 if result.overall_status in ("SUCCESS", "PARTIAL") else 1)

        # Human-readable W4 Correlation CLI summary
        print("\n" + "=" * 72)
        print("  INTELLIGENCE CORRELATION EXECUTION SUMMARY")
        print("=" * 72)
        print(f"  Correlation ID:     {result.correlation_id}")
        print(f"  Overall Status:     {result.overall_status}")
        print(f"  Execution Window:   {result.start_time_utc[:19]}Z -> {result.end_time_utc[:19]}Z")
        print(f"  Source Scan IDs:    {', '.join(result.source_scan_ids) or 'None'}")
        print("-" * 72)

        print("  ASSET RESOLUTION INVENTORY:")
        print(f"   • Total Resolved Assets:     {len(result.assets)}")
        type_counts = {}
        for a in result.assets:
            type_counts[a.asset_type] = type_counts.get(a.asset_type, 0) + 1
        for atype, cnt in sorted(type_counts.items()):
            print(f"      - {atype.upper():16}: {cnt}")

        print("-" * 72)
        print("  EVIDENCE-BACKED RELATIONSHIPS:")
        print(f"   • Total Relationships:       {len(result.relationships)}")
        c_summary = result.confidence_summary.get("counts", {})
        print(f"   • Confidence Breakdown:      CORROBORATED: {c_summary.get('CORROBORATED', 0)} | DIRECT: {c_summary.get('DIRECT', 0)} | INDIRECT: {c_summary.get('INDIRECT', 0)} | UNCONFIRMED: {c_summary.get('UNCONFIRMED', 0)}")
        print(f"   • Avg Confidence Score:      {result.confidence_summary.get('average_confidence_score', 0.0):.2f}")

        print("-" * 72)
        print("  INTELLIGENCE GRAPH METRICS:")
        g_metrics = result.graph.get("metrics", {})
        print(f"   • Graph Nodes:               {g_metrics.get('node_count', len(result.assets))}")
        print(f"   • Graph Edges:               {g_metrics.get('edge_count', len(result.relationships))}")
        print(f"   • Connected Components:      {g_metrics.get('connected_component_count', 0)}")
        print(f"   • Isolated Assets:           {g_metrics.get('isolated_node_count', 0)}")
        print(f"   • Network Graph Density:     {g_metrics.get('graph_density', 0.0)}")

        print("-" * 72)
        print("  UNIFIED ASSET PROFILES SYNTHESIZED:")
        for prof in result.profiles:
            env_str = f"[{prof.environment.upper()}]"
            active_info = f"({len(prof.open_ports)} open ports)" if prof.open_ports else ""
            domain_info = f"({len(prof.related_ips)} IPs, {len(prof.discovered_subdomains)} subdomains)" if prof.asset_type == "domain" else ""
            print(f"   • {env_str:12} {prof.asset_type.upper():8} : {prof.canonical_identity} {active_info}{domain_info}")

        if result.warnings:
            print("-" * 72)
            print("  NOTICES / WARNINGS:")
            for w in result.warnings:
                print(f"   [!] {w}")

        if result.errors:
            print("-" * 72)
            print("  ERRORS:")
            for err in result.errors:
                print(f"   [ERROR] {err}")

        print("-" * 72)
        print("  OUTPUT ARTIFACTS:")
        if result.json_report_path:
            print(f"   • Correlation JSON: {result.json_report_path}")
        if result.pdf_report_path:
            print(f"   • Correlation PDF:  {result.pdf_report_path}")
        print("=" * 72 + "\n")

        sys.exit(0 if result.overall_status in ("SUCCESS", "PARTIAL") else 1)

    elif args.active:
        # Active Reconnaissance Mode (W3)
        target = args.domain or args.target_flag or "192.168.56.111"
        timeout = args.timeout or 60

        if not args.json_only:
            print_active_banner()
            print(f"[*] Target specified: {target}")
            print(f"[*] Scan profile:     {args.profile}")
            print(f"[*] Scanner timeout:  {timeout}s")
            print("[*] Enforcing target scope authorization...")

        pipeline = ActiveReconPipeline(
            base_dir=args.output_dir or PROJECT_ROOT,
            timeout=timeout,
            enable_pdf=not args.no_pdf
        )

        if not args.json_only:
            print("[*] Running active reconnaissance pipeline (Nmap)...")

        result = pipeline.run(target=target, profile=args.profile)

        if args.json_only:
            print(result.model_dump_json(indent=2))
            if result.overall_status in ("SUCCESS", "PARTIAL"):
                sys.exit(0)
            elif result.overall_status == "BLOCKED":
                sys.exit(2)
            else:
                sys.exit(1)

        # Human-readable active recon CLI summary
        print("\n" + "=" * 72)
        print("  ACTIVE RECONNAISSANCE EXECUTION SUMMARY")
        print("=" * 72)
        print(f"  Scan ID:            {result.scan_id}")
        print(f"  Target Host:        {result.target}")
        print(f"  Overall Status:     {result.overall_status}")
        print(f"  Scan Profile:       {result.scan_profile}")
        print(f"  Execution Window:   {result.start_time_utc[:19]}Z -> {result.end_time_utc[:19]}Z")
        print("-" * 72)

        auth = result.authorization_record
        print("  TARGET AUTHORIZATION RECORD:")
        print(f"   • Authorization:   {auth.authorization_status}")
        print(f"   • Target Category: {auth.category}")
        print(f"   • Permitted Scope: {auth.scope}")
        print(f"   • Operator:        {auth.operator}")

        print("-" * 72)
        summary = result.summary or {}
        print("  PORT & SERVICE DISCOVERY SUMMARY:")
        print(f"   • Host State:        {summary.get('host_status', 'unknown').upper()}")
        print(f"   • Open TCP Ports:    {summary.get('open_ports_count', 0)}")
        print(f"   • Filtered Ports:    {summary.get('filtered_ports_count', 0)}")
        print(f"   • Closed Ports:      {summary.get('closed_ports_count', 0)}")
        print(f"   • Detected Services: {summary.get('services_detected_count', 0)}")

        # Print open ports detail
        open_ports = [p for h in result.hosts for p in h.ports if p.state == "open"]
        if open_ports:
            print("\n  OBSERVED OPEN PORTS & IDENTIFIED SERVICES:")
            for p in open_ports:
                s_name = p.service.name if p.service else "unknown"
                prod_ver = []
                if p.service and p.service.product:
                    prod_ver.append(p.service.product)
                if p.service and p.service.version:
                    prod_ver.append(p.service.version)
                prod_str = f"({', '.join(prod_ver)})" if prod_ver else ""
                print(f"   • {p.portid:5d}/{p.protocol:3s} [{p.state:4s}] - {s_name:12s} {prod_str}")

        if result.defensive_observations:
            print("-" * 72)
            print("  DEFENSIVE OBSERVATIONS:")
            for obs in result.defensive_observations:
                print(f"   • {obs}")

        if result.recommended_actions:
            print("-" * 72)
            print("  RECOMMENDED DEFENSIVE ACTIONS:")
            for act in result.recommended_actions:
                print(f"   • {act}")

        if result.errors:
            print("-" * 72)
            print("  NOTICES / ERRORS:")
            for err in result.errors:
                print(f"   [!] {err}")

        print("-" * 72)
        print("  OUTPUT ARTIFACTS:")
        if result.json_report_path:
            print(f"   • JSON Report:   {result.json_report_path}")
        if result.pdf_report_path:
            print(f"   • PDF Report:    {result.pdf_report_path}")
        if result.raw_files:
            print("   • Raw Evidence:")
            for k, v in result.raw_files.items():
                h = result.file_hashes.get(k, "")
                h_str = f" [SHA256: {h[:16]}...]" if h else ""
                print(f"      - {k:10}: {v}{h_str}")
        print("=" * 72 + "\n")

        if result.overall_status in ("SUCCESS", "PARTIAL"):
            sys.exit(0)
        elif result.overall_status == "BLOCKED":
            sys.exit(2)
        else:
            sys.exit(1)

    else:
        # Passive Reconnaissance Mode (W2)
        target = args.domain or args.target_flag
        if not target:
            parser.print_help()
            sys.exit(1)

        timeout = args.timeout or 30

        if not args.json_only:
            print_passive_banner()
            print(f"[*] Target specified: {target}")
            print(f"[*] Collector timeout: {timeout}s")
            print("[*] Initializing Passive Reconnaissance Pipeline...")

        pipeline = PassiveReconPipeline(
            base_dir=args.output_dir or PROJECT_ROOT,
            timeout=timeout,
            enable_pdf=not args.no_pdf
        )

        if not args.json_only:
            print("[*] Running collectors (WHOIS, DNS, theHarvester)...")

        result = pipeline.run(target)

        if args.json_only:
            print(result.model_dump_json(indent=2))
            sys.exit(0 if result.overall_status in ("SUCCESS", "PARTIAL") else 1)

        # Human-readable CLI summary
        print("\n" + "=" * 72)
        print("  PASSIVE RECONNAISSANCE EXECUTION SUMMARY")
        print("=" * 72)
        print(f"  Scan ID:            {result.scan_id}")
        print(f"  Target Domain:      {result.target_domain}")
        print(f"  Overall Status:     {result.overall_status}")
        print(f"  Execution Window:   {result.start_time_utc[:19]}Z -> {result.end_time_utc[:19]}Z")
        print("-" * 72)
        print("  COLLECTOR BREAKDOWN:")
        for rec in result.collector_records:
            count = len(rec.dns_records) if rec.recon_category == "dns" else (
                len(rec.discovered_domains) if rec.recon_category == "search_engine_harvesting" else (
                    1 if rec.whois_data else 0
                )
            )
            print(f"   • {rec.recon_category.upper():20} [{rec.scan_status:7}] - {count} item(s)")

        print("-" * 72)
        summary = result.summary or {}
        print("  CORRELATED ASSET METRICS:")
        print(f"   • Discovered Subdomains: {summary.get('subdomains_count', 0)}")
        print(f"   • IP Addresses:          {summary.get('ip_addresses_count', 0)}")
        print(f"   • Public Email Contacts: {summary.get('email_addresses_count', 0)}")
        print(f"   • Mail Servers (MX):     {summary.get('mail_servers_count', 0)}")
        print(f"   • Authoritative NS:      {summary.get('nameservers_count', 0)}")
        print(f"   • Domain Registrar:      {summary.get('registrar', 'Unknown')}")
        print(f"   • DNSSEC Status:         {summary.get('dnssec_status', 'Unknown')}")

        if result.defensive_observations:
            print("-" * 72)
            print("  DEFENSIVE OBSERVATIONS:")
            for obs in result.defensive_observations:
                print(f"   • {obs}")

        if result.recommended_actions:
            print("-" * 72)
            print("  RECOMMENDED ACTIONS:")
            for act in result.recommended_actions:
                print(f"   • {act}")

        if result.errors:
            print("-" * 72)
            print("  NOTICES / ERRORS:")
            for err in result.errors:
                print(f"   [!] {err}")

        print("-" * 72)
        print("  OUTPUT ARTIFACTS:")
        if result.json_report_path:
            print(f"   • JSON Report:   {result.json_report_path}")
        if result.pdf_report_path:
            print(f"   • PDF Report:    {result.pdf_report_path}")
        if result.raw_files:
            print("   • Raw Evidence:")
            for k, v in result.raw_files.items():
                print(f"      - {k:12}: {v}")
        print("=" * 72 + "\n")

        sys.exit(0 if result.overall_status in ("SUCCESS", "PARTIAL") else 1)


if __name__ == "__main__":
    main()
