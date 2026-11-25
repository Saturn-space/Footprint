# OSINT-RECON — WEEK 4 (W4) IMPLEMENTATION REPORT
## Multi-Source Reconnaissance Intelligence Correlation Engine

**Project:** OSINT-RECON  
**Title:** Digital Footprint Investigator  
**Team Members:**
- Asip Ali
- Mohan Prasad

**Environment:**
- **Host OS:** Windows
- **Virtualization:** Oracle VirtualBox
- **Guest OS:** Kali Linux 2025.4 (Rolling)
- **IDE:** Antigravity IDE (Remote SSH)
- **Target Lab VM:** Metasploitable2 (`192.168.56.111` on VirtualBox Host-Only network `eth1`)
- **Canonical Workspace:** `/home/asip_ali/Desktop/Projects/OSINT-RECON`
- **Symlink:** `/home/asip_ali/OSINT-RECON`
- **Execution Date:** 2026-11-09

---

## 1. W4 Objectives

The objective of Week 4 (W4) is to build an intelligence correlation engine that unifies:
1. **W2 Passive Reconnaissance Findings:** WHOIS records, DNS resource records (A, AAAA, MX, NS, TXT, CNAME), and search engine harvests (theHarvester subdomains and email addresses).
2. **W3 Active Reconnaissance Findings:** Nmap TCP Connect port scans (`-sT`), service version banners (`-sV`), product identifications, and Common Platform Enumeration (CPE) strings on authorized lab targets (`192.168.56.111`).
3. **Synthesis & Correlation:** Resolving assets into stable deterministic entities, building evidence-backed relationships, computing transparent confidence ratings, generating an intelligence network graph, constructing unified asset profiles, and generating dual machine-readable JSON and publication-quality PDF reports.

---

## 2. Initial Repository Audit

Prior to implementation, a complete audit of the repository was conducted:
- **Canonical Workspace:** `/home/asip_ali/Desktop/Projects/OSINT-RECON` verified active with Python 3.13 virtual environment (`.venv`).
- **W1 Baseline Scans:** All 4 baseline artifacts (`whois_example_com.json`, `dns_example_com.json`, `theharvester_kali_org.json`, `nmap_loopback.json`) and raw outputs in `data/raw_outputs/` intact.
- **W2 Passive Findings:** Verified intact in `data/processed/` (e.g. `SCAN-20261109-053636-b40a_report.json`), capturing 16 deduplicated findings on `example.com`.
- **W3 Active Findings:** Verified intact in `data/processed/` (e.g. `SCAN-20261109-082403-bdd8_report.json`), capturing 18 open TCP ports, services, versions, and CPEs on authorized target `192.168.56.111`.
- **Duplicate Prevention:** Existing modules in `src/processors/` (`normalizer.py`, `deduplicator.py`, `correlator.py`) handle single-scan passive metrics. W4 correlation requirements span cross-source, graph-based synthesis, placed in `src/correlation/` and `src/reporting/correlation_report.py`.

---

## 3. Existing W2/W3 Components Reused

1. **W1/W2 Data Models (`src/schema.py`):** `ReconRecord`, `TargetInfo`, `ToolInfo`, `DNSRecord`, `ServiceInfo`, `WhoisData`, `NormalizedFinding`, `PassivePipelineResult`.
2. **W3 Active Models (`src/schema.py`):** `TargetAuthorizationRecord`, `NmapService`, `NmapPort`, `NmapHost`, `NmapScanMetadata`, `ActiveReconResult`.
3. **Cryptographic Checksums:** Reused SHA256 hashing patterns from `src/collectors/nmap_collector.py` and `src/authorization/target_authorizer.py`.
4. **ReportLab Framework:** Reused styling paradigms, paragraph hierarchies, and canvas page-numbering architectures established in `src/reporting/pdf_generator.py`.
5. **CLI Integration:** Preserved positional domain queries (`main.py example.com`) and active scan flags (`main.py --active --target 192.168.56.111`).

---

## 4. Architecture Overview

The W4 Intelligence Correlation Engine is organized into decoupled modules under `src/correlation/`:

```text
src/
├── correlation/
│   ├── __init__.py                 # Public package interface
│   ├── asset_resolver.py           # Entity normalization, deterministic IDs, duplicate merging
│   ├── evidence_linker.py          # Evidence registry, SHA256 integrity, provenance linking
│   ├── confidence_engine.py        # Rule-based, transparent, reproducible confidence calculation
│   ├── relationship_builder.py     # Evidence-supported relationship construction & lab isolation
│   ├── intelligence_graph.py       # Pure-Python directed graph, component partitioning, metrics
│   ├── asset_profile_builder.py    # Domain & IP profile synthesis without assumed data
│   └── correlation_engine.py       # Orchestrator consuming passive & active outputs
├── reporting/
│   └── correlation_report.py       # Dual JSON & 15-section PDF report generator
└── schema.py                       # Unified Pydantic v2 data models
```

---

## 5. Files Created

| File Path | Description |
| :--- | :--- |
| `src/correlation/__init__.py` | Package exports for resolver, linker, confidence, builder, graph, and engine. |
| `src/correlation/asset_resolver.py` | Entity normalizer, deterministic asset ID generator (`ASSET:TYPE:CANONICAL`), duplicate resolver. |
| `src/correlation/evidence_linker.py` | Registers cryptographic evidence references, computes SHA256 checksums, maps raw files. |
| `src/correlation/confidence_engine.py` | Deterministic confidence evaluator (`DIRECT`, `CORROBORATED`, `INDIRECT`, `UNCONFIRMED`). |
| `src/correlation/relationship_builder.py` | Builds evidence-backed relationships; enforces strict Metasploitable2 lab isolation. |
| `src/correlation/intelligence_graph.py` | Lightweight pure-Python graph, calculates connected components, isolated nodes, density. |
| `src/correlation/asset_profile_builder.py` | Synthesizes comprehensive `UnifiedAssetProfile` objects for domains and IP endpoints. |
| `src/correlation/correlation_engine.py` | Master orchestrator consuming W2/W3 JSON results in read-only mode and executing pipeline. |
| `src/reporting/correlation_report.py` | Generates formatted JSON reports and ReportLab multi-page PDF intelligence reports. |
| `config/correlation_config.json` | Environment boundaries, confidence thresholds, and graph export settings. |
| `config/correlation_schema.json` | JSON Schema Draft 2020-12 specification validating `CorrelationResult`. |
| `tests/test_asset_resolver.py` | 10 unit tests for entity normalization, asset ID stability, and duplicate merging. |
| `tests/test_evidence_linker.py` | 4 unit tests for evidence hashing, ID determinism, and multi-collector linking. |
| `tests/test_confidence_engine.py` | 5 unit tests for direct, corroborated, indirect, and duplicate containment rules. |
| `tests/test_relationship_builder.py` | 4 unit tests for DNS/Nmap relationships, empty evidence rejection, and lab isolation. |
| `tests/test_intelligence_graph.py` | 5 unit tests for graph edges, component separation, isolated nodes, and JSON export. |
| `tests/test_asset_profiles.py` | 2 unit tests for domain and lab IP profile construction without assumptions. |
| `tests/test_correlation_engine.py` | 5 unit tests for pipeline orchestration, schema validation, and error containment. |
| `tests/test_w4_integration.py` | 2 integration tests evaluating real W2 and W3 repository scan files and CLI flags. |
| `docs/W4_IMPLEMENTATION_REPORT.md` | Comprehensive Week 4 implementation, testing, and audit report. |

---

## 6. Files Modified

| File Path | Modifications |
| :--- | :--- |
| `src/schema.py` | Extended with Pydantic v2 models: `Asset`, `AssetRelationship`, `EvidenceReference`, `UnifiedAssetProfile`, and `CorrelationResult`. Preserves 100% backward compatibility with W1/W2/W3 models. |
| `main.py` | Added `import json`, `print_correlation_banner()`, CLI arguments (`--correlate`, `--passive-input`, `--active-input`, `--report-dir`), smart auto-discovery of latest processed reports, and terminal execution summary. |
| `README.md` | Updated with W4 CLI commands and documentation links. |

---

## 7. Data Models

Five unified Pydantic v2 data models were implemented in `src/schema.py`:

1. **`Asset`:**
   - `asset_id`: Stable deterministic identifier (e.g. `ASSET:DOMAIN:example.com`, `ASSET:IPV4:192.168.56.111`).
   - `asset_type`: `Literal["domain", "subdomain", "ipv4", "ipv6", "hostname", "email", "nameserver", "service", "port", "cpe"]`.
   - `canonical_value`: Normalized string representation.
   - `display_name`: Human-readable label.
   - `first_seen`, `last_seen`: Timezone-aware ISO 8601 UTC timestamps.
   - `sources`: List of reporting tools/scans.
   - `tags`: Categorical classification tags (e.g. `lab`, `public_ip`, `target_domain`).
   - `attributes`: Dictionary of verified attributes.

2. **`AssetRelationship`:**
   - `relationship_id`: Deterministic hash ID (`REL-<PREDICATE>-<DIGEST>`).
   - `source_asset_id`, `target_asset_id`: Connected asset identifiers.
   - `relationship_type`: Standardized predicate (e.g. `DOMAIN_RESOLVES_TO_IP`, `IP_HAS_OPEN_PORT`, `IP_EXPOSES_SERVICE`, `SERVICE_HAS_CPE`).
   - `evidence_ids`: List of supporting `evidence_id` references.
   - `confidence`: `Literal["DIRECT", "CORROBORATED", "INDIRECT", "UNCONFIRMED"]`.
   - `confidence_score`: Float between 0.0 and 1.0.
   - `confidence_explanation`: Human-readable justification.
   - `first_observed`, `last_observed`: ISO 8601 UTC observation timestamps.

3. **`EvidenceReference`:**
   - `evidence_id`: Deterministic identifier (`EVID-<MODULE>-<TYPE>-<DIGEST>`).
   - `source_module`: Originating collector (e.g. `dnspython`, `nmap`, `whois`).
   - `scan_id`: Unique scan session identifier.
   - `evidence_type`: Categorical type (`dns_a_record`, `nmap_open_port`, `nmap_service_probe`).
   - `original_value`: Unaltered observed value.
   - `normalized_value`: Standardized value.
   - `source_file`: Path to preserved raw evidence on disk.
   - `sha256`: Cryptographic checksum of raw evidence artifact.
   - `context`: Auxiliary metadata (e.g. port, protocol, TTL).

4. **`UnifiedAssetProfile`:**
   - Consolidates complete profile information for primary targets (domains and IP addresses).
   - Fields: `asset_id`, `canonical_identity`, `environment` (`lab`, `external`, `local`), `related_domains`, `related_hostnames`, `related_ips`, `dns_records`, `whois_information`, `open_ports`, `detected_services`, `detected_versions`, `cpe_identifiers`, `evidence_references`, `notes`.
   - Explicitly records `None` or notes when data is absent; never assumes unobserved open ports or WHOIS registration.

5. **`CorrelationResult`:**
   - Top-level schema containing `correlation_id`, `source_scan_ids`, `overall_status`, `assets`, `relationships`, `evidence`, `profiles`, `graph`, `confidence_summary`, `warnings`, `errors`, and output report paths.

---

## 8. Normalization Logic

- **DNS / Domains:** Strips leading protocols (`http://`, `https://`), port specifications, paths, trailing dots, and converts to lowercase FQDN.
- **IP Addresses:** Normalizes IPv4 and IPv6 using Python `ipaddress`. Strips leading zeros from IPv4 octets to prevent ambiguity. Generates exploded standard representation for IPv6.
- **Email Addresses:** Lowercases domain part, preserves local part (`user@domain.com`).
- **Services & Ports:** Converts service names to lowercase; canonicalizes ports as `<protocol>:<port>` (e.g. `tcp:22`).
- **CPE Identifiers:** Strips whitespace and normalizes to lowercase standard CPE format.

---

## 9. Correlation Rules

1. **`DOMAIN_RESOLVES_TO_IP`:** Established when a DNS `A` or `AAAA` record maps a domain to an IPv4/IPv6 address.
2. **`SUBDOMAIN_OF`:** Established when a discovered subdomain FQDN ends with the target domain.
3. **`DOMAIN_USES_NAMESERVER`:** Established when DNS `NS` records or WHOIS records delegate authority to a nameserver.
4. **`HOSTNAME_OBSERVED_ON_SCAN`:** Established when Nmap reverse DNS PTR resolution detects a hostname for an active IP.
5. **`IP_HAS_OPEN_PORT`:** Established when Nmap active scanning observes an open port state via TCP SYN-ACK handshake.
6. **`IP_EXPOSES_SERVICE`:** Established when Nmap service banner probing identifies an active application daemon.
7. **`SERVICE_HAS_CPE`:** Established when Nmap correlates a detected banner to a standardized CPE string.
8. **`EMAIL_DOMAIN_ASSOCIATION`:** Established when WHOIS contact data or search engine queries observe an email on the domain.
9. **Rule of Mandatory Evidence:** Every relationship requires at least one registered `evidence_id`. Unsupported relationships are rejected.
10. **Strict Laboratory VM Isolation:** The private lab asset `192.168.56.111` is NEVER associated with `example.com` or public domains unless an explicit source record (such as an authoritative DNS A record) establishes that relationship.

---

## 10. Confidence Methodology

Confidence is calculated using transparent, deterministic, reproducible rules:

$$\text{Confidence Score} = \begin{cases} 
0.95 & \text{CORROBORATED (Confirmed independently by } \ge 2 \text{ distinct toolchains)} \\
0.85 & \text{DIRECT (Confirmed via explicit primary technical probe)} \\
0.65 & \text{INDIRECT (Associative or contextual inference)} \\
0.40 & \text{UNCONFIRMED (Single unverified third-party scraping result)}
\end{cases}$$

- **Duplicate Containment Rule:** Multiple observations originating from the *same* tool or scan do not count as independent corroboration.
- **Heuristic Transparency:** Every relationship includes an explicit human-readable string explaining the confidence assignment.

---

## 11. Intelligence Graph Design

Implemented as a lightweight, pure-Python directed graph (`IntelligenceGraph`):
- **Nodes:** Represent resolved assets with canonical value, type, tags, sources, and attributes.
- **Edges:** Represent evidence-backed relationships with predicate, confidence class, numeric score, and evidence IDs.
- **Topological Analysis:** Calculates weakly connected components, isolated assets, and network density.
- **JSON Serialization:** Exports clean node/edge structures compatible with web visualization libraries (D3.js, Cytoscape, Vis.js).

---

## 12. Asset Profile Examples

### A. Public Target Domain (`example.com`)
```json
{
  "asset_id": "ASSET:DOMAIN:example.com",
  "asset_type": "domain",
  "canonical_identity": "example.com",
  "environment": "external",
  "related_domains": ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"],
  "related_ips": ["104.20.23.154", "172.66.147.243"],
  "dns_records": [
    { "record_type": "A", "value": "172.66.147.243", "ttl": 300 },
    { "record_type": "A", "value": "104.20.23.154", "ttl": 300 }
  ],
  "whois_information": {
    "registrar": "RESERVED-Internet Assigned Numbers Authority",
    "dnssec": "signedDelegation"
  },
  "open_ports": [],
  "detected_services": [],
  "notes": ["Primary public domain profile synthesized across 3 passive collector stream(s)."]
}
```

### B. Isolated Laboratory Endpoint (`192.168.56.111`)
```json
{
  "asset_id": "ASSET:IPV4:192.168.56.111",
  "asset_type": "ipv4",
  "canonical_identity": "192.168.56.111",
  "environment": "lab",
  "related_domains": [],
  "related_hostnames": ["metasploitable.localdomain"],
  "related_ips": [],
  "dns_records": [],
  "whois_information": null,
  "open_ports": [
    { "portid": 21, "protocol": "tcp", "state": "open", "reason": "syn-ack" },
    { "portid": 22, "protocol": "tcp", "state": "open", "reason": "syn-ack" },
    { "portid": 80, "protocol": "tcp", "state": "open", "reason": "syn-ack" }
  ],
  "detected_services": [
    { "port": 21, "service_name": "ftp", "product": "vsftpd", "version": "2.3.4" },
    { "port": 22, "service_name": "ssh", "product": "OpenSSH", "version": "4.7p1" }
  ],
  "cpe_identifiers": ["cpe:/a:vsftpd:vsftpd:2.3.4", "cpe:/a:openbsd:openssh:4.7p1"],
  "notes": ["Intentionally isolated laboratory virtual machine (192.168.56.111) on VirtualBox Host-Only network. Passive WHOIS and public DNS resolution are intentionally unavailable and unobserved."]
}
```

---

## 13. CLI Commands

```bash
# 1. Automatic Intelligence Correlation (Auto-discovers latest passive and active scans)
python main.py --correlate

# 2. Explicit Intelligence Correlation with specified report inputs
python main.py --correlate \
  --passive-input data/processed/SCAN-20261109-053636-b40a_report.json \
  --active-input data/processed/SCAN-20261109-082403-bdd8_report.json

# 3. Machine-readable JSON output to stdout
python main.py --correlate --json-only

# 4. Custom report output directory
python main.py --correlate --output-dir /tmp/osint_recon
```

---

## 14. Real Evidence Validation & Output Locations

Correlation was executed against the real repository scan evidence:
- **W2 Passive Scan ID:** `SCAN-20261109-053636-b40a` (`example.com`)
- **W3 Active Scan ID:** `SCAN-20261109-082403-bdd8` (`192.168.56.111`)

### Execution Results
- **Correlation ID:** `CORR-20261109-085926-bbc0`
- **Overall Status:** `SUCCESS`
- **Total Resolved Assets:** 56
- **Total Correlated Relationships:** 51
- **Intelligence Graph Nodes:** 56 | **Edges:** 51 | **Connected Components:** 6
- **Laboratory Isolation Verification:** `example.com` and `192.168.56.111` belong to distinct connected components with zero cross-edges.
- **Output Artifacts:**
  - **Processed JSON Report:** `data/processed/CORR-20261109-085926-bbc0_correlation_report.json`
  - **Publication PDF Report:** `reports/CORR-20261109-085926-bbc0_correlation_report.pdf` (11,048 bytes)

---

## 15. Automated Test Suite Results

The comprehensive test suite was executed across all unit, integration, and baseline modules:

| Test Module | Component Tested | Tests | Result | Description |
| :--- | :--- | :---: | :---: | :--- |
| `tests/test_asset_resolver.py` | `AssetResolver` | 10 | **PASSED** | Normalization, ID determinism, duplicate merging, lab tagging |
| `tests/test_evidence_linker.py` | `EvidenceLinker` | 4 | **PASSED** | File hashing, deterministic evidence IDs, multi-source linking |
| `tests/test_confidence_engine.py` | `ConfidenceEngine` | 5 | **PASSED** | Corroborated, direct, indirect, duplicate containment rules |
| `tests/test_relationship_builder.py` | `RelationshipBuilder` | 4 | **PASSED** | DNS/Nmap relationships, evidence requirements, lab isolation |
| `tests/test_intelligence_graph.py` | `IntelligenceGraph` | 5 | **PASSED** | Node/edge deduplication, isolated nodes, components, JSON export |
| `tests/test_asset_profiles.py` | `AssetProfileBuilder` | 2 | **PASSED** | Domain and lab IP profile synthesis without assumed data |
| `tests/test_correlation_engine.py` | `CorrelationEngine` | 5 | **PASSED** | Pipeline orchestration, schema validation, corrupt file handling |
| `tests/test_w4_integration.py` | W4 Real Data / CLI | 2 | **PASSED** | Real W2/W3 evidence correlation, isolation check, CLI testing |
| `tests/test_target_authorizer.py` | Target Authorizer | 11 | **PASSED** | Target allowlist, strict IP rejection, CIDR prohibition |
| `tests/test_nmap_parser.py` | Nmap XML Parser | 6 | **PASSED** | XML parsing, ports, banners, extraports |
| `tests/test_nmap_collector.py` | Nmap Collector | 6 | **PASSED** | Binary detection, argument safety, timeout handling |
| `tests/test_active_pipeline.py` | Active Pipeline | 4 | **PASSED** | End-to-end active scanning with mocked outputs |
| `tests/test_whois_collector.py` | W2 WHOIS Collector | 9 | **PASSED** | W2 WHOIS regression verification |
| `tests/test_dns_collector.py` | W2 DNS Collector | 9 | **PASSED** | W2 DNS regression verification (including Null MX) |
| `tests/test_theharvester_collector.py` | W2 theHarvester | 8 | **PASSED** | W2 theHarvester regression verification |
| `tests/test_processors.py` | W2 Processors | 4 | **PASSED** | Normalizer, deduplicator, and correlator verification |
| `tests/test_pipeline_integration.py` | W2 Passive Pipeline | 5 | **PASSED** | End-to-end passive pipeline regression verification |
| `tests/test_environment_verification.py` | W1 Lab Environment | 15 | **PASSED** | Master environment, storage, network, and toolchain checks |
| `tests/test_baseline_recon.py` | W1 Lab Baseline | 4 | **PASSED** | W1 baseline recon collections across all tools |

**Total Automated Test Count:** **118 Tests Executed | 118 PASSED | 0 FAILED** (100% Pass Rate).

---

## 16. Known Technical Limitations

1. **Passive/Active Asymmetry:** Public domain assets (`example.com`) have rich passive DNS and WHOIS records but lack active port scans (as external port scanning without authorization is strictly prohibited). Conversely, private lab targets (`192.168.56.111`) have rich active port scans but lack public WHOIS registration. The correlation engine correctly handles this asymmetry without fabricating data.
2. **Read-Only Ingestion:** The correlation engine operates strictly on saved JSON result files and does not trigger live active scans or DNS queries during correlation execution.

---

## 17. Outstanding Issues

- **None.** All W4 correlation requirements, entity normalization rules, relationship builders, confidence engines, graph exporters, unified asset profile builders, CLI arguments, and regression tests are fully operational with zero defects.

---

## 18. W1/W2/W3 Regression Status

- **W1 Baseline Reconnaissance:** Verified intact via `test_baseline_recon.py` (4/4 passed).
- **W1 Environment Verification:** Verified intact via `test_environment_verification.py` (15/15 passed).
- **W2 Passive Reconnaissance:** All collectors, normalizers, deduplicators, and CLI commands verified via 35 unit/integration tests.
- **W3 Active Reconnaissance:** Scope authorizers, Nmap collectors, XML parsers, and active pipelines verified via 27 unit/integration tests.
- **Zero Regressions Observed:** All previous milestone capabilities function identically.

---

## 19. Week 5 (W5) Readiness Assessment

The correlation engine and data models provide direct hooks for Week 5 (Vulnerability Assessment & Correlation):
- `AssetRelationship` supports extending relationship predicates to `SERVICE_HAS_VULNERABILITY` and `PORT_HAS_CVE`.
- `UnifiedAssetProfile` provides clean containers for correlated CVE IDs, CVSS severity ratings, and vulnerability descriptions.
- `ConfidenceEngine` provides an established framework for rating vulnerability detection confidence (e.g. banner-inferred vs. active probe confirmed).

**W5 READINESS STATUS:** **READY**

---
*End of Week 4 Implementation Report — OSINT-RECON.*

