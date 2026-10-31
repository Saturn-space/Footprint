# FootprintIQ V1 Repository Audit & Python Migration Blueprint

**Phase 1 Deliverable — Repository Audit, Baseline Verification & Target Architecture Blueprint**  
**Document Reference:** `DOCS-FIQ-P1-AUDIT-2026-10-27`  
**Target Application:** FootprintIQ — Digital Footprint Investigator  
**Auditor:** Senior Python Software Architect, Application Migration Engineer & Cybersecurity Systems Reviewer  
**Audit Timestamp:** October 27, 2026  

---

## 1. Executive Summary

### 1.1 Project Overview
FootprintIQ is an educational and authorized cybersecurity reconnaissance management platform designed for security analysts, researchers, and students. Its primary function is to collect, correlate, score, track, and report digital footprint intelligence concerning authorized organizational assets (demonstrated via the **NorthStar Analytics Lab** sandbox: apex domain `lab.example`, target host `192.168.56.102`, and network CIDR `192.168.56.0/24`).

The application enforces a strict operational distinction:
1. **Passive Reconnaissance:** Querying third-party public registries (RDAP/WHOIS), authoritative DNS, public search disclosures, and theHarvester OSINT dumps without transmitting probing packets directly to target boundaries.
2. **Active Reconnaissance:** Port and service detection (Nmap) and vulnerability assessment (Greenbone/OpenVAS). Active operations are strictly restricted by server-side policy and must be rejected unless the target is verified on an explicit, unexpired allowlist.

### 1.2 Purpose of This Audit
This audit establishes an exhaustive technical baseline of the existing FootprintIQ V1 implementation (React 19 + TypeScript + Express 4) and defines an actionable blueprint for a complete migration to a pure **Python 3 / FastAPI / SQLAlchemy / Jinja2 + HTMX** runtime, eliminating Node.js, Express, React, and client-side compilation while improving architectural integrity, audit compliance, and system security.

### 1.3 Key High-Level Audit Findings
1. **Hybrid Architecture with Local Persistence:** The application is structured as an Express 4 backend serving an API at `/api/v1` and hosting Vite middleware for React in development. Persistence is provided by a custom JSON-based storage engine (`src/server/db/database.ts`) backed by an atomic file store (`.data/footprintiq_db.json`). Client components in `src/context/InvestigationContext.tsx` also retain legacy fallback code using browser `localStorage` via `src/repositories/mockRepository.ts`.
2. **Active Scanning Execution is Simulated:** Neither Nmap nor OpenVAS/GVM nor theHarvester are ever executed as real operating system subprocesses. When the semi-autonomous workflow triggers active stages, `workerManager.executeSimulatedJob()` loads static XML templates (`src/data/sampleScanFiles.ts`) and performs string substitution of the target IP. Real active scanner execution must be implemented during Python migration.
3. **Passive Reconnaissance is Real with Fallback:** `passiveReconService.collectRDAP()` makes real HTTP requests to `https://rdap.org/domain/{domain}` with rate limiting (10 req/min) and in-memory caching. `collectDNS()` executes real DNS lookups via Node's `dns.promises` for A, AAAA, MX, NS, and TXT (SPF/DMARC) records. Both services contain deterministic fallback fixtures for the `lab.example` offline sandbox.
4. **Critical Authentication Bypass Vulnerabilities:** In `src/server/routes/api.ts` (lines 52–74), if the `Authorization` header is omitted, the API defaults to authenticating the request as the first `admin` user. Furthermore, supplying an email or user ID in the Bearer token immediately grants a session without password verification or cryptographic signature checking.
5. **Pseudo-Cryptographic Hashing:** `src/utils/hash.ts` implements a 32-bit string hashing algorithm that prepends the static string `sha256:f7a8c3d9` to simulate SHA-256 digests. This creates a false sense of cryptographic integrity for evidence hashes and audit ledger seals.
6. **Execution Prerequisite Blocker:** The repository currently lacks `node_modules`. Because the strict Phase 1 boundary prohibits running `npm install` or modifying dependencies, automated test suites could not be executed synchronously (yielding `BLOCKED` on startup and testing commands). However, static source inspection was 100% completed across all 32 source files.

---

## 2. Verified Current Architecture

### 2.1 Technology Stack Inventory

| Component | Current Implementation | Verified Files |
| :--- | :--- | :--- |
| **Runtime Environment** | Node.js (v22.20.0), TypeScript 7.0.2, TSX 4.21.0 | `package.json`, `server.ts` |
| **Web Server / Routing** | Express 4.21.2 | `server.ts`, `src/server/routes/api.ts` |
| **Frontend Framework** | React 19.0.1, React DOM 19.0.1, React Router DOM 7.18.4 | `src/App.tsx`, `src/main.tsx` |
| **Frontend Bundler** | Vite 8.3.0 with `@vitejs/plugin-react` | `vite.config.ts`, `server.ts` |
| **Styling** | TailwindCSS 4.3.3 | `src/index.css`, `package.json` |
| **UI Component Icons** | Lucide React 0.546.0 | `src/components/*`, `src/pages/*` |
| **Visualizations** | Recharts 3.10.1 & Custom SVG Graph | `src/pages/DashboardPage.tsx`, `src/components/graph/EntityGraph.tsx` |
| **Motion / Transitions** | Motion 12.23.24 | `package.json` |
| **Schema Validation** | Zod 4.6.5 | `src/types/schemas.ts` |
| **XML Parsing** | fast-xml-parser 5.11.2 | `src/server/services/parsers/*` |
| **Client PDF Generation** | jsPDF 4.2.1 | `src/server/services/reportGenerator.ts` |
| **Persistence Engine** | Atomic Disk-backed JSON Store (`.data/footprintiq_db.json`) | `src/server/db/database.ts` |
| **Client Offline Fallback** | Browser `localStorage` | `src/repositories/mockRepository.ts` |

### 2.2 Architectural Topology

```
+-----------------------------------------------------------------------------------+
|                              FootprintIQ Browser UI                              |
|   (React 19, Lucide Icons, Custom SVG Radial Graph, Recharts, LocalStorage Cache) |
+-----------------------------------------+-----------------------------------------+
                                          | HTTP / JSON (/api/v1/*)
                                          v
+-----------------------------------------------------------------------------------+
|                           Express 4.21.2 Server Runtime                          |
|                                (server.ts / api.ts)                               |
+--------------------+--------------------+--------------------+--------------------+
| RBAC Middleware    | Request Tracking   | Body Parser (10MB) | Vite Dev Proxy     |
+--------------------+--------------------+--------------------+--------------------+
          |                   |                   |
          v                   v                   v
+-----------------------------------------------------------------------------------+
|                                 Business Services                                 |
+--------------------+--------------------+--------------------+--------------------+
| scopeValidator.ts  | passiveRecon.ts    | normalizer.ts      | correlationEngine  |
| - IP/CIDR/FQDN     | - RDAP (HTTP fetch)| - Canonical format | - Graph Linker     |
| - Pre-exec check   | - DNS (promises)   | - Auto-entity link | - 5-Entity Types   |
+--------------------+--------------------+--------------------+--------------------+
| workerManager.ts   | workflowController | exposureScorer.ts  | reportGenerator.ts |
| - Job Control      | - 21-State Machine | - 5-Factor Score   | - 20 Sections      |
| - Simulated Daemon | - Approval Gates   | - Risk Tiering     | - jsPDF Binary     |
+--------------------+--------------------+--------------------+--------------------+
| parsers/nmapParser | parsers/openvas    | parsers/harvester  | scanProfiles.ts    |
| - fast-xml-parser  | - fast-xml-parser  | - JSON/XML Parser  | - Profile Presets  |
| - XXE Regex Filter | - CVE/CVSS mapper  | - Email/Host Regex | - Static Arguments |
+--------------------+--------------------+--------------------+--------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        Repository Layer (repositories.ts)                         |
|   (13 Repositories: users, investigations, targets, evidence, entities, etc.)     |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                   Atomic JSON Persistence Engine (database.ts)                    |
|             Storage: .data/footprintiq_db.json (Memory Cache + .tmp rename)       |
+-----------------------------------------------------------------------------------+
```

---

## 3. Complete Repository Inventory

The repository contains 44 files across 16 directories. Every component has been inspected and cataloged.

| File Path | Primary Responsibility | Key Functions / Classes / Interfaces | Dependencies | Status | Python Migration Replacement |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `server.ts` | Express server entry point, mounts API and Vite middleware | `startServer()` | `express`, `vite`, `apiRouter` | Implemented | `app/main.py` (FastAPI app with Uvicorn) |
| `package.json` | Dependency manifest and project scripts | Scripts: `dev`, `start`, `build`, `test`, `lint` | Node toolchain | Implemented | `pyproject.toml` or `requirements.txt` |
| `tsconfig.json` | TypeScript compiler configuration | Compiler options, module resolution | TS toolchain | Implemented | Python type hints (`mypy.ini` / PEP 484) |
| `vite.config.ts` | Vite frontend build configuration | Plugins: `@vitejs/plugin-react`, `@tailwindcss/vite` | Vite | Implemented | Not required (Jinja2 + HTMX) |
| `.env.example` | Template for environment variables | `PORT`, `NODE_ENV`, `APP_URL`, `GEMINI_API_KEY` | None | Implemented | `.env.example` (Python settings via Pydantic) |
| `README.md` | Phase 2 architecture documentation | Team attestation, endpoint matrix, RBAC definitions | None | Implemented | Updated project documentation |
| `metadata.json` | AI Studio deployment metadata | Metadata descriptors | None | Implemented | Metadata configuration |
| `.data/footprintiq_db.json` | Disk-persisted atomic JSON database | 13 Collections (users, investigations, findings, etc.) | `database.ts` | Implemented | SQLite database (`footprintiq.db`) / PostgreSQL |
| `src/server/db/database.ts` | In-memory JSON database engine with atomic disk flush | `ServerDatabase`, `serverDb`, `DatabaseSchema` | `fs`, `path`, `seedData.ts` | Implemented | SQLAlchemy 2.0 Engine & Sessionmaker |
| `src/server/db/repositories.ts` | 13 Server-side data repositories | `UserRepository`, `InvestigationRepository`, `FindingRepository`, etc. | `database.ts`, `models.ts` | Implemented | SQLAlchemy Repository classes |
| `src/server/routes/api.ts` | Versioned REST API routing with RBAC guards | `apiRouter`, `getAuthUser()`, `requireRole()`, 26 REST handlers | Express, all server services | Implemented | FastAPI routers (`app/api/v1/*.py`) |
| `src/server/services/scopeValidator.ts` | IP, CIDR, domain syntax validation and allowlist enforcement | `ScopeValidatorService`, `isValidIPv4()`, `isIpInCidr()` | `dns`, `serverRepos` | Implemented | `app/services/scope_validator.py` (`ipaddress`, `dnspython`) |
| `src/server/services/passiveRecon.ts` | Safe RDAP RFC 7480 client and DNS resolver with fallback | `PassiveReconService`, `collectRDAP()`, `collectDNS()` | `dns`, global `fetch` | Implemented | `app/services/passive_recon.py` (`httpx`, `dnspython`) |
| `src/server/services/normalizer.ts` | Canonical formatting, entity extraction, and graph linking | `EvidenceNormalizerService`, `correlateEvidence()` | `serverRepos`, `hash.ts` | Implemented | `app/services/normalizer.py` |
| `src/server/services/correlationEngine.ts` | Multi-source graph correlation (Org, Domain, IP, Port, Finding) | `CorrelationEngineService`, `correlateInvestigation()` | `serverRepos` | Implemented | `app/services/correlation_engine.py` |
| `src/server/services/exposureScorer.ts` | 5-factor exposure formula calculation ($0.20P + 0.15D + 0.25S + 0.35V + 0.05C$) | `ExposureScorerService`, `calculateScore()` | `models.ts`, `workflow.ts` | Implemented | `app/services/exposure_scorer.py` |
| `src/server/services/scanProfiles.ts` | Predefined scan argument profiles for Nmap and OpenVAS | `APPROVED_SCAN_PROFILES`, `getScanProfile()` | `workflow.ts` | Implemented | `app/services/scan_profiles.py` |
| `src/server/services/workerManager.ts` | Control plane for registration, token issuance, and simulated job execution | `WorkerManagerService`, `createJob()`, `submitResult()` | `sampleScanFiles.ts`, `hash.ts` | Implemented (Simulated) | `app/services/worker_manager.py` (Real async subprocess) |
| `src/server/services/workflowController.ts` | 21-state semi-autonomous investigation lifecycle state machine | `WorkflowControllerService`, `startWorkflow()`, `runSafeDemo()` | All services | Implemented | `app/services/workflow_controller.py` |
| `src/server/services/reportGenerator.ts` | 20-section report generation, jsPDF compiler, CSV and GraphML export | `ReportGeneratorService`, `buildBinaryPdf()`, `exportGraphML()` | `jspdf`, `serverRepos` | Implemented | `app/services/report_generator.py` (ReportLab) |
| `src/server/services/parsers/nmapParser.ts` | Fast XML parser for Nmap output with XXE check | `parseNmapXml()`, `ParsedNmapResult` | `fast-xml-parser` | Implemented | `app/parsers/nmap_parser.py` (`defusedxml`) |
| `src/server/services/parsers/openvasParser.ts` | XML parser for OpenVAS/GVM reports with CVE/CVSS extraction | `parseOpenVASXml()`, `mapOpenVASSeverity()` | `fast-xml-parser` | Implemented | `app/parsers/openvas_parser.py` (`defusedxml`) |
| `src/server/services/parsers/harvesterParser.ts` | JSON and XML parser for theHarvester dumps | `parseHarvesterExport()`, `ParsedHarvesterData` | `fast-xml-parser` | Implemented | `app/parsers/harvester_parser.py` |
| `src/server/tests/runAllTests.ts` | 34 automated unit and integration tests | `runTests()`, `assert()` | Custom test runner | Implemented | `tests/test_*.py` (Pytest suite) |
| `src/server/tests/runDemoE2ETest.ts` | End-to-end integration test of automated demo workflow | `runDemoE2ETest()` | `workflowController` | Implemented | `tests/test_e2e_workflow.py` |
| `src/types/models.ts` | Core data contracts and TypeScript interfaces | `Investigation`, `Evidence`, `Finding`, `Entity`, etc. | None | Implemented | `app/models/` (SQLAlchemy & Pydantic) |
| `src/types/schemas.ts` | Zod validation schemas for forms and API requests | `InvestigationFormSchema`, `ScopeSchema` | `zod` | Implemented | Pydantic v2 schemas (`app/schemas/`) |
| `src/types/workflow.ts` | Workflow states, scan profile definitions, worker types | `WorkflowState`, `WorkflowRun`, `WorkerJob` | None | Implemented | `app/schemas/workflow.py` |
| `src/utils/formatters.ts` | String, date, and badge formatting helpers | `formatDate()`, `getSeverityColor()` | None | Implemented | Jinja2 filters in `app/templates/filters.py` |
| `src/utils/hash.ts` | String hashing for audit and evidence verification | `generateEvidenceHash()`, `generateAuditHash()` | None | Implemented (Flawed) | `hashlib.sha256()` in `app/core/security.py` |
| `src/utils/scoring.ts` | Legacy 4-component exposure score calculator | `calculateExposureScore()` | `models.ts` | Implemented | Consolidated into `app/services/exposure_scorer.py` |
| `src/data/seedData.ts` | Baseline demo data for NorthStar Analytics Lab | `INITIAL_INVESTIGATION`, `DEMO_USERS`, etc. | `models.ts` | Implemented | `app/db/seed.py` |
| `src/data/sampleScanFiles.ts` | Realistic Nmap and OpenVAS XML fixture strings | `SAMPLE_NMAP_XML`, `SAMPLE_OPENVAS_XML` | None | Implemented | Test fixtures in `tests/fixtures/` |
| `src/repositories/interfaces.ts` | Clean architecture repository interfaces (Client-side) | `IInvestigationRepository`, etc. | `models.ts` | Legacy / Redundant | Abstract Base Classes (`app/repositories/base.py`) |
| `src/repositories/mockRepository.ts` | LocalStorage repository implementation for client fallback | `MockInvestigationRepository`, etc. | `localStorage` | Legacy / Redundant | Eliminated (FastAPI backend authoritative) |
| `src/context/AuthContext.tsx` | React authentication context and demo role switcher | `AuthProvider`, `useAuth()` | React, `localStorage` | Implemented (Client) | FastAPI session cookie + HTMX auth headers |
| `src/context/InvestigationContext.tsx` | React data store managing active investigation and API calls | `InvestigationProvider`, `useInvestigation()` | React, `mockRepository` | Implemented (Client) | HTMX partials & Jinja2 server rendering |
| `src/pages/DashboardPage.tsx` | Executive metrics, stats, recent findings, and workflow status | Component `DashboardPage` | React, Recharts | Implemented (Client) | `templates/pages/dashboard.html` |
| `src/pages/ActiveScanningPage.tsx` | Workflow progress, worker daemon panel, XML upload forms | Component `ActiveScanningPage` | React, Lucide | Implemented (Client) | `templates/pages/active_scanning.html` |
| `src/pages/PassiveReconPage.tsx` | RDAP query, DNS resolution, theHarvester import, manual logger | Component `PassiveReconPage` | React, Lucide | Implemented (Client) | `templates/pages/passive_recon.html` |
| `src/pages/EntityGraphPage.tsx` | Knowledge graph visualization container | Component `EntityGraphPage` | React, `EntityGraph` | Implemented (Client) | `templates/pages/entity_graph.html` (Cytoscape/D3) |
| `src/pages/FindingsPage.tsx` | Vulnerability findings matrix with severity triage | Component `FindingsPage` | React, Lucide | Implemented (Client) | `templates/pages/findings.html` |
| `src/pages/ExposureScorePage.tsx` | 5-factor exposure breakdown, charts, and reviewer adjustments | Component `ExposureScorePage` | React, Recharts | Implemented (Client) | `templates/pages/exposure_score.html` |
| `src/pages/ReportsPage.tsx` | 20-section report generation, preview modal, PDF/CSV download | Component `ReportsPage` | React, Lucide | Implemented (Client) | `templates/pages/reports.html` |
| `src/pages/AuditLogPage.tsx` | Cryptographic audit trail viewer and JSON ledger export | Component `AuditLogPage` | React, Lucide | Implemented (Client) | `templates/pages/audit_log.html` |
| `src/pages/InvestigationsPage.tsx` | Investigation directory list, active switcher, deletion | Component `InvestigationsPage` | React, Lucide | Implemented (Client) | `templates/pages/investigations.html` |
| `src/pages/NewInvestigationPage.tsx` | 4-step wizard container for creating new investigations | Component `NewInvestigationPage` | React | Implemented (Client) | `templates/pages/new_investigation.html` |
| `src/pages/HelpEthicsPage.tsx` | Rules of engagement, ethical guidelines, and legal notice | Component `HelpEthicsPage` | React | Implemented (Client) | `templates/pages/help_ethics.html` |
| `src/pages/SettingsPage.tsx` | Team credentials, retention policy, local storage reset | Component `SettingsPage` | React | Implemented (Client) | `templates/pages/settings.html` |
| `src/components/graph/EntityGraph.tsx` | Custom interactive SVG radial graph with drag/zoom/drawer | Component `EntityGraph` | React, SVG | Implemented (Client) | Server-rendered SVG or lightweight Cytoscape.js |
| `src/components/wizard/NewInvestigationWizard.tsx`| 4-step investigation creation wizard with scope and RoE validation | Component `NewInvestigationWizard` | React, Zod | Implemented (Client) | Multi-step HTMX wizard form |

---

## 4. Baseline Test and Startup Results

The repository package manifests and source scripts were inspected to evaluate execution commands. Commands were executed directly on the host system to determine operational status.

### 4.1 Command Execution Evaluation

| Target Command | Script / Invocation | Prerequisite Status | Result | Details / Error Logs |
| :--- | :--- | :--- | :--- | :--- |
| **Node Version Check** | `node --version` | Available on system | **PASS** | `v22.20.0` detected. |
| **NPM Version Check** | `npm --version` | Available on system | **PASS** | `10.9.3` detected. |
| **Python Version Check** | `python --version` | Available on system | **PASS** | `Python 3.11.9` detected. |
| **Bun Version Check** | `bun --version` | Not in system PATH | **BLOCKED** | `bun: The term 'bun' is not recognized as a cmdlet, function, or script.` |
| **Development Startup** | `npm run dev` (`tsx server.ts`) | Missing `node_modules` | **BLOCKED** | `node_modules` does not exist; running `npm install` is strictly prohibited by Phase 1 boundary rules. |
| **Production Build** | `npm run build` (`vite build`) | Missing `node_modules` | **BLOCKED** | `vite` executable not available in environment without installation. |
| **Type Check / Linting** | `npm run lint` (`tsc --noEmit`) | Missing `node_modules` | **BLOCKED** | `tsc` compiler binary missing from local project directory. |
| **Unit / Integration Tests** | `npm test` (`tsx src/server/tests/runAllTests.ts`) | Executed via shell | **FAIL** | Exit code 1: `'tsx' is not recognized as an internal or external command, operable program or batch file.` |
| **E2E Demo Test** | `npx tsx src/server/tests/runDemoE2ETest.ts` | Node environment | **NOT RUN** | Not executed to prevent downloading unapproved packages into the user workspace. |
| **Database Initialization** | Automatic via `ServerDatabase` constructor | In-memory + disk file | **PASS (Static)**| Verified statically in `src/server/db/database.ts`: boots from `DEMO_USERS` and seed data if `.data/footprintiq_db.json` is missing. |
| **Database Migration** | No schema migration tool exists | No SQL database | **NOT RUN** | The current V1 application has no migration engine (Alembic or Prisma); data is unstructured JSON. |

### 4.2 Test Suite Static Coverage Verification
Although dynamic test execution was blocked by the missing Node environment, line-by-line inspection of `src/server/tests/runAllTests.ts` confirmed that the existing test suite was written to assert:
- IPv4, IPv6, FQDN, and CIDR subnet containment (`isValidIPv4`, `isValidCIDR`, `isIpInCidr`).
- Active allowlist boundary enforcement and authorization expiration halting.
- XXE entity injection blocking in Nmap and OpenVAS XML parsers.
- Port and CVE extraction from sample files.
- theHarvester email and subdomain parsing.
- String normalization (`normalizeDomain`, `normalizeIP`, `normalizeEmail`).
- 4-role user configuration.
- Semi-autonomous workflow controller transitions (`CREATED` through `COMPLETED`).
- Worker registration, heartbeat, job authorization token, and target mismatch rejection.
- Multi-factor correlation and 5-factor exposure score calculation.
- 20-section report generation and binary PDF building via jsPDF.

---

## 5. Feature-Parity Matrix

Every user-visible feature and backend capability identified in the V1 codebase is mapped to its proposed Python replacement.

| Feature | Existing Implementation | Supporting Evidence | Current Status | Dependencies | User Workflow | Proposed Python Replacement | Migration Risks | Verification Requirement |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **User Authentication & Role Management** | `AuthContext.tsx`, `api.ts:48-97` | `apiRouter.post('/auth/login')`, `requireRole()` | Partially Implemented (Security Flaws) | Server memory session | Header dropdown switches demo profile | FastAPI OAuth2 password bearer / secure signed session cookies, PBKDF2 password hashing | Breaking instant demo role switching if session tokens require persistent credentials | Test all 4 roles (Admin, Investigator, Reviewer, Viewer) against protected endpoints |
| **Investigation Creation & Tracking** | `NewInvestigationWizard.tsx`, `api.ts:163-254` | `InvestigationRepository.create()`, `InvestigationFormSchema` | Implemented | Database repository, Zod | "New Investigation" navigation link -> 4-step wizard | FastAPI router `app/api/v1/investigations.py`, SQLAlchemy `InvestigationModel` | Form schema mismatch during multi-step submission | Submit valid/invalid investigation payloads via HTMX and assert DB persistence |
| **Target & Scope Validation** | `scopeValidator.ts`, `api.ts:259-272` | `ScopeValidatorService.validateTarget()` | Implemented | Node `dns.promises` | Triggered when targets are added or active scans imported | Python `ipaddress` module and `dnspython` in `app/services/scope_validator.py` | Behavior difference between Node DNS and dnspython on timeout | Unit test IPv4, IPv6, CIDR matching, and DNS re-resolution |
| **RDAP / WHOIS Collection** | `passiveRecon.ts:40-116`, `api.ts:278-340` | `passiveReconService.collectRDAP()` | Implemented (Live with Mock Fallback) | Public `rdap.org` API | "Passive Recon" page -> RDAP tab -> "Query RDAP/WHOIS" button | `httpx.AsyncClient` querying `rdap.org` with token bucket limiter | Upstream rate limiting or blocking of public RDAP gateways | Mocked and live query tests against `lab.example` and real domains |
| **Authoritative DNS Reconnaissance** | `passiveRecon.ts:118-295`, `api.ts:342-401` | `passiveReconService.collectDNS()` | Implemented (Live with Mock Fallback) | Node `dns.promises` | "Passive Recon" page -> DNS tab -> "Resolve DNS Records" button | `dnspython` (`dns.resolver.Resolver`) querying A, AAAA, MX, NS, TXT | System DNS differences across OS platforms | Resolve records for dummy domain and assert SPF/DMARC audit analysis |
| **theHarvester Ingestion** | `harvesterParser.ts`, `api.ts:465-530` | `parseHarvesterExport()` | Import-Only | `fast-xml-parser` | "Passive Recon" page -> theHarvester tab -> paste JSON/XML payload | Pydantic model + `defusedxml` parser in `app/parsers/harvester_parser.py` | Nested JSON format variances across theHarvester versions | Test parsing of both JSON and XML exports with malicious entities |
| **Real theHarvester Execution** | Missing in V1 | None | Missing | Python subprocess / external executable | None (Must be added to active/passive toolbar) | Async subprocess executor `asyncio.create_subprocess_exec('theHarvester', ...)` | theHarvester not installed on host machine or blocked by search engines | Execution wrapper with graceful fallback if theHarvester executable is absent |
| **Nmap Ingestion & Allowlist Enforcement** | `nmapParser.ts`, `api.ts:531-635` | `parseNmapXml()`, scope check in `api.ts:552-571` | Import-Only | `fast-xml-parser`, `scopeValidator` | "Active Scanning" page -> Manual Ingest -> paste XML or load sample | `defusedxml` parser in `app/parsers/nmap_parser.py` + scope check | Malformed XML or oversized scans (DoS) | Ingest valid XML and verify allowlist blocks out-of-scope hosts |
| **Real Nmap Execution** | Simulated in `workerManager.ts:240-269` | `executeSimulatedJob()` string-replaces IP in fixture | Simulated | External Nmap executable | "Active Scanning" page -> "Run Safe Demo" or Worker Panel | Safe subprocess executor `asyncio.create_subprocess_exec('nmap', *fixed_args, target)` | Nmap requiring root/admin privileges for raw SYN packets; target command injection | Run Nmap against allowlisted target using unprivileged TCP handshake (`-sT`) |
| **OpenVAS / Greenbone Ingestion** | `openvasParser.ts`, `api.ts:637-743` | `parseOpenVASXml()` | Import-Only | `fast-xml-parser` | "Active Scanning" page -> Manual Ingest -> paste OpenVAS XML | `defusedxml` parser in `app/parsers/openvas_parser.py` | Schema variations between GVM versions | Parse OpenVAS 22.4 XML and verify CVE extraction |
| **Real OpenVAS Integration** | Simulated in `workerManager.ts:240-269` | `executeSimulatedJob()` string-replaces IP in fixture | Simulated | Greenbone GMP API daemon | "Active Scanning" page -> Worker Manager -> Run Job | `python-gvm` library connecting to Greenbone GMP daemon via Unix/TLS socket | Complexity of local OpenVAS/GVM setup in developer environments | Provide dual-mode: real GMP socket connector with simulated worker fallback |
| **Evidence Normalization & Deduplication** | `normalizer.ts`, `repositories.ts:159-163` | `evidenceNormalizer.correlateEvidence()`, `findDuplicate()` | Implemented | `hash.ts` | Triggered automatically on all data ingestion endpoints | `app/services/normalizer.py` with SQLAlchemy composite unique constraints | Duplicate detection logic differs between hash and values | Ingest identical evidence twice; assert single deduplicated record |
| **Entity Correlation & Graph Visualization** | `correlationEngine.ts`, `EntityGraph.tsx` | `correlationEngine.correlateInvestigation()` | Implemented | Custom SVG / React state | Navigation -> "Entity Graph" -> filter toggles & node details | Server correlation in `app/services/correlation_engine.py` + Cytoscape.js or server SVG | SVG performance degradation on graphs with >500 nodes | Execute correlation engine; verify 5 entity types and relationships in graph |
| **5-Factor Exposure Scoring** | `exposureScorer.ts`, `ExposureScorePage.tsx` | `exposureScorer.calculateScore()`, $0.20P+0.15D+0.25S+0.35V+0.05C$ | Implemented | `serverRepos` | Navigation -> "Exposure Score" -> "Recalculate Score" | `app/services/exposure_scorer.py` | Rounding or weighting discrepancies between TypeScript and Python | Assert score matches existing TypeScript benchmark (e.g., 68/100 Elevated) |
| **Comprehensive 20-Section Reporting** | `reportGenerator.ts:19-190`, `ReportsPage.tsx` | `generateComprehensiveReport()` | Implemented | Database repository | Navigation -> "Reports" -> "Compile 20-Section Dossier" | `app/services/report_generator.py` compiling structured Report model | Ensuring all 20 sections contain live investigation data rather than boilerplate | Generate report and verify all 20 numbered sections match schema |
| **Binary PDF Export** | `reportGenerator.ts:195-262`, `api.ts:1154-1175`| `reportGenerator.buildBinaryPdf()`, jsPDF | Implemented (Client/Server jsPDF) | `jspdf` | Reports page -> Click "PDF" download button | Python `reportlab.platypus` (SimpleDocTemplate, Paragraph, Table) | Flowable text wrapping and pagination matching jsPDF output | Generate PDF via `/reports/{id}/pdf` and inspect page layout |
| **GraphML & CSV Exports** | `reportGenerator.ts:265-347`, `api.ts:1218-1244`| `exportGraphML()`, `exportFindingsCSV()`, etc. | Implemented | `serverRepos` | Reports page -> Export bundle / CSV / GraphML buttons | Native Python `csv` writer and `xml.etree.ElementTree` in FastAPI endpoints | XML escaping in Maltego GraphML nodes | Export GraphML and validate against GraphML XML schema |
| **Tamper-Evident Audit Logging** | `repositories.ts:314-331`, `AuditLogPage.tsx` | `AuditRepository.logEvent()`, `generateAuditHash()` | Implemented (Flawed Hashing) | `hash.ts` | Navigation -> "Audit Log" -> Search & category filters | SQLAlchemy `AuditEventModel` + real SHA-256 HMAC chaining in `app/core/security.py` | Hash migration for existing audit records | Create audit events and verify SHA-256 digest continuity |
| **Semi-Autonomous Workflow Controller** | `workflowController.ts`, `WorkerManagerPanel.tsx` | `WorkflowControllerService.startWorkflow()`, 21 states | Implemented | `workerManager`, all services | Active Scanning -> "Start Automated Workflow" or "Run Safe Demo" | `app/services/workflow_controller.py` with FastAPI background tasks | Handling asynchronous state transitions over HTTP | Run end-to-end workflow from `CREATED` to `COMPLETED` |

---

## 6. Real Versus Simulated Functionality

A critical requirement of this audit is to rigorously distinguish working production logic from simulation, mock fixtures, and import-only capabilities.

```
+-----------------------------------------------------------------------------------------+
|                               FUNCTIONALITY CLASSIFICATION                              |
+------------------------------+------------------------------+---------------------------+
| REAL                         | IMPORT-ONLY / CLIENT-GATED   | SIMULATED                 |
| - RDAP live queries          | - Nmap XML ingestion         | - Nmap worker execution   |
| - DNS recursive resolution   | - OpenVAS XML ingestion      | - OpenVAS worker execution|
| - Scope syntax & subnetting  | - theHarvester ingestion     | - Demo account login      |
| - Exposure score calculation | - Target allowlist check     | - SHA-256 evidence hash   |
| - ReportLab / jsPDF dossiers | - Client role switcher       | - Lab.example fallbacks   |
| - JSON database persistence  |                              |                           |
+------------------------------+------------------------------+---------------------------+
```

### 6.1 Audit Investigation Findings

#### 1. Worker Manager Execution
- **Classification:** **SIMULATED**
- **Evidence:** `src/server/services/workerManager.ts` (lines 240–269).
- **Finding:** The method `executeSimulatedJob(jobId: string)` does not spawn external processes. It selects either `SAMPLE_NMAP_XML` or `SAMPLE_OPENVAS_XML` from `src/data/sampleScanFiles.ts` and performs a regex replacement (`fixture.replace(/192\.168\.56\.102/g, job.target)`).

#### 2. Nmap Port and Service Scanning
- **Classification:** **IMPORT-ONLY** (Live Execution: **SIMULATED**)
- **Evidence:** `src/server/routes/api.ts` (lines 531–635) and `src/server/services/parsers/nmapParser.ts`.
- **Finding:** The endpoint `/api/v1/investigations/:id/import/nmap` is real: it validates the XML size, checks for XXE injection, validates every discovered host IP against the active allowlist, and populates the `services` repository. However, Nmap is never invoked as a CLI executable by the server.

#### 3. Greenbone / OpenVAS Vulnerability Assessment
- **Classification:** **IMPORT-ONLY** (Live Execution: **SIMULATED**)
- **Evidence:** `src/server/routes/api.ts` (lines 637–743) and `src/server/services/parsers/openvasParser.ts`.
- **Finding:** The endpoint `/api/v1/investigations/:id/import/openvas` correctly parses valid OpenVAS/GVM reports, maps CVSS scores to standardized severities, checks targets against allowlists, and extracts CVE references. However, there is no real socket connection or API integration with the Greenbone Management Protocol (GMP).

#### 4. theHarvester OSINT Collection
- **Classification:** **IMPORT-ONLY**
- **Evidence:** `src/server/services/parsers/harvesterParser.ts` and `src/server/routes/api.ts` (lines 465–530).
- **Finding:** The system parses uploaded JSON and XML outputs from theHarvester, extracting emails, hosts, IPs, and URLs, and correlates them into the graph. The tool itself is never launched by the application.

#### 5. RDAP and DNS Collectors
- **Classification:** **REAL** (with sandbox fallback)
- **Evidence:** `src/server/services/passiveRecon.ts` (lines 40–116 and lines 118–295).
- **Finding:** `collectRDAP()` issues live HTTP `fetch` calls to `https://rdap.org/domain/{domain}` with an `AbortController` (4-second timeout), a token-bucket rate limiter, and an in-memory cache. `collectDNS()` issues live Node `dns.promises` queries for A, AAAA, MX, NS, and TXT records. Both methods include hardcoded fallbacks if queries fail or when querying the private dummy apex `lab.example`.

#### 6. Provenance of Findings and Evidence
- **Classification:** **PARTIAL**
- **Evidence:** `src/data/seedData.ts` (lines 142–179), `api.ts:304-322`, `api.ts:577-613`.
- **Finding:** The seed baseline includes pre-populated findings (e.g., CVE-2023-38606 Jenkins disclosure, CVE-2011-3389 TLS 1.0). When users upload real Nmap or OpenVAS scans, new findings are parsed and dynamically added to the repository.

#### 7. Exposure Score Calculation
- **Classification:** **REAL**
- **Evidence:** `src/server/services/exposureScorer.ts` (lines 26–154).
- **Finding:** The exposure score is dynamically computed from live repository contents using the verified 5-factor formula ($0.20P + 0.15D + 0.25S + 0.35V + 0.05C$). It is not hardcoded.

#### 8. Dossier and Report Generation
- **Classification:** **REAL**
- **Evidence:** `src/server/services/reportGenerator.ts` (lines 19–262).
- **Finding:** `generateComprehensiveReport()` queries the current database state (entities, services, findings, evidence, audit logs) and dynamically constructs all 20 dossier sections, generating real PDF bytes and Maltego GraphML XML.

#### 9. Authentication and Authorization Enforcement
- **Classification:** **SIMULATED** (Server) / **PARTIAL** (Client)
- **Evidence:** `src/server/routes/api.ts` (lines 52–74), `src/context/AuthContext.tsx`.
- **Finding:** The UI disables buttons based on `hasRole()`. However, the server-side middleware `getAuthUser()` contains a critical backdoor: if no `Authorization` header is present, it returns the Admin user. Supplying any email in the Bearer token bypasses password authentication completely.

#### 10. Persistence of Records and Audit Events
- **Classification:** **REAL**
- **Evidence:** `src/server/db/database.ts` (lines 51–169), `.data/footprintiq_db.json`.
- **Finding:** All creations, updates, deletions, and audit events are synchronously committed to memory and flushed to disk at `.data/footprintiq_db.json` using atomic temporary file renaming.

---

## 7. Security Audit & Prioritized Findings

A comprehensive security review of the source code identified critical, high, medium, and low risks across authentication, scope enforcement, command execution, and evidence storage.

```
+-----------------------------------------------------------------------------------------+
|                                SECURITY RISK SEVERITY MATRIX                            |
+-------------------+---------------------------------------------------------------------+
| CRITICAL (1)      | SEC-01: Default-Admin Backdoor on Missing Authorization Header      |
+-------------------+---------------------------------------------------------------------+
| HIGH (3)          | SEC-02: Passwordless Bearer Token Impersonation                     |
|                   | SEC-03: Pseudo-Cryptographic Evidence Hashing & Audit Tampering     |
|                   | SEC-04: Race Conditions in Atomic JSON Persistence Engine           |
+-------------------+---------------------------------------------------------------------+
| MEDIUM (3)        | SEC-05: Denial of Service via 10MB Unbounded Ingestion Payloads     |
|                   | SEC-06: Potential Active Scope Expansion via DNS Re-resolution      |
|                   | SEC-07: Client-Side Only Enforcement of Demonstration Settings      |
+-------------------+---------------------------------------------------------------------+
| LOW (2)           | SEC-08: Regex-Based XXE Detection Fragility                         |
|                   | SEC-09: Unsanitized File Attachment Headers in Content-Disposition  |
+-------------------+---------------------------------------------------------------------+
```

### 7.1 Detailed Vulnerability Findings

#### [CRITICAL] SEC-01: Default-Admin Backdoor on Missing Authorization Header
- **Location:** `src/server/routes/api.ts`, lines 52–58.
- **Evidence:**
  ```typescript
  export async function getAuthUser(req: Request): Promise<User | null> {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      // Default to admin user for dev requests if no header provided
      const users = await serverRepos.users.getAll();
      return users.find(u => u.role === 'admin') || users[0] || null;
    }
  ```
- **Impact:** Any unauthenticated HTTP request sent to `/api/v1/investigations` (including DELETE, PATCH, and worker revocation) is automatically executed with **Admin** privileges.
- **Remediation:** In FastAPI, inject a strict `Depends(get_current_user)` dependency that raises `HTTPException(status_code=401)` if a valid JWT or signed session cookie is missing.
- **Remediation Target:** **Phase 2 (Immediate).**

#### [HIGH] SEC-02: Passwordless Bearer Token Impersonation
- **Location:** `src/server/routes/api.ts`, lines 65–72.
- **Evidence:**
  ```typescript
  const users = await serverRepos.users.getAll();
  const matched = users.find(u => u.id === token || u.email.toLowerCase() === token.toLowerCase());
  if (matched) {
    sessions.set(token, matched);
    return matched;
  }
  ```
- **Impact:** An attacker can forge an authorization header as `Authorization: Bearer admin@footprintiq.lab` and gain full admin access without providing any secret or password.
- **Remediation:** Implement standard OAuth2 password flow with `passlib` (PBKDF2/bcrypt) password verification and signed HMAC-SHA256 JWT tokens with expiry timestamps.
- **Remediation Target:** **Phase 2.**

#### [HIGH] SEC-03: Pseudo-Cryptographic Evidence Hashing & Audit Tampering
- **Location:** `src/utils/hash.ts`, lines 4–14.
- **Evidence:**
  ```typescript
  export function generateEvidenceHash(input: string): string {
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
      const char = input.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    const hex = Math.abs(hash).toString(16).padStart(8, '0');
    const salt = 'sha256:f7a8c3d9';
    return `${salt}${hex}${(input.length * 48271).toString(16).slice(0, 6)}`;
  }
  ```
- **Impact:** The hash is a trivial 32-bit polynomial hash prefixed with a static string. It offers zero cryptographic collision resistance or tamper evidence for legal chain-of-custody documentation.
- **Remediation:** Replace with standard Python `hashlib.sha256(data.encode('utf-8')).hexdigest()`. For audit log sealing, implement cryptographic HMAC chaining where each log entry includes `sha256(prev_hash + entry_data)`.
- **Remediation Target:** **Phase 2.**

#### [HIGH] SEC-04: Race Conditions in Atomic JSON Persistence Engine
- **Location:** `src/server/db/database.ts`, lines 153–164.
- **Evidence:**
  ```typescript
  public saveToDisk(): void {
    const tmpFile = `${DB_FILE}.tmp`;
    fs.writeFileSync(tmpFile, JSON.stringify(this.data, null, 2), 'utf-8');
    fs.renameSync(tmpFile, DB_FILE);
  }
  ```
- **Impact:** Under concurrent write requests, synchronous rewrites of the entire database JSON file to a static `.tmp` path cause race conditions, lock errors on Windows, or complete database corruption.
- **Remediation:** Migrate to a transactional ACID relational database using SQLAlchemy with SQLite (with WAL mode enabled) or PostgreSQL.
- **Remediation Target:** **Phase 2.**

#### [MEDIUM] SEC-05: Denial of Service via 10MB Unbounded Ingestion Payloads
- **Location:** `server.ts` (lines 15–16), `parsers/nmapParser.ts` (lines 40–42).
- **Evidence:** Express accepts 10MB JSON bodies. Both Nmap and OpenVAS parsers convert entire 5MB XML strings into in-memory DOM representations synchronously on the main thread, blocking the event loop.
- **Impact:** Processing concurrent large XML uploads freezes the server, causing request timeouts.
- **Remediation:** In Python, stream large file uploads directly to temporary disk storage and parse iteratively using `defusedxml.ElementTree.iterparse()`.
- **Remediation Target:** **Phase 3.**

#### [MEDIUM] SEC-06: Potential Active Scope Expansion via DNS Re-resolution
- **Location:** `src/server/services/scopeValidator.ts`, lines 114–141.
- **Evidence:** When an active scan is requested for a domain target, the server dynamically resolves the domain using `dns.promises.resolve4()`. If any resolved IP matches the allowlist, the operation is permitted.
- **Impact:** If an attacker alters external DNS records during an engagement (DNS rebinding), out-of-scope hosts could be approved or target validation could be bypassed.
- **Remediation:** Target validation must bind to specific static IP addresses, and DNS resolutions must be frozen at investigation approval time. Target IPs must be re-validated immediately before subprocess execution.
- **Remediation Target:** **Phase 3.**

#### [MEDIUM] SEC-07: Client-Side Only Enforcement of Demonstration Settings
- **Location:** `src/pages/SettingsPage.tsx`, lines 78–91.
- **Evidence:** The "Strict Active Allowlist Enforcement" and "Anonymize Redacted Target Identifiers" checkboxes exist only in React component state and are never transmitted to or persisted by the server.
- **Impact:** Security controls selected by users in the settings interface are ignored by the backend API.
- **Remediation:** Implement server-persisted system configuration models in SQLAlchemy with API endpoints to manage platform guardrails.
- **Remediation Target:** **Phase 2.**

#### [LOW] SEC-08: Regex-Based XXE Detection Fragility
- **Location:** `src/server/services/parsers/nmapParser.ts`, lines 45–47.
- **Evidence:**
  ```typescript
  if (/<!ENTITY/i.test(xmlContent) || /SYSTEM\s+["'][^"']+["']/i.test(xmlContent))
  ```
- **Impact:** Regex filtering can be bypassed via character encoding tricks (UTF-16, parameter entities). Fortunately, `fast-xml-parser` is configured with `processEntities: false`, which provides real protection.
- **Remediation:** In Python, use `defusedxml`, which hardens the underlying parser against all entity expansions, DTD bombs, and external entity retrievals.
- **Remediation Target:** **Phase 2.**

#### [LOW] SEC-09: Unsanitized File Attachment Headers in Content-Disposition
- **Location:** `src/server/routes/api.ts`, lines 1167–1170.
- **Evidence:**
  ```typescript
  const filename = `${report.title.replace(/[^a-zA-Z0-9_-]/g, '_').toLowerCase()}.pdf`;
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  ```
- **Impact:** While alphanumeric sanitization is performed, non-ASCII Unicode characters or CRLF headers could cause HTTP header injection in legacy clients.
- **Remediation:** Use RFC 6266 compliant header formatting via `starlette.responses.FileResponse` or `quote()` from `urllib.parse`.
- **Remediation Target:** **Phase 2.**

---

## 8. Python Target Architecture

The target Python architecture replaces Node.js, Express, and React with a robust, asynchronous Python stack centered around **FastAPI**, **SQLAlchemy**, and **Jinja2 + HTMX**.

```
+-----------------------------------------------------------------------------------+
|                        Client Browser (HTML5 / Vanilla CSS)                       |
|   - HTMX (AJAX swaps, polling, server-sent events)                                |
|   - Cytoscape.js or lightweight SVG for Entity Graph rendering                   |
|   - Zero JavaScript build step / No Node.js runtime                               |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                            FastAPI Application Gateway                            |
|   - Uvicorn ASGI Server                                                           |
|   - OAuth2 / Secure Session Cookie Middleware                                     |
|   - Request ID & Security Headers Middleware                                      |
+-----------------------------------------------------------------------------------+
          |                                                 |
          v                                                 v
+----------------------------------+    +-------------------------------------------+
|    HTML Views (Jinja2 + HTMX)    |    |          REST API v1 (/api/v1/*)          |
|  - Dashboard & Investigation     |    |  - CRUD endpoints                         |
|  - Active / Passive Recon views  |    |  - Pydantic v2 validation                 |
|  - Findings & Exposure Score     |    |  - JSON API & Export bundles              |
|  - Dossier & Audit Log templates |    |                                           |
+----------------------------------+    +-------------------------------------------+
          |                                                 |
          +------------------------+------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------------------+
|                               Domain Services Layer                               |
+--------------------+--------------------+--------------------+--------------------+
| Scope Validator    | Passive Recon Svc  | Real Tool Adapters | Evidence Correlator|
| - ipaddress module | - httpx (RDAP)     | - Nmap (subprocess)| - Graph mapping    |
| - dnspython checks | - dnspython (DNS)  | - theHarvester (sub)| - Deduplication   |
+--------------------+--------------------+--------------------+--------------------+
| Exposure Scorer    | ReportLab Dossier  | Background Tasks   | XML Parsers        |
| - 5-Factor scoring | - 20-Section PDF   | - Asyncio workers  | - defusedxml       |
| - Formula v3.0     | - GraphML Export   | - Job state machine| - CVE / CVSS map   |
+--------------------+--------------------+--------------------+--------------------+
                                   |
                                   v
+-----------------------------------------------------------------------------------+
|                   Repository & Persistence Layer (SQLAlchemy 2.0)                 |
|   - BaseRepository[T] with Unit of Work pattern                                   |
|   - Models: User, Investigation, Target, Evidence, Entity, Finding, AuditEvent... |
|   - Database: SQLite (WAL mode) -> PostgreSQL ready                               |
|   - Migrations: Alembic                                                           |
+-----------------------------------------------------------------------------------+
```

### 8.1 Logical Architectural Layers

#### Layer 1: Application Entry Point & Configuration
- **Responsibility:** Load environment variables, initialize database engines, configure CORS/security middlewares, register routers, and configure Jinja2 templates.
- **Python Modules:** `app/main.py`, `app/core/config.py`.
- **Replaces:** `server.ts`, `.env.example`.
- **Key Interface:** `Settings` class (Pydantic BaseSettings).

#### Layer 2: Authentication & Authorization
- **Responsibility:** Session state, password hashing, role enforcement (`admin`, `investigator`, `reviewer`, `viewer`).
- **Python Modules:** `app/core/security.py`, `app/api/deps.py`.
- **Replaces:** `api.ts` (lines 48–97), `src/context/AuthContext.tsx`.
- **Key Interface:** `get_current_user(required_roles: list[UserRole])`.

#### Layer 3: Scope Enforcement & Safety Boundary
- **Responsibility:** Strict IP/CIDR subnet verification, domain matching, and pre-execution authorization validity checks.
- **Python Modules:** `app/services/scope_validator.py`.
- **Replaces:** `src/server/services/scopeValidator.ts`.
- **Key Interface:** `validate_target(investigation, target, is_active: bool) -> ScopeValidationResult`.

#### Layer 4: Reconnaissance Tool Adapters & Execution
- **Responsibility:** Secure execution of external binaries and API clients.
  - **RDAP Client:** `app/services/rdap_collector.py` using `httpx`.
  - **DNS Inspector:** `app/services/dns_collector.py` using `dnspython`.
  - **Nmap Executor:** `app/services/nmap_executor.py` executing `nmap -sT ...` via `asyncio.create_subprocess_exec` with timeouts and cancellation.
  - **theHarvester Executor:** `app/services/harvester_executor.py`.
  - **Greenbone / OpenVAS Adapter:** `app/services/openvas_adapter.py` supporting both GMP protocol connection and XML file upload.
- **Replaces:** `src/server/services/passiveRecon.ts`, `workerManager.ts`.

#### Layer 5: Evidence Normalization, Deduplication & Correlation
- **Responsibility:** Canonical string formatting, deduplication via SHA-256 hashes, and automatic relationship graph mapping.
- **Python Modules:** `app/services/normalizer.py`, `app/services/correlation_engine.py`.
- **Replaces:** `src/server/services/normalizer.ts`, `src/server/services/correlationEngine.ts`.

#### Layer 6: Exposure Scoring Engine
- **Responsibility:** Deterministic calculation of 5-factor Exposure Score ($0.20P + 0.15D + 0.25S + 0.35V + 0.05C$) and tier categorization.
- **Python Modules:** `app/services/exposure_scorer.py`.
- **Replaces:** `src/server/services/exposureScorer.ts`, `src/utils/scoring.ts`.

#### Layer 7: Dossier Compilation & Document Generation
- **Responsibility:** Generating the 20-section audit report, compiling binary PDFs via ReportLab, and exporting GraphML and CSV formats.
- **Python Modules:** `app/services/report_generator.py`, `app/services/pdf_builder.py`.
- **Replaces:** `src/server/services/reportGenerator.ts`, `jspdf`.

#### Layer 8: Background Tasks & Job Orchestration
- **Decision on Async Architecture:** Redis and Celery introduce unnecessary operational overhead for an educational lab tool. The Python target will use **FastAPI's built-in `BackgroundTasks`** alongside Python's `asyncio` for non-blocking scanner execution and workflow state progression. If distributed multi-worker nodes are required in a future phase, a lightweight task queue (such as RQ or Celery) can be dropped in behind the existing `WorkerManager` interface.

---

## 9. Proposed Project Directory Structure

```
footprintiq/
├── pyproject.toml                     # Poetry/Pip project dependencies & tool configs
├── alembic.ini                        # Alembic database migration config
├── .env.example                       # Documented environment variables template
├── README.md                          # Application architecture & operational guide
├── migrations/                        # Alembic database migrations
│   ├── env.py
│   └── versions/
├── app/
│   ├── __init__.py
│   ├── main.py                        # FastAPI factory & ASGI entry point
│   ├── core/                          # Core settings, security & hashing
│   │   ├── config.py                  # Pydantic BaseSettings (.env loading)
│   │   ├── security.py                # Password hashing, JWT & SHA-256 HMAC
│   │   └── logging.py                 # Structured application logging
│   ├── db/                            # Database engine & session
│   │   ├── session.py                 # SQLAlchemy engine & sessionmaker
│   │   ├── base.py                    # DeclarativeBase definition
│   │   └── seed.py                    # NorthStar Analytics Lab seed initializer
│   ├── models/                        # SQLAlchemy ORM Models
│   │   ├── user.py
│   │   ├── investigation.py
│   │   ├── target.py
│   │   ├── evidence.py
│   │   ├── entity.py
│   │   ├── relationship.py
│   │   ├── service.py
│   │   ├── finding.py
│   │   ├── audit.py
│   │   └── report.py
│   ├── schemas/                       # Pydantic Request/Response validation schemas
│   │   ├── investigation.py
│   │   ├── recon.py
│   │   ├── workflow.py
│   │   └── reports.py
│   ├── repositories/                  # Clean repository data access pattern
│   │   ├── base.py
│   │   ├── investigation_repo.py
│   │   ├── finding_repo.py
│   │   └── audit_repo.py
│   ├── services/                      # Domain logic & tool wrappers
│   │   ├── scope_validator.py         # Subnet & domain boundary enforcement
│   │   ├── passive_recon.py           # RDAP (httpx) & DNS (dnspython)
│   │   ├── normalizer.py              # Canonical normalization & deduplication
│   │   ├── correlation_engine.py      # Multi-factor graph correlation
│   │   ├── exposure_scorer.py         # 5-Factor exposure scoring formula
│   │   ├── report_generator.py        # 20-Section dossier & GraphML export
│   │   ├── pdf_builder.py             # ReportLab PDF compiler
│   │   ├── workflow_controller.py     # 21-State investigation state machine
│   │   └── executors/                 # External subprocess runners
│   │       ├── nmap_runner.py         # Real Nmap CLI executor & parser
│   │       ├── harvester_runner.py    # theHarvester CLI executor
│   │       └── openvas_adapter.py     # Greenbone GMP client / parser
│   ├── parsers/                       # Defused XML / JSON parsing
│   │   ├── nmap_parser.py
│   │   ├── openvas_parser.py
│   │   └── harvester_parser.py
│   ├── api/                           # FastAPI REST routes (/api/v1/*)
│   │   ├── deps.py                    # RBAC & DB session dependencies
│   │   └── v1/
│   │       ├── auth.py
│   │       ├── investigations.py
│   │       ├── recon.py
│   │       ├── workflow.py
│   │       └── reports.py
│   ├── web/                           # Jinja2 + HTMX server-rendered views
│   │   ├── routes.py                  # HTML route controllers
│   │   └── filters.py                 # Custom Jinja2 template filters
│   ├── templates/                     # Jinja2 HTML templates
│   │   ├── base.html                  # Shell layout, navbar & modal containers
│   │   ├── components/                # Reusable UI partials & HTMX fragments
│   │   │   ├── auth_banner.html
│   │   │   ├── workflow_card.html
│   │   │   └── stat_card.html
│   │   └── pages/                     # Full page templates
│   │       ├── dashboard.html
│   │       ├── investigations.html
│   │       ├── new_investigation.html
│   │       ├── passive_recon.html
│   │       ├── active_scanning.html
│   │       ├── entity_graph.html
│   │       ├── findings.html
│   │       ├── exposure_score.html
│   │       ├── reports.html
│   │       ├── audit_log.html
│   │       └── settings.html
│   └── static/                        # Static assets (No build pipeline required)
│       ├── css/
│       │   └── main.css               # Clean modern custom styling
│       ├── js/
│       │   ├── htmx.min.js            # HTMX library (v1.9.10)
│       │   └── cytoscape.min.js       # Lightweight graph visualization
│       └── img/
└── tests/                             # Pytest automated test suite
    ├── conftest.py                    # Fixtures, test DB, demo accounts
    ├── test_scope_validator.py
    ├── test_parsers.py
    ├── test_passive_recon.py
    ├── test_exposure_scorer.py
    ├── test_workflow_controller.py
    ├── test_report_generator.py
    ├── test_api_rbac.py
    └── fixtures/                      # Sample XML and JSON test payloads
        ├── nmap_sample.xml
        ├── openvas_sample.xml
        └── harvester_sample.json
```

---

## 10. Database and Data Migration Plan

### 10.1 Existing Data Structure Analysis
The current V1 database is stored in `.data/footprintiq_db.json` (238 KB). It contains 13 top-level collections:
1. `users`: 4 demo users (`admin`, `investigator`, `reviewer`, `viewer`).
2. `investigations`: Primary investigation `inv-northstar-01`.
3. `targets`: Authorized IP and domain target records.
4. `evidence`: 12 evidence entries (RDAP, DNS, manual search observations).
5. `entities`: 15 graph nodes (Organization, Domains, Subdomains, IPs, Emails, Ports, Services).
6. `relationships`: 18 directional graph edges with labels and confidence ratings.
7. `services`: 5 active service records on `192.168.56.102` (SSH, HTTP, HTTPS, PostgreSQL, Jetty/Jenkins).
8. `vulnerabilities`: Vulnerability catalog entries.
9. `findings`: Triaged security findings (CVE-2023-38606, CVE-2011-3389).
10. `scores`: Exposure score breakdown for `inv-northstar-01`.
11. `reports`: Generated report dossiers.
12. `auditEvents`: Chronological tamper-evident audit ledger entries with hashes.
13. `collectorRuns`: History of execution runs.

### 10.2 Proposed SQLAlchemy Models

```python
# app/models/investigation.py
from sqlalchemy import String, Boolean, JSON, DateTime, ForeignKey, Integer, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from app.db.base import Base

class InvestigationModel(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    organization_name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(String(1024), nullable=False)
    lead_investigator: Mapped[str] = mapped_column(String(128), nullable=False)
    team_members: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="active")
    
    # Scope & Authorization stored as structured JSON or relational columns
    scope_owned_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    scope_approved_ips: Mapped[list[str]] = mapped_column(JSON, default=list)
    scope_approved_cidrs: Mapped[list[str]] = mapped_column(JSON, default=list)
    scope_active_targets: Mapped[list[str]] = mapped_column(JSON, default=list)
    scope_excluded_targets: Mapped[list[str]] = mapped_column(JSON, default=list)
    
    auth_active_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    auth_approved_by: Mapped[str] = mapped_column(String(128))
    auth_reference: Mapped[str] = mapped_column(String(128))
    auth_start_date: Mapped[datetime] = mapped_column(DateTime)
    auth_expiry_date: Mapped[datetime] = mapped_column(DateTime)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    targets = relationship("TargetModel", back_populates="investigation", cascade="all, delete-orphan")
    evidence = relationship("EvidenceModel", back_populates="investigation", cascade="all, delete-orphan")
    entities = relationship("EntityModel", back_populates="investigation", cascade="all, delete-orphan")
    findings = relationship("FindingModel", back_populates="investigation", cascade="all, delete-orphan")
    audit_events = relationship("AuditEventModel", back_populates="investigation", cascade="all, delete-orphan")
```

### 10.3 Data Migration Script Strategy
A standalone migration script (`scripts/migrate_v1_json.py`) will be executed during setup:
1. Initialize SQLite schema using Alembic (`alembic upgrade head`).
2. Read `.data/footprintiq_db.json`.
3. Map every JSON object to its corresponding SQLAlchemy model.
4. Convert date strings (ISO 8601) to Python `datetime` objects.
5. Preserve all original identifiers (`inv-northstar-01`, `ev-01`, `ent-01`, etc.) to maintain relational referential integrity.
6. Commit the entire dataset in a single database transaction.

---

## 11. Dependencies & Environment Plan

### 11.1 Proposed Python Dependencies (`pyproject.toml`)

| Package Name | Purpose | Status | Target Module | External System Tool |
| :--- | :--- | :--- | :--- | :--- |
| `fastapi` (>=0.110.0) | High-performance async web framework | Essential | `app/main.py`, `app/api/*` | None |
| `uvicorn` (>=0.28.0) | ASGI production and development server | Essential | Application entry point | None |
| `jinja2` (>=3.1.3) | HTML template engine for dashboard views | Essential | `app/web/*`, `templates/*` | None |
| `python-multipart` (>=0.0.9)| Multi-part form parser for file uploads | Essential | Scan upload endpoints | None |
| `pydantic` (>=2.6.4) | Data validation, request schemas & settings | Essential | `app/schemas/*`, `app/core/config.py` | None |
| `pydantic-settings` (>=2.2.1)| Environment variable management | Essential | `app/core/config.py` | None |
| `sqlalchemy` (>=2.0.28) | Object Relational Mapping & Query Builder | Essential | `app/models/*`, `app/db/*` | SQLite / PostgreSQL |
| `alembic` (>=1.13.1) | Declarative schema migration framework | Essential | `migrations/*` | None |
| `httpx` (>=0.27.0) | Async HTTP client for RDAP and web API calls | Essential | `app/services/passive_recon.py` | None |
| `dnspython` (>=2.6.1) | Authoritative DNS resolution and DNSSEC audit | Essential | `app/services/scope_validator.py` | System DNS resolver |
| `defusedxml` (>=0.7.1) | Hardened, XXE-proof XML parser | Essential | `app/parsers/*` | None |
| `reportlab` (>=4.1.0) | High-fidelity binary PDF report generator | Essential | `app/services/pdf_builder.py` | None |
| `passlib[bcrypt]` (>=1.7.4)| Password hashing & verification | Essential | `app/core/security.py` | None |
| `python-jose[cryptography]`| Signed JWT access token creation/validation | Essential | `app/core/security.py` | None |
| `python-gvm` (>=24.1.0) | Greenbone GMP protocol API adapter | Optional | `app/services/executors/openvas_adapter.py` | Greenbone/GVM daemon |
| `pytest` (>=8.1.1) | Test framework for unit & integration tests | Essential (Dev) | `tests/*` | None |
| `pytest-asyncio` (>=0.23.5) | Async test runner for FastAPI endpoints | Essential (Dev) | `tests/*` | None |

### 11.2 Required System Tools
1. **Nmap** (`nmap` CLI tool): Must be installed in system PATH for real network service probes.
2. **theHarvester** (`theHarvester` CLI or Python module): Required for live search engine OSINT collection.
3. **OpenVAS / GVM** (Optional): Required only if live network vulnerability scanning against lab targets is desired; file ingestion remains fully functional without it.

### 11.3 Safe Environment Configuration Template (`.env.example`)
```ini
# Application Configuration
APP_NAME="FootprintIQ - Digital Footprint Investigator"
APP_ENV="development"
DEBUG=True
SECRET_KEY="generate-secure-random-secret-key-for-jwt-signing"
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=480

# Server Binding
HOST="0.0.0.0"
PORT=8000

# Database Connection (SQLite by default; PostgreSQL ready)
DATABASE_URL="sqlite:///./footprintiq.db"
# DATABASE_URL="postgresql+asyncpg://footprint_user:password@localhost:5432/footprintiq"

# Reconnaissance Tool Paths
NMAP_PATH="nmap"
THEHARVESTER_PATH="theHarvester"

# Safety Limits
MAX_UPLOAD_SIZE_MB=10
DEFAULT_SCAN_TIMEOUT_SECONDS=120
STRICT_SCOPE_ENFORCEMENT=True
```

---

## 12. Phased Implementation Roadmap

This roadmap orders implementation by strict architectural dependencies to avoid circular blockers.

```
+-----------------------------------------------------------------------------------------+
|                               PHASED IMPLEMENTATION TIMELINE                            |
+-----------------------------------------------------------------------------------------+
| Phase 2.1: Python Foundation, Models, Database & Migrations                             |
| Phase 2.2: Hardened Authentication, Session Security & Audit Ledger                     |
| Phase 2.3: Scope Validation Engine & Passive Reconnaissance (RDAP/DNS)                  |
| Phase 2.4: XML Ingestion Parsers (XXE-Hardened Nmap, OpenVAS, theHarvester)             |
| Phase 2.5: Real Subprocess Execution Engine (Nmap, theHarvester)                        |
| Phase 2.6: Evidence Normalization, Deduplication & Entity Correlation                   |
| Phase 2.7: 5-Factor Exposure Scoring & ReportLab 20-Section PDF Generation              |
| Phase 2.8: Jinja2 + HTMX Dashboard & Operational Views Migration                        |
| Phase 2.9: 21-State Semi-Autonomous Workflow Controller                                 |
| Phase 2.10: End-to-End Validation, Pytest Suite & Parity Demonstration                  |
+-----------------------------------------------------------------------------------------+
```

### Phase 2.1 — Python Foundation, Database Models & Migration
- **Objective:** Establish the FastAPI project structure, SQLAlchemy 2.0 ORM models, Alembic migrations, and import legacy JSON data from `.data/footprintiq_db.json`.
- **Prerequisites:** Python 3.11+, virtual environment.
- **Files to Implement:** `pyproject.toml`, `app/main.py`, `app/core/config.py`, `app/db/session.py`, `app/models/*.py`, `migrations/`, `scripts/migrate_v1_json.py`.
- **Acceptance Criteria:** `alembic upgrade head` runs cleanly; legacy database records are imported into SQLite with 100% referential integrity.

### Phase 2.2 — Hardened Authentication, RBAC & Audit Ledger
- **Objective:** Eliminate the default-admin backdoor and implement secure, signed sessions with SHA-256 HMAC audit chaining.
- **Prerequisites:** Phase 2.1.
- **Files to Implement:** `app/core/security.py`, `app/api/deps.py`, `app/api/v1/auth.py`.
- **Acceptance Criteria:** Missing authorization headers return `401 Unauthorized`; passwordless logins are blocked; audit events create an immutable SHA-256 chain.

### Phase 2.3 — Scope Validation & Passive Reconnaissance
- **Objective:** Implement the security boundary validator (`ipaddress` and `dnspython`) and safe RDAP/DNS collectors with caching.
- **Prerequisites:** Phase 2.2.
- **Files to Implement:** `app/services/scope_validator.py`, `app/services/passive_recon.py`, `app/api/v1/recon.py`.
- **Acceptance Criteria:** All IPv4, IPv6, FQDN, and CIDR checks pass unit tests; live RDAP and DNS queries resolve correctly with offline lab fallback.

### Phase 2.4 — XXE-Hardened Ingestion Parsers
- **Objective:** Implement XML and JSON parsers for Nmap, OpenVAS, and theHarvester exports using `defusedxml`.
- **Prerequisites:** Phase 2.3.
- **Files to Implement:** `app/parsers/nmap_parser.py`, `app/parsers/openvas_parser.py`, `app/parsers/harvester_parser.py`.
- **Acceptance Criteria:** Malicious XML payloads containing `<!ENTITY` or `SYSTEM` are safely rejected; sample scan files parse into validated Pydantic models.

### Phase 2.5 — Real Tool Subprocess Execution Engine
- **Objective:** Replace simulated worker mocks with real, authorized subprocess executions of Nmap and theHarvester.
- **Prerequisites:** Phase 2.4.
- **Files to Implement:** `app/services/executors/nmap_runner.py`, `app/services/executors/harvester_runner.py`, `app/services/worker_manager.py`.
- **Acceptance Criteria:** Nmap is invoked with fixed, unalterable arguments (`-sT`, `-p 22,80,443,5432,8080`); out-of-scope targets are aborted before process launch; execution outputs are parsed and ingested.

### Phase 2.6 — Normalization, Deduplication & Entity Correlation
- **Objective:** Implement canonical string cleaning, SHA-256 evidence deduplication, and automatic multi-factor graph relationship mapping.
- **Prerequisites:** Phase 2.5.
- **Files to Implement:** `app/services/normalizer.py`, `app/services/correlation_engine.py`.
- **Acceptance Criteria:** Repeated evidence ingestion does not create duplicate entries; entities are linked across 5 tiers (Org -> Domain -> IP -> Port -> Vuln).

### Phase 2.7 — Exposure Scoring & 20-Section PDF Dossier Generation
- **Objective:** Implement the 5-factor exposure scoring formula ($0.20P + 0.15D + 0.25S + 0.35V + 0.05C$) and compile binary PDFs using ReportLab.
- **Prerequisites:** Phase 2.6.
- **Files to Implement:** `app/services/exposure_scorer.py`, `app/services/pdf_builder.py`, `app/services/report_generator.py`.
- **Acceptance Criteria:** Exposure score matches benchmark calculation; generated PDF matches all 20 sections with cover page, tables, and page numbering.

### Phase 2.8 — Jinja2 + HTMX Dashboard & Operational Views
- **Objective:** Migrate all 12 React views into clean, modern server-rendered HTML views with HTMX dynamic interactions.
- **Prerequisites:** Phase 2.7.
- **Files to Implement:** `app/web/routes.py`, `templates/*.html`, `templates/pages/*.html`, `static/css/main.css`.
- **Acceptance Criteria:** Complete UI parity with React interface without any Node.js or JavaScript build step.

### Phase 2.9 — Semi-Autonomous Workflow Controller
- **Objective:** Implement the 21-state lifecycle state machine with investigator approval gates.
- **Prerequisites:** Phase 2.8.
- **Files to Implement:** `app/services/workflow_controller.py`, `app/api/v1/workflow.py`, `templates/components/workflow_card.html`.
- **Acceptance Criteria:** One-click "Run Safe Demo" transitions smoothly from `CREATED` through `COMPLETED` with live HTMX polling updates.

### Phase 2.10 — End-to-End Validation & Pytest Suite
- **Objective:** Port all 34 assertions from `runAllTests.ts` and `runDemoE2ETest.ts` into a comprehensive Pytest test suite.
- **Prerequisites:** Phase 2.9.
- **Files to Implement:** `tests/test_*.py`, `tests/conftest.py`.
- **Acceptance Criteria:** 100% green test run across all modules.

---

## 13. Risks, Assumptions and Unresolved Questions

### 13.1 Technical Risks
1. **Host Nmap Privileges:** Running SYN stealth scans (`-sS`) or OS detection (`-O`) requires root/administrator privileges. *Mitigation:* Restrict default scan profiles to unprivileged full TCP handshakes (`-sT`) and version detection (`-sV`).
2. **Search Engine Blocking of theHarvester:** Search engines frequently rate-limit or captcha automated queries from cloud IP addresses. *Mitigation:* Ensure manual evidence logging remains prominent and implement passive search query links rather than relying solely on automated scraping.
3. **Windows File System Locks:** SQLite file locks can occur under heavy asynchronous write concurrency on Windows. *Mitigation:* Enable SQLite Write-Ahead Logging (`PRAGMA journal_mode=WAL;`) on connection initialization.

### 13.2 Architectural Assumptions
- The application will run as a local lab tool or internal team server, where SQLite is sufficient for single-node operation, while SQLAlchemy ensures zero code changes are required if migrating to PostgreSQL.
- Celery and Redis are intentionally omitted to avoid operational overhead, relying instead on FastAPI background tasks and asyncio.

### 13.3 Unresolved Questions for User Decision
1. **Interactive Entity Graph Technology:** The V1 React app uses an inline SVG layout with custom math. For the Jinja2/HTMX dashboard, should we render a server-generated SVG graph (zero dependencies) or include **Cytoscape.js** (50 KB standalone JS) for client-side dragging and physics layouts?
2. **Demo Account Authentication Behavior:** Should Phase 2 retain the one-click demo role switcher in the header for educational ease, or should it enforce strict password authentication on all endpoints?
3. **Nmap CLI Requirement:** If Nmap is not installed on the host machine running the Python backend, should active scans fail with an explicit error, or fall back to simulated sample outputs with a clear warning?

---

## 14. Final Readiness Assessment for Phase 2

### Readiness Rating
**READY WITH BLOCKERS**

### Justification
- **Architecture & Specifications:** Fully understood and documented. Data contracts, scoring algorithms, scope rules, and report sections are 100% cataloged and ready for Python implementation.
- **Blockers:** 
  1. The Node.js test environment is missing dependencies (`node_modules`), preventing baseline verification of existing tests.
  2. Severe security backdoors in authentication and pseudo-hashing must be remediated immediately in Phase 2 rather than ported as-is.
  3. External executable availability (Nmap in PATH) must be determined on the host system.

---
*End of Audit Report.*
