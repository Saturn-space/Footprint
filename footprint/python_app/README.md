# FootprintIQ: Digital Footprint Investigator (Python Application)

**Phase 3 Implementation Deliverable — Authentication, Role-Based Access Control (RBAC), Server Sessions & Audit Logging**

---

## 1. Overview & Purpose

This package (`python_app/`) provides the modernized **Python 3 / FastAPI / SQLAlchemy / Jinja2 + HTMX** application for FootprintIQ, migrating away from the legacy React 19 / Express 4 runtime.

In Phase 3, production-conscious authentication and authorization have been established:
- **Argon2id Password Hashing:** RFC 9106 compliant password hashing via `argon2-cffi`, eliminating weak polynomial hashes and deprecated bcrypt backends.
- **Server-Side Session Store:** Stateful session tracking persisted in SQLite/PostgreSQL with SHA-256 hashed session identifiers, preventing database token leaks, session fixation, and enabling instant revocation.
- **Strict Role-Based Access Control (RBAC):** Three discrete roles (`administrator`, `analyst`, `viewer`) with server-side permission enforcement (`require_permission` / `require_role`).
- **Preparatory Scan Permission Model:** Dedicated permission tokens (`investigation.create`, `investigation.view`, `report.view`, `report.export`, `user.manage`, `scope.manage`, `recon.passive`, `recon.active`, `vulnerability.scan`).
- **Comprehensive CSRF Defense:** Double-submit cookie with cryptographic validation (`footprintiq_csrf`) for all state-changing browser cookie requests (`POST`/`PUT`/`DELETE`), with safe exemption for API Bearer tokens.
- **Account Lockout & Throttling:** Automatic 15-minute lockout after 5 consecutive failed login attempts to prevent brute-force credential stuffing.
- **Tamper-Evident Security Audit Trail:** Structured recording of critical security events (`LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGOUT`, `USER_CREATED`, `ROLE_CHANGED`, `PERMISSION_DENIED`, `ADMIN_PROVISIONED`) with strict credential redaction.
- **Safe Initial Administrator Provisioning:** Dedicated CLI command (`scripts/create_admin.py`) enforcing password complexity rules without default credentials.
- **Zero V1 Regressions:** Original React/Express V1 files in `src/`, `server.ts`, and root manifests remain 100% untouched.

---

## 2. Architecture & Directory Layout

```
python_app/
├── alembic.ini                        # Alembic migration configuration
├── pyproject.toml                     # Dependency manifest and pytest settings
├── .env.example                       # Documented configuration template
├── .gitignore                         # Exclusions for virtualenvs, caches, db files
├── README.md                          # Developer setup and operational guide
├── scripts/
│   └── create_admin.py                # Safe interactive/non-interactive admin provisioning
├── migrations/                        # Alembic schema migrations
│   ├── env.py                         # Migration runner linking Base.metadata
│   ├── script.py.mako                 # Migration revision template
│   └── versions/
│       ├── 0001_initial_investigation_foundation.py
│       └── 0002_add_auth_and_sessions.py
├── app/
│   ├── __init__.py
│   ├── main.py                        # FastAPI factory, security headers, & dashboard routes
│   ├── config.py                      # Pydantic Settings & environment validators
│   ├── logging_config.py              # Structured JSON / standard logging & correlation IDs
│   ├── database.py                    # SQLAlchemy 2.x engine, Base, and get_db dependency
│   ├── core/                          # Security & authentication core services
│   │   ├── __init__.py
│   │   ├── security.py                # Argon2id hashing, token generation, RBAC permission map
│   │   └── auth.py                    # User authentication, session lifecycle, audit logger
│   ├── models/                        # Declarative SQLAlchemy models
│   │   ├── __init__.py
│   │   ├── investigation.py           # InvestigationModel
│   │   ├── user.py                    # UserModel & UserSessionModel
│   │   └── audit.py                   # AuditLogModel
│   ├── schemas/                       # Pydantic validation schemas
│   │   ├── __init__.py
│   │   ├── health.py                  # Liveness, readiness, and API health schemas
│   │   ├── investigation.py           # Scope and investigation schemas
│   │   └── auth.py                    # LoginRequest, TokenResponse, UserResponse, UserCreate
│   ├── api/                           # REST API v1 endpoints
│   │   ├── __init__.py
│   │   ├── deps.py                    # get_current_user, require_role, require_permission, CSRF
│   │   ├── health.py                  # /health/live, /health/ready, /api/v1/health
│   │   ├── auth.py                    # /api/v1/auth/login, /api/v1/auth/logout, /api/v1/auth/me
│   │   ├── users.py                   # /api/v1/users (Admin user management)
│   │   ├── audit.py                   # /api/v1/audit-logs (Admin audit inspection)
│   │   └── investigations.py          # /api/v1/investigations (Protected CRUD)
│   ├── templates/                     # Jinja2 HTML templates
│   │   ├── base.html                  # Responsive layout, navbar, user badge, signout form
│   │   ├── dashboard.html             # Investigation workspace view
│   │   ├── login.html                 # Investigator authentication form
│   │   ├── access_denied.html         # HTTP 403 Access Denied template
│   │   └── components/
│   │       └── health_badge.html      # HTMX dynamic polling fragment
│   └── static/                        # Static assets (Zero build step required)
│       ├── css/
│       │   └── main.css               # Cybersecurity dark theme design tokens
│       └── js/
│           └── htmx.min.js            # Standalone HTMX library (v1.9.12)
└── tests/                             # Automated test suite (100% passing)
    ├── conftest.py                    # Test database fixtures, isolated clients, user mocks
    ├── test_health.py                 # Liveness & readiness probe tests
    ├── test_dashboard.py              # Dashboard rendering & HTMX component tests
    ├── test_database.py               # Session lifecycle & model constraint tests
    ├── test_migrations.py             # Alembic fresh DB initialization tests
    ├── test_error_handling_and_config.py # Sanitized errors & configuration rule tests
    ├── test_auth.py                   # Login, logout, session expiration, token tests
    ├── test_rbac.py                   # Role boundaries, permissions, unauthorized rejection
    ├── test_csrf_and_cookies.py       # CSRF protection, headers, lockout throttling
    ├── test_audit_logging.py          # Audit trail generation & secret redaction
    └── test_admin_provisioning.py     # Admin CLI provisioning & complexity rules
```

---

## 3. Safe Administrator Provisioning

FootprintIQ contains **no default credentials** and **never pre-seeds passwords**. Before operators can log in, an initial administrator must be provisioned.

### 3.1 Interactive CLI Provisioning (Recommended)

Run the provisioning script from the `python_app` directory:

```bash
python scripts/create_admin.py
```

The script will interactively prompt for:
1. **Username:** Minimum 3 characters (e.g., `admin_lead`).
2. **Email Address:** Valid organizational email (e.g., `admin@northstar.example`).
3. **Password (hidden prompt via getpass):** Enforces password complexity:
   - Minimum 12 characters.
   - At least 1 uppercase letter (`A-Z`).
   - At least 1 lowercase letter (`a-z`).
   - At least 1 number or special symbol (`0-9`, `!@#$%^&*`).

### 3.2 Non-Interactive Provisioning (CI / Automation)

For automated lab deployments, credentials can be passed via arguments or environment variables:

```bash
python scripts/create_admin.py \
  --username admin_lead \
  --email admin@northstar.example \
  --password "NorthStarSecure2026!#" \
  --non-interactive
```

Repeat execution is completely safe: if the administrator account already exists, the script safely offers to update the password without raising duplicate key errors.

---

## 4. Role-Based Access Control (RBAC) & Permissions

FootprintIQ enforces server-side authorization at both the role level and individual capability level.

| Role | Target Permissions | Allowed Operations |
| :--- | :--- | :--- |
| **Administrator** (`administrator`) | All permissions | Manage user accounts, assign roles, inspect security audit logs, configure system behavior, create & view investigations. |
| **Security Analyst** (`analyst`) | `investigation.create`, `investigation.view`, `report.view`, `report.export`, `scope.manage`, `recon.passive` | Create campaigns, review scope, analyze findings, export reports. Cannot manage users, alter permissions, or view raw audit logs. |
| **Read-Only Viewer** (`viewer`) | `investigation.view`, `report.view` | View authorized investigation records and generated reports. Cannot create campaigns, launch scans, or modify any resource. |

### Preparatory Scanning Permission Model (Phase 3 -> Phase 4/5)
Possession of a scanning capability (e.g., `recon.active`, `vulnerability.scan`) establishes that a user's role permits scanning. However, **target-level authorization records** in later phases will independently verify target scope ownership, approved scan windows, and authorization references prior to external tool execution.

---

## 5. Authentication & Session Management

### 5.1 Web Dashboard Login & Logout Workflow
1. Navigate to `http://127.0.0.1:8000/login`.
2. Enter credentials. On successful authentication, the server:
   - Issues a high-entropy session token (256-bit).
   - Hashes the token using SHA-256 and records the session in `user_sessions`.
   - Attaches `footprintiq_session` (`HttpOnly`, `SameSite=lax`, `Path=/`, `Secure` in production).
   - Attaches `footprintiq_csrf` cookie for CSRF defense.
   - Redirects to `/` displaying the operator's active identity and role badge.
3. Clicking **Sign Out** submits `POST /auth/logout` with the form's CSRF token, invalidating the session in the database and deleting all cookies.

### 5.2 REST API Authentication
API clients authenticate via the standard Bearer header:
```bash
# Authenticate
curl -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username_or_email": "admin_lead", "password": "NorthStarSecure2026!#"}'

# Use Access Token
curl -X GET http://127.0.0.1:8000/api/v1/investigations \
  -H "Authorization: Bearer <access_token>"
```

API requests presenting an `Authorization: Bearer` header are **exempt from CSRF** checks because browser ambient credentials are not utilized.

---

## 6. Phase 4 — Passive Reconnaissance Integrations

Phase 4 integrates live passive OSINT reconnaissance pipelines, forensic evidence persistence, and common entity normalization:

### 1. Dedicated Collectors
- **RDAP Domain Registration (`app/services/collectors/rdap.py`):** Queries RFC 7483 RDAP endpoints with fallback to RFC 3912 TCP socket WHOIS queries (`whois.iana.org` referral resolution). Extracts registrars, registration dates, statuses, and nameservers.
- **DNS Record Collector (`app/services/collectors/dns_collector.py`):** Queries A, AAAA, MX, NS, CNAME, TXT, SOA records via `dnspython`. Categorizes authoritative absence (NXDOMAIN / NoAnswer) vs transient resolver failures.
- **Certificate Transparency Logs (`app/services/collectors/crtsh.py`):** Collects TLS certificates and SANs via the `crt.sh` JSON API. Extracts subdomains, domains, and certificate metadata.
- **theHarvester Integration (`app/services/collectors/theharvester.py`):** Controlled subprocess invocation (`asyncio.create_subprocess_exec`) without shell interpolation. When the binary is not present on PATH, reports `NOT_CONFIGURED` without fabricating data or failing the pipeline.
- **Public Search Collector (`app/services/collectors/search_collector.py`):** Strictly enforces API-based collection policy. Without configured API keys, returns clean `NOT_CONFIGURED` semantics rather than brittle scraping.

### 2. Forensic Evidence Storage & Integrity
- Stored under `./evidence_storage/<investigation_id>/<evidence_id>_<source>.raw.<ext>`
- Strictly enforces path traversal protection (`is_relative_to` checks).
- Computes SHA-256 cryptographic hashes for tamper-evident verification.
- Exposes relative database paths (never absolute server filepaths).
- Raw evidence retrieval endpoint verifies hash matching on read:
  `GET /api/v1/investigations/{id}/evidence/{evidence_id}/raw` returns `X-Content-SHA256` and `X-Evidence-Integrity: VERIFIED`.

### 3. Entity Normalization & Deduplication
- **Deterministic Normalization:** FQDN lowercasing and trailing-dot removal, standard-library IPv4/IPv6 address parsing, conservative email normalization.
- **Deduplication:** Repeated discoveries within the same campaign update `last_seen` timestamps, preserve multi-source `evidence_ids` provenance, and merge non-conflicting metadata.
- **Supported Entity Types:** `DOMAIN`, `SUBDOMAIN`, `IP_ADDRESS`, `HOST`, `EMAIL`, `ORGANIZATION`, `DNS_RECORD`, `CERTIFICATE`, `URL`.

### 4. Target Authorization & Scope Enforcement
Before executing reconnaissance:
1. Validates that target falls strictly within the investigation's approved scope (`owned_domains`, `approved_ips`, `approved_cidrs`, `active_targets`).
2. Checks for a valid, non-expired, unrevoked administrative authorization record (`TargetAuthorizationModel`).
3. Rejects active-scan commands or unauthorized targets with audit logging.
4. Records authorization decisions under `TARGET_AUTHORIZATION_VERIFIED` or `TARGET_AUTHORIZATION_REJECTED`.

### 5. API Endpoints
- `POST /api/v1/investigations/{id}/passive-recon` — Triggers bounded-concurrency reconnaissance (requires `recon.passive`).
- `GET /api/v1/investigations/{id}/passive-recon` — Lists collection jobs.
- `GET /api/v1/investigations/{id}/entities` — Lists normalized deduplicated findings.
- `GET /api/v1/investigations/{id}/evidence` — Lists forensic evidence records.
- `GET /api/v1/investigations/{id}/evidence/{id}/raw` — Streams raw forensic evidence with SHA-256 verification.
- `POST /api/v1/investigations/{id}/validate-target` — Validates target scope and authorization status.
- `POST /api/v1/investigations/{id}/authorizations` — Creates target authorization record (requires `scope.manage`).
- `GET /api/v1/investigations/{id}/authorizations` — Lists target authorizations.
- `DELETE /api/v1/investigations/{id}/authorizations/{auth_id}` — Revokes target authorization.

---

## 6. Phase 5: Controlled Real Nmap Active Reconnaissance & Ingestion

Phase 5 establishes real network reconnaissance execution via Nmap for explicitly authorized lab targets without permitting arbitrary command entry or elevated privilege bypasses.

### 1. Installation & Environment Configuration
- **Windows:** Download and install Nmap from [nmap.org](https://nmap.org/download.html). The binary will typically reside at `C:\Program Files (x86)\Nmap\nmap.exe` or `E:\asipali\Nmap\nmap.exe`. Set `NMAP_BIN="C:/Program Files (x86)/Nmap/nmap.exe"` in `.env` if not on the system `PATH`.
- **Linux (Ubuntu/Debian):** `sudo apt-get update && sudo apt-get install -y nmap`
- **macOS (Homebrew):** `brew install nmap`
- **Verification:** Execute `GET /api/v1/tools/nmap/status` or run `python -c "from app.services.active.nmap_detector import get_nmap_detector; print(get_nmap_detector().check_availability())"`.

### 2. Administrator-Vetted Scan Profiles
Arbitrary flag entry is strictly forbidden. Scanning is restricted to three vetted server-side profiles:
- `basic_tcp` (`-sT -T3 --top-ports 100 -Pn`): Conservative TCP connect scan on top 100 ports, standard timing template, unprivileged connect mode, 90s timeout.
- `service_inventory` (`-sT -sV --version-intensity 2 -T3 --top-ports 100 -Pn`): Service detection and version banner extraction on top 100 ports, 180s timeout.
- `quick_ping` (`-sn -T3`): Host reachability and ping sweep without port interrogation, 45s timeout.

### 3. Pre-Execution Target Authorization & Scope Enforcement
Every scan execution revalidates:
1. User authentication and account active state.
2. User holds `recon.active` permission (Administrator role).
3. Target is within investigation scope (`approved_ips`, `approved_cidrs`, or `active_targets`).
4. An active, non-expired, unrevoked `TargetAuthorizationModel` record explicitly authorizes `"SCAN_ACTIVE"` on the target.
5. Target hostname resolves via DNS, and all resolved IPs comply with network policy (multicast and unspecified IPs rejected).
6. Investigation has `active_scanning_enabled=True`.

### 4. Safe Subprocess Execution & Provenance
- Executed via `asyncio.create_subprocess_exec` using argument lists (no shell interpolation).
- Output is written directly to a managed temporary XML file (`data/temp_scans/nmap_{job_id}_{hash}.xml`).
- Concurrency is bounded by an `asyncio.Semaphore` (`NMAP_MAX_CONCURRENCY=2`).
- Running processes can be cancelled via `POST /api/v1/nmap-scans/{id}/cancel`.
- XML is ingested into `EvidenceStore` with SHA-256 hash calculation, parsed securely with XXE defense (`xml.etree.ElementTree`), and persisted to `scan_hosts`, `scan_ports`, and `entities` tables.
- Comprehensive audit records logged: `SCAN_ACTIVE_QUEUED`, `SCAN_ACTIVE_STARTED`, `SCAN_ACTIVE_COMPLETED`, `SCAN_ACTIVE_CANCELLED`, `SCAN_ACTIVE_TIMED_OUT`, `SCAN_ACTIVE_DENIED`.

### 5. Nmap REST API Endpoints
- `GET /api/v1/tools/nmap/status` — Checks Nmap binary availability, version, and diagnostic code.
- `GET /api/v1/nmap/profiles` — Lists permitted scan profiles.
- `POST /api/v1/investigations/{id}/nmap-scans` — Dispatches authorized scan job (requires `recon.active`).
- `GET /api/v1/investigations/{id}/nmap-scans` — Lists active scan jobs for an investigation.
- `GET /api/v1/nmap-scans/{job_id}` — Gets status and metadata for a scan job.
- `POST /api/v1/nmap-scans/{job_id}/cancel` — Cancels a running or queued scan job.
- `GET /api/v1/nmap-scans/{job_id}/results` — Retrieves normalized findings (hosts, ports, services).
- `GET /api/v1/nmap-scans/{job_id}/xml` — Downloads raw Nmap XML evidence with `X-Content-SHA256` header.

---

## 7. Database Migrations

Apply Alembic migrations to upgrade the database schema:

---

## 7. Phase 6: Greenbone / OpenVAS Vulnerability Assessment Integration

Phase 6 integrates genuine Greenbone Vulnerability Management (GVM) / OpenVAS into FootprintIQ. It provides end-to-end vulnerability assessment orchestration with explicit target authorization, bounded polling, cancellation, secure XML report parsing, and normalized vulnerability findings.

### 1. Integration Architecture & Connectivity
- **Client & Adapter Layer:** Dedicated low-level client (`app/integrations/greenbone_client.py`) and high-level adapter (`app/integrations/greenbone_adapter.py`) using `python-gvm` and GMP (Greenbone Management Protocol).
- **Supported Connection Modes:**
  - Network TLS: Configured via `GVM_HOST`, `GVM_PORT`, with mandatory TLS certificate verification (`GVM_TLS_VERIFY=True`).
  - Local Unix Domain Socket: Configured via `GVM_UNIX_SOCKET` (e.g. `/run/gvmd/gvmd.sock`) on Linux and WSL systems.
- **Honest Availability Reporting:** If credentials or endpoints are unconfigured, reports status `NOT_CONFIGURED`. If unreachable, reports `UNAVAILABLE`. If authentication fails, reports `AUTHENTICATION_FAILED`. Never silently simulates fake scan results.
- **Zero Secret Exposure:** Credentials are read from environment variables; passwords and session tokens are strictly redacted from diagnostic endpoints and audit logs.

### 2. Approved Vulnerability Scan Profiles
Arbitrary or destructive scan configuration IDs cannot be submitted by users. Assessments are constrained to administrator-vetted profiles (`app/services/vuln/profiles.py`):
- `openvas-basic` (GVM `Base`, UUID `daba56c8-73ec-11df-a475-002264764ceb`): Conservative, non-destructive vulnerability assessment evaluating service vulnerabilities and misconfigurations. Safe for sensitive lab hosts.
- `openvas-full-and-fast` (GVM `Full and fast`, UUID `daba56c8-73ec-11df-a475-002264764cea`): Standard comprehensive assessment with DoS plugins disabled by policy.
- `openvas-discovery` (GVM `Discovery`, UUID `daba56c8-73ec-11df-a475-002264764cec`): Lightweight service and OS enumeration without active vulnerability testing.

### 3. Pre-Assessment Target Authorization & Scope Enforcement
Target authorization is strictly revalidated immediately before execution:
1. Operator must hold the `vulnerability.scan` permission (Administrator role).
2. Target must be within the investigation scope (`approved_ips` or `active_targets`).
3. An active, non-expired, unrevoked `TargetAuthorizationModel` record must explicitly include `"SCAN_VULN"` or `"SCAN_VULNERABILITY"`.
4. Permission to run passive reconnaissance or active Nmap does **not** grant permission for vulnerability assessment.
5. Hostname targets are resolved via DNS, and resolved IPs are verified against network policy.

### 4. Scan Lifecycle Management
- **States:** `QUEUED` -> `CONFIGURING_TARGET` -> `CREATING_TASK` -> `RUNNING` -> `RETRIEVING_REPORT` -> `PARSING` -> `COMPLETED`.
- **Failure States:** Explicitly categorized into `FAILED`, `TIMED_OUT`, `CANCELLED`, or `NOT_CONFIGURED`.
- **Bounded Polling:** Monitored at configurable intervals (`GVM_POLL_INTERVAL_SECONDS=5`) up to a maximum attempt ceiling (`GVM_MAX_POLL_ATTEMPTS=60`), preventing unbounded loops.
- **Cancellation:** Running tasks can be stopped immediately via `POST /api/v1/vulnerability-assessments/{job_id}/cancel`, sending a stop signal to GVM and transitioning the job to `CANCELLED`.

### 5. Safe Report Parsing & Findings Normalization
- **XXE & Billion Laughs Defense:** Incoming XML reports are checked against size bounds (25 MB limit) and strictly reject `<!DOCTYPE` or `<!ENTITY` definitions.
- **State Validation:** Reports with `scan_run_status` indicating `Running` or `Incomplete` are rejected; parser failures do not mark jobs completed.
- **Evidence Storage:** Raw report XML is stored in `EvidenceStore` with SHA-256 content hashes, establishing immutable provenance.
- **Normalized Findings Model (`vuln_findings` table):**
  - Host, port number, protocol (`tcp`, `udp`).
  - Title, description, solution/mitigation guidance, NVT OID, QOD (Quality of Detection).
  - CVSS score (0.0-10.0), CVSS version, extracted CVE identifiers.
  - Normalized severities: `critical` (CVSS >= 9.0), `high` (7.0-8.9), `medium` (4.0-6.9), `low` (0.1-3.9), `info` (0.0 or Log).
  - Missing severity is honestly marked as `unknown` (never coerced to `low`).
- **Entity Correlation:** Discovered vulnerabilities are correlated into the investigation's `entities` table (`canonical_value`, `metadata_json`).

### 6. Vulnerability Assessment REST API Endpoints
- `GET /api/v1/tools/greenbone/status` — Checks Greenbone GMP service status and daemon compatibility.
- `GET /api/v1/vulnerability-profiles` — Lists approved vulnerability assessment profiles.
- `POST /api/v1/investigations/{id}/vulnerability-assessments` — Dispatches an authorized scan job (requires `vulnerability.scan`).
- `GET /api/v1/investigations/{id}/vulnerability-assessments` — Lists assessment jobs for an investigation.
- `GET /api/v1/vulnerability-assessments/{job_id}` — Gets status, progress, and metadata for a scan job.
- `POST /api/v1/vulnerability-assessments/{job_id}/cancel` — Cancels a running or queued assessment job.
- `GET /api/v1/vulnerability-assessments/{job_id}/findings` — Retrieves normalized vulnerability findings.
- `GET /api/v1/vulnerability-assessments/{job_id}/report` — Downloads raw Greenbone XML report evidence with `X-Content-Hash`.

---

## 8. Database Migrations

Apply Alembic migrations to upgrade the database schema:

```bash
# Upgrade to latest revision (creates all database tables)
python -m alembic upgrade head

# Rollback one revision if necessary
python -m alembic downgrade -1

# Inspect current schema revision
python -m alembic current
```

---

## 9. Running the Automated Test Suite

The test suite runs against isolated, temporary SQLite databases with mock network fixtures (zero live external network calls during pytest):

```bash
python -m pytest tests -v
```

### Test Summary: **151 Passed, 0 Failed (100% Success)**
- **Knowledge Graph GraphML Export (`tests/test_graphml_export.py`):** 6 tests validating GraphML XML document construction, directed edges, node schemas for investigation/entities/hosts/ports/vulnerabilities, XML entity escaping (defense against XXE and script injection), empty investigation handling, authorized web streaming download, and API Bearer token authorization checks.
- **Dashboard & Workflows (`tests/test_dashboard_phase7.py`):** Executive overview metrics, search query and status filtering, campaign creation form with CSRF validation, investigation detail workspace with tabbed navigation, unified findings matrix filtering, live scans monitor, forensic evidence ledger with SHA-256 hashes, security audit trail, and administrative target authorizations & scanner diagnostics.
- **Consolidated PDF Reporting (`tests/test_pdf_report.py`):** ReportLab Platypus multi-page binary PDF generation, NumberedCanvas header/footer with page numbers, genuine database records ingestion, honest empty-state handling without crashes, and authorized streaming download endpoint (`GET /investigations/{id}/report/pdf`).
- **Greenbone Client & Diagnostics (`tests/test_greenbone_client.py`):** Unconfigured detection, network connection errors (`UNAVAILABLE`), TLS verification failure handling, invalid credentials (`AUTHENTICATION_FAILED`), version parsing, approved profile lookups.
- **Greenbone XML Report Parser (`tests/test_greenbone_xml_parser.py`):** Real sample report parsing (`gvm-imp-31efbea759.xml`), Log4Shell CVE and CVSS 9.8 extraction, empty report handling, in-progress report rejection, malformed XML handling, XXE entity injection defense, 25MB size limit enforcement, severity normalization rules, port/protocol parsing, deduplication key generation.
- **Vulnerability Orchestrator & Authorization (`tests/test_vulnerability_runner.py`):** Out-of-scope target rejection, missing authorization rejection, active-only authorization rejection (`SCAN_VULN` required), expired authorization rejection, successful end-to-end execution, evidence persistence with SHA-256 hash, normalized finding persistence, entity correlation, task cancellation flow.
- **Vulnerability REST API & RBAC (`tests/test_vulnerability_api.py`):** Unauthenticated 401 rejection, tool diagnostic status endpoint, profiles listing, analyst and viewer 403 forbidden rejection (`vulnerability.scan` required), unauthorized target 403 rejection, successful scan dispatch (201), job listing and status retrieval, normalized findings list endpoint, raw report XML evidence download.
- **Active Nmap Reconnaissance (`tests/test_nmap_*.py`):** 33 tests verifying binary detection, argument allowlisting (`shell=False`), XML parser, evidence persistence, host and port normalization.
- **Passive OSINT Orchestration (`tests/test_collectors.py`, `tests/test_passive_recon_orchestrator.py`):** 14 tests verifying RDAP, DNS, theHarvester, crt.sh, entity normalization, and deduplication.
- **Authentication, RBAC & Core (`tests/test_auth.py`, `tests/test_rbac.py`, `tests/test_csrf_and_cookies.py`, etc.):** 46 tests verifying Argon2id password hashing, session tokens, audit logging, CSRF defense, and database integrity.

---

## 10. Phase 7 & 8: Web Dashboard, Reporting & GraphML Export Architecture

FootprintIQ provides a complete, responsive, light-theme cybersecurity dashboard rendered entirely via **Jinja2 + HTMX** (eliminating React, TypeScript, and Node.js at runtime):

### Available Pages & User Workflows:
1. **Overview Dashboard (`/`):** Real-time database metrics (investigations, assets, open ports, vulnerabilities), recent investigations workspace table, and live scanner readiness diagnostics.
2. **Investigations Campaign Index (`/investigations`):** Search by keyword, filter by status (`active`, `completed`, `archived`), and modal for registering new campaigns with target scope boundaries.
3. **Investigation Detail Workspace (`/investigations/{id}`):**
   - **Overview & Scope:** Scope apex domains, approved CIDRs/IPs, active targets allowlist, and investigator team.
   - **Target Authorizations:** Explicit allowlist records covering `SCAN_PORTS` and `SCAN_VULN` operations.
   - **Passive OSINT & Entities:** Harvested DNS records, RDAP/WHOIS disclosures, and normalized entities (emails, subdomains, persons). Includes collector dispatch trigger.
   - **Active Nmap Reconnaissance:** Enumerated open ports, states, services, fingerprints, and versions with vetted profile selector (`nmap-service-detect`, `nmap-quick`, `nmap-conservative`).
   - **Vulnerability Assessment:** Greenbone findings matrix with severity pills, CVSS scores, CVE references, NVT OID, and remediation solution guidance with approved profile selector (`openvas-basic`, `openvas-full-and-fast`, `openvas-discovery`).
   - **Forensic Evidence:** Preserved raw artifacts with true SHA-256 integrity digests and byte sizes.
   - **Execution Jobs:** Real-time job monitor for passive, active, and vulnerability scan pipelines with status badges and cooperative cancellation triggers.
   - **Score & Report:** 5-factor Exposure Score breakdown ($0.20 \cdot P + 0.15 \cdot D + 0.25 \cdot S + 0.35 \cdot V + 0.05 \cdot C$), one-click ReportLab PDF dossier generation, and GraphML XML export.
4. **Unified Findings Matrix (`/findings`):** Comprehensive table of all vulnerabilities and port exposures across campaigns with severity and campaign filters.
5. **Reconnaissance & Scan Monitor (`/scans`):** Central execution hub tracking all running, completed, and queued jobs.
6. **Forensic Evidence Ledger (`/evidence`):** Central browser for all preserved raw artifacts with SHA-256 hashes.
7. **Security Audit Trail (`/audit`):** Chronological ledger of security-critical actions, logins, target authorizations, and scans.
8. **Administrative Control Center (`/admin/authorizations`, `/admin/tools`):**
   - Target allowlist management and immediate revocation controls.
   - Real-time scanner diagnostics for Nmap (local executable discovery) and Greenbone GVM (GMP protocol availability).

### Multi-Format Export Capabilities:
- **Consolidated PDF Report Dossier (`/investigations/{id}/report/pdf`):** Generated via **ReportLab Platypus** with `NumberedCanvas` (headers, footers, total page counts). 17 structured sections covering scope, authorizations, executive summary, 5-factor score breakdown, entity inventory, Nmap port tables, Greenbone vulnerability matrix, prioritized remediation roadmap, and SHA-256 evidence digests.
- **Knowledge Graph XML Export (`/investigations/{id}/report/graphml` and `/api/v1/investigations/{id}/export/graphml`):** Generates standard GraphML XML representing all entities, network hosts, open ports, and vulnerabilities connected by directed relationship edges (`DISCOVERED_ENTITY`, `RESOLVED_HOST`, `EXPOSES_PORT`, `HAS_VULNERABILITY`). Fully compatible with Gephi, Cytoscape, and Maltego.

---

## 11. Security Guardrails & Production Considerations

1. **Target Authorization Required:** Login alone does not authorize scanning. Every target must be within scope and have an active administrative authorization record explicitly permitting `"SCAN_VULN"` or `"SCAN_PORTS"`.
2. **Operation Isolation:** Permission for passive reconnaissance or active Nmap scanning does not permit vulnerability assessments.
3. **Finding Isolation:** Discovered entities remain findings only; they are never automatically promoted into authorized targets for scans.
4. **No Arbitrary Configurations:** Users cannot supply arbitrary GVM scan config IDs, scanner IDs, or command strings.
5. **No Denial of Service:** Profiles strictly avoid DoS plugins and destructive checks.
6. **HTTPS & Cookie Security:** In production (`APP_ENV=production`), `cookie_secure` evaluates to `True`, forcing `Secure` cookies. Set `SESSION_COOKIE_SECURE=True` in `.env` if terminating SSL behind a reverse proxy.
7. **Secret Redaction:** Command logs, error messages, and audit events never expose API keys, passwords, or session tokens.
8. **No Password Encryption:** Passwords are one-way hashed using Argon2id with RFC 9106 parameters.

---

## 12. Verification & Demonstration Documentation

- **Final Validation & Stabilization Report:** [`docs/phase-8-final-validation-report.md`](../docs/phase-8-final-validation-report.md)
- **Interactive Demonstration Runbook:** [`docs/demo-runbook.md`](../docs/demo-runbook.md)
- **Phase 1 Migration Audit & Matrix:** [`docs/phase-1-migration-audit.md`](../docs/phase-1-migration-audit.md)



