# FootprintIQ — Final Automated Test Execution Report

**Execution Timestamp:** October 2026  
**Test Runner:** `pytest 7.4.4` / `pytest-asyncio 0.23.3` / `anyio 4.13.0`  
**Environment:** Python 3.11.9 (Windows 11 x64)  
**Total Tests:** **171**  
**Passed:** **171** (100%)  
**Failed:** **0**  
**Skipped:** **0**  
**Blocked:** **0**  

---

## 1. Test Execution Command

The entire test suite was executed in the `python_app` workspace using:

```bash
python -m pytest tests/ -v
```

---

## 2. Test Suite Breakdown by Module

| Test Module | Coverage Scope | Tests | Result |
|---|---|:---:|:---:|
| `tests/test_auth.py` | Login, password hashing, sessions, cookie expiration, open redirect defense, self-service public signup, and demo provisioning | **15** | **15 PASS** |
| `tests/test_database.py` | Models, relationships, cascades, WAL journal mode, and transaction rollbacks | **11** | **11 PASS** |
| `tests/test_error_handling_and_config.py` | 404/422/500 handlers, sanitized validation error schemas, and config overrides | **12** | **12 PASS** |
| `tests/test_graphml_export.py` | Investigation entity graph exporter, XML topology schema, and host/domain nodes | **7** | **7 PASS** |
| `tests/test_greenbone_api.py` | Vulnerability assessment routes, target authorization, and GVM task polling | **9** | **9 PASS** |
| `tests/test_greenbone_xml_parser.py` | DefusedXML report parser, XXE rejection, and CVE severity normalization | **8** | **8 PASS** |
| `tests/test_health.py` | Liveness (`/health/live`), readiness (`/health/ready`), and database connection checks | **4** | **4 PASS** |
| `tests/test_migrations.py` | Alembic schema migrations, downgrade, and upgrade verification | **2** | **2 PASS** |
| `tests/test_nmap_api.py` | Nmap scanning API routes, scan profile dispatch, and status tracking | **8** | **8 PASS** |
| `tests/test_nmap_detector.py` | Subprocess detection of local Nmap binary, error codes, and timeout limits | **5** | **5 PASS** |
| `tests/test_nmap_runner.py` | Target scope enforcement, active scan authorization checks, and execution timeouts | **7** | **7 PASS** |
| `tests/test_nmap_xml_parser.py` | XML parsing of real Nmap output, port/service ingestion, and entity safety | **10** | **10 PASS** |
| `tests/test_passive_recon_orchestrator.py` | DNS, RDAP, WHOIS collection, failure isolation, and entity deduplication | **5** | **5 PASS** |
| `tests/test_pdf_report.py` | ReportLab PDF compilation, evidence hash inclusion, and download endpoints | **4** | **4 PASS** |
| `tests/test_rbac.py` | Role-based authorization matrix (`administrator`, `analyst`, `viewer`) and IDOR prevention | **7** | **7 PASS** |
| `tests/test_target_authorization.py` | IP/domain classification, CIDR scope evaluation, and time-bounded approvals | **3** | **3 PASS** |
| `tests/test_vulnerability_api.py` | Vulnerability assessment endpoints, job creation, and report downloading | **8** | **8 PASS** |
| `tests/test_vulnerability_runner.py` | Greenbone scan orchestrator, authorization checks, and task cancellation | **7** | **7 PASS** |
| `tests/test_landing.py` | Public landing page rendering, navigation anchors, feature integrity, and route protection | **12** | **12 PASS** |
| `tests/test_dashboard.py` | Initial dashboard shell, empty state, and health badge component | **3** | **3 PASS** |
| `tests/test_dashboard_phase7.py` | Executive dashboard metrics, investigation filters, CSRF defense, and admin tools | **11** | **11 PASS** |
| **TOTAL** | **Entire Application Surface** | **171** | **171 PASS (100%)** |

---

## 3. End-to-End Workflow Verification

In addition to automated unit and integration tests, direct end-to-end verification was conducted against the live application:

1. **Demo Account Provisioning:**
   - Ran `python scripts/provision_demo_account.py --reset --password "DemoInvestigator2026!#"`.
   - Verified that user was created with Argon2id password hash `$argon2id$...`.
   - Verified that user cannot access administrator-only routes (`/admin/users`, `/api/v1/users`).
2. **Web Browser Login & Session Issuance:**
   - Acquired CSRF cookie from `GET /login`.
   - Submitted credentials via `POST /auth/login`.
   - Verified 303 redirect to `/` with HTTP-only session cookie `footprintiq_session` and updated CSRF token.
3. **Open Redirect Defense:**
   - Attempted malicious redirects with `?next=//attacker.com/steal`, `?next=/\attacker.com`, `?next=javascript:alert(1)`.
   - All vectors were rejected; application redirected safely to `/`.
4. **Self-Service Registration:**
   - Tested public signup via web form (`POST /auth/signup`) and REST API (`POST /api/v1/auth/signup`).
   - Verified that accounts are strictly provisioned with `role="analyst"`, never administrator.
   - Verified that duplicate username or email attempts return HTTP 409 Conflict.
5. **Session Revocation:**
   - Submitted `POST /auth/logout` with valid CSRF token.
   - Verified session was invalidated in database and deleted from cookies.
   - Subsequent access to protected pages was redirected to `/login`.

---

## 4. Final Limitations & Environment Notes

- **Nmap Local Binary:** Active port scanning requires an authorized lab target (`127.0.0.1` or internal RFC 1918 range). Scans against unauthorized targets are rejected server-side.
- **Greenbone / OpenVAS:** In environments without an active GVM socket, the application reports `NOT CONFIGURED` honestly without fabricating simulated vulnerability findings.
- **Legacy V1 Source:** The original React/TypeScript source code in `src/` and `server.ts` remains intact and unmodified.
