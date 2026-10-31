# FootprintIQ Final Application Audit

**Audit date:** 2026-10-28 (Asia/Kolkata)  
**Audited runtime:** `python_app` (FastAPI, SQLAlchemy, Jinja2/HTMX)  
**Readiness:** Suitable for local development demonstration after the access-control repair. Production readiness is not established.

## 1. Executive summary

The repository contains a legacy React/Express prototype and a later Python application. The Python app README identifies the FastAPI service as the current application. Its API routes had server-side authentication and RBAC dependencies, but operational web dashboard routes were inconsistent: several relied on `get_current_user_optional`, then queried or changed data even when it returned `None`. I added a central web request boundary, role/permission gates for dashboard administration and state-changing operations, and regression coverage. The public landing and authentication entry pages remain available.

The full Python suite now passes: **181 passed, 0 failed**. Live HTTP checks against `http://127.0.0.1:8000` verified public landing/login and health, redirects for protected pages, and JSON 401 for protected API calls. Database connectivity was confirmed by Uvicorn startup. No known original HTTP 500 was supplied with a reproducible request; tests exercise sanitized 422 and 500 handling. This is not evidence that every external integration or all production workflows are available.

## 2. Initial findings

| Severity | Finding | Root cause and evidence | Repair |
|---|---|---|---|
| High | Anonymous access to operational dashboard pages/actions | In `app/api/web_dashboard.py`, multiple handlers used optional-user lookup without consistently rejecting `None`; e.g. list/detail/report paths proceeded to database queries, while some actions used fallback actor identities. Live pre-fix `/investigations` returned 200 and exposed rendered operational data. | Central HTTP middleware now resolves sessions and redirects anonymous operational browser requests. It rejects anonymous API calls with structured 401 JSON. |
| High | Dashboard admin functions lacked consistent role gates | `/admin/*` and `/audit` routes lacked centralized role enforcement. | Administrator role required for admin/audit pages; browser write operations check required permissions. API routes keep their own role/permission dependencies. |
| Medium | Operational route tests encoded unauthenticated access as expected behavior | Dashboard/report test cases called protected routes anonymously, masking the defect. | Updated workflow tests to use server-issued sessions; added anonymous route matrix and unknown-route checks. |
| Informational | Global `DEBUG=release` prevents Pydantic settings initialization | The host process environment contains a non-boolean value for `DEBUG`; ordinary pytest startup failed before tests loaded. | Verification commands explicitly set `DEBUG=false`. The global environment was not changed. |

No particular HTTP 500 request was present in the brief or independently reproduced. The application has centralized sanitized exception handling; validation tests verify 422 and unexpected-exception tests verify 500 without returning exception secrets.

## 3. Authentication and authorization audit

See [FOOTPRINTIQ_ROUTE_ACCESS_MATRIX.md](FOOTPRINTIQ_ROUTE_ACCESS_MATRIX.md) for the examined route families and enforcement/test details. Verified anonymously: `/` and `/login` return 200; representative protected pages redirect to `/login?next=...`; `/api/v1/health` returns 200 JSON; `/api/v1/investigations` and `/api/v1/auth/me` return 401 JSON. Existing tests cover valid login, invalid credentials, logout invalidation, CSRF, session expiry, role checks, scan permissions, target allowlisting, and authenticated report downloads.

Investigation records are currently a shared workspace; the data model does not carry an owner/tenant field. The audit does not claim cross-user owner isolation. Multi-tenant deployment requires an ownership model and migration.

## 4. HTTP 500 audit

No reproducible 500 defect was supplied. Executed tests confirm malformed request validation is sanitized as 422 and an injected unexpected exception returns sanitized 500 without exposing stack traces or secret text. PDF/GraphML and scan/recon workflow tests pass. External Greenbone failure modes are isolated and represented as unavailable/not configured; a live GVM server was not available for end-to-end verification. No 500 has been suppressed or misreported as repaired.

## 5. Functional module audit

| Module | Status | Evidence / limitation |
|---|---|---|
| Public landing and login | Verified locally | Live HTTP 200 |
| Sessions, password hashing, CSRF, RBAC | Verified by automated suite | Auth, role, cookie, audit tests |
| Investigation UI and API | Verified in tests | Authenticated workflow tests; shared workspace semantics |
| Passive reconnaissance | Verified with isolated fixtures | No claim of unrestricted external-provider availability |
| Nmap | Implemented and test-verified | Live scan depends on local Nmap and authorized target |
| Greenbone/OpenVAS | Partially verified | Client/parser/workflow tests; no configured daemon confirmed live |
| Evidence normalization/storage | Test-verified | Evidence and parser tests |
| Exposure scoring | Test-verified | Dashboard/scoring tests |
| PDF and GraphML exports | Test-verified | Authenticated download tests |
| Audit log | Test-verified | Audit tests; admin-only UI/API policy |
| Database | Local connectivity verified | Existing SQLite database preserved; no reset performed |

## 6. Database and data integrity

Uvicorn startup confirmed SQLite connectivity. The existing `python_app/footprintiq.db` and its WAL files were preserved; no destructive initialization or migration command was run. Isolated test databases were used by pytest. Database restart/persistence behavior is covered by existing tests, but I did not restart the service after writing application records in the user's existing database.

## 7. Security findings

- **High, repaired:** anonymous access to operational dashboard paths; centralized session checks now run before operational handlers.
- **High, repaired:** anonymous API access remains rejected by server dependencies and is also covered by request-boundary checks. API errors are JSON 401 rather than login HTML.
- **Medium, repaired:** role enforcement for dashboard admin/audit routes and permissions for browser state-changing operations.
- **Informational, unresolved by design:** no resource-owner/tenant data model exists, so the app is a shared workspace, not a multi-tenant system.
- **Informational, deployment:** production must supply a strong `SECRET_KEY`, HTTPS, secure cookies, trusted-host configuration, and external service credentials as applicable.

## 8. Test results

| Check | Command/method | Result | Evidence / limitation |
|---|---|---|---|
| Python test suite | `$env:DEBUG='false'; python -m pytest tests -q` from `python_app` | **181 passed** | 7 warnings: upstream deprecations, one SQLAlchemy transaction warning, and unawaited coroutine warnings in mocked scan paths |
| Public page and auth entry | Live HTTP GET | 200 | `127.0.0.1:8000` |
| Protected browser route set | Live HTTP GET | 303 to login | Dashboard, investigations, findings, scans, evidence, audit, admin, report route |
| Protected API | Live HTTP GET | 401 JSON | Investigations and auth/me |
| Health endpoint | Live HTTP GET | 200 JSON | Public service health |
| Startup/database | Uvicorn lifespan logs | Passed | Startup logged SQLite connectivity confirmed |
| Production build / legacy Node app | Not run | Not applicable to selected runtime | Python app README designates FastAPI runtime; legacy prototype remains in source |
| GVM live scan / external OSINT | Not run | Environment dependent | No external service credentials/daemon confirmed |

## 9. Files changed

- `python_app/app/main.py` — centralized operational route session enforcement, API JSON 401 behavior, admin role checks, and browser action permission gates.
- `python_app/tests/conftest.py` — authenticated analyst/admin browser-client fixtures.
- `python_app/tests/test_dashboard_phase7.py`, `test_graphml_export.py`, `test_pdf_report.py`, `test_error_handling_and_config.py` — exercise protected browser workflows with real sessions.
- `python_app/tests/test_landing.py` — anonymous protection coverage for operational pages and unknown-route 404 behavior.
- `docs/FOOTPRINTIQ_ROUTE_ACCESS_MATRIX.md` — route classification and enforcement matrix.
- `docs/FOOTPRINTIQ_FINAL_APPLICATION_AUDIT.md` — this evidence-based audit.

## 10. Local setup and recovery

From `python_app`, use Python 3.11+, install the package dependencies from `pyproject.toml`, then run:

```powershell
$env:DEBUG='false'
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/`; login is at `/login`. Provision an administrator using the documented `python scripts/create_admin.py` workflow. For tests, use `$env:DEBUG='false'; python -m pytest tests -q`. Do not use the existing production-like DB for tests. Greenbone requires a separately configured GVM endpoint. The local service is currently running at `http://127.0.0.1:8000`.

## 11. Remaining issues and recommendations

- Add investigation ownership/tenant boundaries before serving multiple customer organizations.
- Fix the async scan test warnings and update deprecated Starlette/httpx dependencies when convenient.
- Validate GVM against a real configured daemon and validate Nmap only against a specifically authorized lab target.
- Review deployment secrets, HTTPS proxy configuration, backups, rate limits, and operational monitoring before production deployment.
- Audit the legacy React/Express prototype separately if it is intended to remain deployable; it is not the selected local runtime.

## 12. Final readiness assessment

| Area | Assessment |
|---|---|
| Authentication and access control | Verified for central browser gate and API auth/RBAC tests; owner isolation unavailable because model is shared-workspace |
| HTTP error handling | Sanitized 422/500 behavior verified; no original 500 reproducer supplied |
| Functional correctness | 181 automated tests pass; external services not fully live-verified |
| Tool integration | Nmap/GVM test coverage present; GVM live dependency not confirmed |
| Database reliability | Local SQLite connectivity confirmed; existing data preserved |
| Test coverage | Good automated coverage with 7 warnings; no claim of exhaustive coverage |
| Local deployment | Running and live HTTP access checks pass |
| Production deployment | Not ready to claim; tenant isolation and deployment-specific security/service checks remain |
