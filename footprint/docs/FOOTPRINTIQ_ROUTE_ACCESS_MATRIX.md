# FootprintIQ Route Access Matrix

Date: 2026-10-28. Runtime audited: `python_app` FastAPI application (Jinja2/HTMX UI). The legacy Vite/Express prototype under the repository root is not the runtime selected by the Python app README.

| Route or endpoint | Expected access | Enforcement | Verification |
|---|---|---|---|
| `GET /`, `/login`, `/signup`; `POST /auth/login`, `/auth/signup` | Public | Explicit public allowlist; CSRF on browser form posts; signup grants least-privileged role | Public landing/login tested; automated auth tests |
| `POST /auth/logout` | Authenticated | Session resolved, server session invalidated, CSRF checked for cookie requests | Auth/session and CSRF tests |
| `/static/*`, `/health/*` (HTML badge), `/api/v1/health*` | Public/service health | Static mount and health handlers | Static, landing and health tests |
| `GET /dashboard`, `/investigations[/{investigation_id}]`, `/findings`, `/scans`, `/evidence` | Authenticated | Central HTTP middleware validates server-side session before handlers; anonymous browser requests redirect to `/login?next=...` | Parametrized anonymous route tests; live HTTP checks |
| `POST /investigations`, `/investigations/{id}/authorizations`, `/investigations/{id}/recon/passive`, `/investigations/{id}/scans/{nmap,vuln}`, `/scans/vuln/{job_id}/cancel` | Authenticated + role permission + target authorization where scanning | Central session gate; permission checks; CSRF; scan authorization services | Existing RBAC, CSRF, target-authorization, Nmap, recon and vulnerability tests |
| `GET /investigations/{id}/report/{pdf,graphml}` | Authenticated; report permission applies in API export | Central session gate; investigation existence checked by handler | PDF/GraphML tests, including authenticated download |
| `GET /audit`, `/admin/*`; `POST /admin/authorizations/{id}/revoke` | Administrator | Central session gate and administrator role check; state-changing forms require CSRF | Admin page/revocation tests; non-admin denial enforced at middleware |
| `/api/v1/auth/login`, `/api/v1/auth/signup` | Public | Credential validation / signup policy | Auth tests |
| `/api/v1/auth/me`, `/api/v1/auth/logout` | Authenticated | Session/Bearer validation; cookie CSRF for state changes | Auth and CSRF tests |
| `/api/v1/investigations*`, `/api/v1/users*`, `/api/v1/audit-logs*` | Authenticated; roles/permissions per operation | Server dependencies; users and audit endpoints administrator-only; investigation view/create permissions | RBAC, API, audit tests; anonymous request returns 401 |
| `/api/v1/recon*`, `/api/v1/authorizations*`, `/api/v1/nmap*`, `/api/v1/vulnerability*` | Authenticated + operation permission; active target authorization for active scans | Server dependencies and target authorization services | API authorization and workflow tests |
| `/docs`, `/redoc`, `/openapi.json` | Development only | FastAPI docs disabled in production | Configuration inspected; production behavior not deployed here |
| Unknown paths | Public router resolution (normally 404) | Not classified as an operational route by auth middleware | Unknown path regression test |

Resource ownership: the current database model and API expose investigation records as shared workspace data and have no investigation owner field. Cross-user owner isolation is therefore not implemented or claimed; role permissions protect operations. Add ownership/tenant fields and migration before using this as a multi-tenant service.

Internal/background workers are not HTTP routes. Scanner APIs still require authenticated users and explicit target authorization. Greenbone requires an external GVM service; unavailable service is reported as not configured/unavailable, not simulated as success.
