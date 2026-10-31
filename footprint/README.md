# FootprintIQ: OSINT Recon Toolkit — Digital Footprint Investigator

**Phase 2 Deliverable — Backend, Persistence, Evidence Ingestion & Passive Reconnaissance**

### Project Research Team
- **Asip Ali**, Student ID: `251347048` (Lead Investigator & Platform Architect)
- **Mohan Prasad**, Student ID: `251347070` (Analyst & Security Engineer)

---

## 1. Project Purpose & Scope

FootprintIQ is an educational and authorized cybersecurity reconnaissance management platform. It assists security analysts and lab students in collecting, importing, organizing, correlating, scoring, and reporting information about a team-controlled dummy company (**NorthStar Analytics Lab**), owned domain (`lab.example`), or isolated lab host (`192.168.56.102`).

The platform enforces a strict boundary between:
1. **Passive Reconnaissance**: Querying third-party registries, authoritative DNS, theHarvester dumps, and indexed search records without sending direct probe packets to the target.
2. **Active Reconnaissance**: Ingesting Nmap XML and OpenVAS vulnerability assessments, which are **strictly rejected by server-side policy** unless the target IP is verified on an explicit authorization allowlist.

---

## 2. Phase 2 Architecture & Server Engine

```
├── server.ts                   # Express full-stack runtime mounting /api/v1 + Vite middlewares
├── src/
│   ├── server/                 # Dedicated Backend Architecture
│   │   ├── db/                 # Atomic persistence layer
│   │   │   ├── database.ts     # ServerDatabase with automatic disk flushing & memory cache
│   │   │   └── repositories.ts # 15 Server-side repositories (users, investigations, scopes, etc.)
│   │   ├── services/           # Security & Reconnaissance Domain Services
│   │   │   ├── scopeValidator.ts # IP/CIDR/Domain syntax checks, re-resolution, allowlist enforcement
│   │   │   ├── passiveRecon.ts   # Node DNS promises & RDAP RFC 7480 client with token bucket
│   │   │   ├── normalizer.ts     # Canonical evidence formatting & auto graph relationship linking
│   │   │   └── parsers/
│   │   │       ├── nmapParser.ts      # XXE-safe Nmap XML parser (-oX)
│   │   │       ├── openvasParser.ts   # XXE-safe OpenVAS/GVM XML parser
│   │   │       └── harvesterParser.ts # theHarvester JSON & XML parser
│   │   ├── routes/
│   │   │   └── api.ts          # Versioned REST API (/api/v1) with RBAC middleware
│   │   └── tests/
│   │       └── runAllTests.ts  # Automated test suite (34 unit & integration tests)
│   ├── types/                  # Shared data models, Zod validation schemas
│   ├── context/
│   │   ├── AuthContext.tsx     # RBAC session & demo role switching (Admin, Investigator, Reviewer, Viewer)
│   │   └── InvestigationContext.tsx # Client store connecting to /api/v1 with offline fallback
│   ├── components/             # Reusable UI components & Auth/AccessDenied banners
│   └── pages/                  # 12 Operational views
```

---

## 3. Role-Based Access Control (RBAC)

The system enforces 4 discrete roles on both client and server:
- **Admin** (`admin@footprintiq.lab` - Asip Ali): Full platform configuration, user administration, investigation management, and scan ingestion.
- **Investigator** (`investigator@footprintiq.lab` - Mohan Prasad): Creates investigations, executes RDAP & DNS queries, imports allowlisted XML scans.
- **Reviewer** (`reviewer@footprintiq.lab` - Dr. Marcus Vance): Reviews findings, alters vulnerability triage statuses, audits exposure scores, and signs off reports.
- **Viewer** (`viewer@footprintiq.lab` - Auditor Guest): Read-only access to completed investigations, reports, and knowledge graphs. Any data modification returns a `403 Access Denied`.

Use the user profile menu in the top right to instantly switch demo accounts and test server-side permission barriers.

---

## 4. Server API Endpoints (`/api/v1`)

| Method | Endpoint | Description | Role Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Health check & collector subsystem statuses | Public |
| `POST` | `/api/v1/auth/login` | Session login with demo credentials | Public |
| `GET` | `/api/v1/auth/me` | Current authenticated user profile | Authenticated |
| `GET` | `/api/v1/investigations` | List all investigations | Any Role |
| `POST` | `/api/v1/investigations` | Register new authorized investigation | Admin, Investigator |
| `GET` | `/api/v1/investigations/:id` | Fetch investigation by ID | Any Role |
| `PATCH` | `/api/v1/investigations/:id` | Update investigation metadata/status | Admin, Investigator, Reviewer |
| `DELETE` | `/api/v1/investigations/:id` | Delete investigation and artifacts | Admin |
| `POST` | `/api/v1/investigations/:id/validate-scope` | Server-side IP, CIDR, and domain validation | Any Role |
| `POST` | `/api/v1/investigations/:id/collect/rdap` | Safe RDAP query with rate limiting and cache | Admin, Investigator |
| `POST` | `/api/v1/investigations/:id/collect/dns` | Authoritative DNS resolution (A, AAAA, MX, NS, TXT) | Admin, Investigator |
| `POST` | `/api/v1/investigations/:id/evidence/manual` | Log manual search engine leak observation | Admin, Investigator, Reviewer |
| `POST` | `/api/v1/investigations/:id/import/harvester` | Ingest theHarvester JSON/XML export | Admin, Investigator |
| `POST` | `/api/v1/investigations/:id/import/nmap` | Ingest Nmap XML (validates active allowlist) | Admin, Investigator |
| `POST` | `/api/v1/investigations/:id/import/openvas` | Ingest OpenVAS XML (validates active allowlist) | Admin, Investigator |
| `GET` | `/api/v1/investigations/:id/entities` | Correlated knowledge graph entities | Any Role |
| `GET` | `/api/v1/investigations/:id/findings` | Triage findings matrix | Any Role |
| `GET` | `/api/v1/investigations/:id/score` | Live calculated Exposure Score breakdown | Any Role |
| `GET` | `/api/v1/investigations/:id/audit` | Chronological tamper-evident audit ledger | Any Role |

---

## 5. Security & XXE Protections

1. **XXE Elimination**: XML parsers (`fast-xml-parser`) are configured with `processEntities: false`, ignoring external entity tags (`<!ENTITY`, `SYSTEM`) and blocking file disclosure or SSRF attacks.
2. **Deterministic Active Allowlist**: Active XML ingests compare extracted hosts against `scope.activeTargets` and `scope.approvedCIDRs`. Out-of-scope hosts trigger a `403 Forbidden` response and log an audit event.
3. **No Browser Command Execution**: Shell commands, raw socket scans, and unauthorized HTTP probes are not executed from the browser.

---

## 6. Testing Instructions

Run the automated test suite from the terminal:
```bash
npm test
```
The suite verifies:
- IPv4, IPv6, FQDN, and CIDR subnet syntax algorithms
- Active scope allowlist enforcement and authorization expiration checks
- XXE entity injection rejection in Nmap and OpenVAS parsers
- Parsing and extraction of ports, services, CVEs, and CVSS ratings
- theHarvester email and subdomain extraction
- Canonical normalization and relationship deduplication
- RBAC permissions for all 4 roles

---

## 7. Required Environment Variables

Defined in `.env.example`:
- `PORT`: Server port (defaults to `3000`).
- `NODE_ENV`: Set to `development` or `production`.
- `APP_URL`: Base application URL for self-referential links.

---

## 8. Database Setup Instructions

Phase 2 uses an atomic, disk-persisted database engine stored at `.data/footprintiq_db.json`.
- In development mode, the database automatically boots with the **NorthStar Analytics Lab** baseline.
- Data persists across server restarts and page refreshes.
- To reset database state, click "Reset Demo Local Storage" in **Settings** or delete `.data/footprintiq_db.json`.
- The repository layer follows Clean Architecture interfaces (`IInvestigationRepository`, etc.), ready for Firestore or PostgreSQL in Phase 3.

---

## 9. Remaining Limitations

- **Phase 3 Remote Worker**: Real network port probing against physical remote networks is gated for Phase 3 behind mutual-TLS (mTLS) worker agents.
- **Search Scraping Policy**: Search engine queries are logged via the Manual Evidence form; direct automated scraping of search engines is blocked to prevent IP blacklisting.
