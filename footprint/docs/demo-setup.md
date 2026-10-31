# FootprintIQ — Local Demo Setup & Provisioning Guide

This document provides exact, reproducible steps to initialize, configure, provision, and run **FootprintIQ — Digital Footprint Investigator** locally for demonstration and evaluation.

---

## 1. Prerequisites

- **Operating System:** Windows 10/11, Linux, or macOS.
- **Python Version:** Python 3.11+ (Python 3.11.9 verified).
- **Package Manager:** `pip` or `uv`.
- **Optional Tools:** Nmap 7.90+ (required only if demonstrating live active network scanning against local lab targets).

---

## 2. Environment Configuration

Navigate to the `python_app` directory:
```bash
cd footprint/python_app
```

Create or verify the `.env` configuration file:
```ini
APP_NAME=FootprintIQ
APP_ENV=development
DEBUG=True
LOG_LEVEL=INFO

# Database
DATABASE_URL=sqlite:///./footprintiq.db

# Authentication & Sessions
SESSION_COOKIE_NAME=footprintiq_session
CSRF_COOKIE_NAME=footprintiq_csrf
SESSION_MAX_AGE_SECONDS=86400
COOKIE_SECURE=False

# Self-Service Registration
ALLOW_PUBLIC_SIGNUP=True
DEFAULT_SIGNUP_ROLE=analyst

# Active Tool Integrations
NMAP_PATH=nmap
NMAP_TIMEOUT_SECONDS=300
GREENBONE_HOST=127.0.0.1
GREENBONE_PORT=9390
```

---

## 3. Database Initialization & Migrations

Ensure database tables and schema are applied using Alembic:
```bash
python -m alembic upgrade head
```
*Note: SQLite database is configured with Write-Ahead Logging (`WAL`) mode for robust concurrency.*

---

## 4. Demo Account Provisioning

Run the automated provisioning script:
```bash
python scripts/provision_demo_account.py --reset --password "DemoInvestigator2026!#"
```

### Verified Demo Credentials:
- **Username:** `demo_analyst`
- **Email:** `demo@footprintiq.local`
- **Password:** `DemoInvestigator2026!#`
- **Role:** `ANALYST` (Least-Privileged Security Analyst)
- **Permissions:**
  - Create, view, and update authorized investigations (`investigation.create`, `investigation.view`)
  - Execute passive OSINT collection (`recon.passive`)
  - View findings, raw evidence, and export audit trails (`report.view`, `report.export`)
  - **Administrative controls strictly restricted:** Cannot access `/api/v1/users` or modify system settings.

### Custom or Dynamic Passwords:
To generate a random cryptographically secure password meeting complexity criteria:
```bash
python scripts/provision_demo_account.py --reset
```
The script will output the generated password directly in the terminal and verify live login against the database.

---

## 5. Starting the Application

Launch the FastAPI application using Uvicorn:
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The application is now accessible at:
- **Public Homepage (Landing Page):** [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Executive Dashboard (Authenticated):** [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)
- **Login Page:** [http://127.0.0.1:8000/login](http://127.0.0.1:8000/login)
- **Self-Service Registration:** [http://127.0.0.1:8000/signup](http://127.0.0.1:8000/signup)
- **API Documentation (Swagger UI):** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check:** [http://127.0.0.1:8000/api/v1/health/ready](http://127.0.0.1:8000/api/v1/health/ready)

---

## 6. Demonstration Workflow

1. **Sign In:**
   - Open `http://127.0.0.1:8000/login`.
   - Enter `demo_analyst` and `DemoInvestigator2026!#`.
   - Click **Sign In**.
2. **Dashboard Overview:**
   - View real metrics (active investigations, verified findings, risk distribution).
   - Inspect recent audit trail records.
3. **Investigation Workflow:**
   - Navigate to **Investigations** and click **New Investigation**.
   - Input an authorized target domain or IP (e.g. `example.com` or `127.0.0.1`).
   - Define scope and permitted operations.
4. **Passive OSINT Collection:**
   - Trigger passive reconnaissance (RDAP domain lookup, DNS enumeration).
   - Review ingested DNS records and WHOIS registrant details in **Evidence**.
5. **Report Generation:**
   - Click **Generate Report** to produce an executive PDF report and GraphML topology export.
6. **Sign Out:**
   - Click user profile / **Sign Out** to verify session revocation and redirection to `/login?logged_out=1`.

---

## 7. Troubleshooting

| Issue | Cause | Solution |
|---|---|---|
| `401 Unauthorized` | Incorrect credentials | Re-run `python scripts/provision_demo_account.py --reset --password "DemoInvestigator2026!#"` |
| `CSRF Validation Failed` | Stale browser cookie | Clear browser cookies or open `http://127.0.0.1:8000/login` in an Incognito window |
| `OpenVAS Not Configured` | OpenVAS daemon is offline | Normal behavior. Greenbone displays `NOT CONFIGURED` honestly without fabricating data. |
| `Nmap executable not found` | Nmap not in system `PATH` | Passive recon works independently; install Nmap or add to PATH if testing active scans. |
