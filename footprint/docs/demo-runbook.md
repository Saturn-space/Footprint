# FootprintIQ — Demonstration Runbook & Presentation Guide
**Platform:** Digital Footprint Investigator (Python FastAPI & Jinja2 Architecture)  
**Target Environment:** Isolated Security Laboratory / Localhost Demonstration  
**Applicable Release:** Phase 8 Stabilized Release  

---

## 1. Demonstration Overview

This runbook guides a security analyst, evaluator, or technical reviewer through a complete, reproducible demonstration of FootprintIQ. The demonstration showcases:
- Secure administrator authentication and session management.
- Creation of an investigation campaign with strict target scope boundaries.
- Explicit administrative target authorization for active operations.
- Execution of passive OSINT collectors (RDAP, DNS, crt.sh).
- Execution of genuine Nmap network discovery and service enumeration.
- Graceful, honest degradation when optional scanning tools (Greenbone GVM) are unconfigured.
- Normalized finding correlation and cryptographic (SHA-256) evidence integrity tracking.
- Dynamic 5-factor exposure score calculation.
- Publication-grade 17-section PDF dossier generation (ReportLab Platypus).
- Knowledge graph XML export (GraphML) for Gephi, Cytoscape, and Maltego.

---

## 2. Prerequisites & Quick Setup

### System Prerequisites
- **Python:** 3.11+
- **Nmap:** Installed and accessible via system PATH (e.g. `nmap.exe` on Windows or `/usr/bin/nmap` on Linux).
- **Web Browser:** Any modern browser (Chrome, Edge, Firefox).

### Step-by-Step Environment Setup
Navigate to the `python_app/` directory:

```bash
cd footprint/python_app

# 1. Initialize environment variables
copy .env.example .env

# 2. Apply database migrations to head
python -m alembic upgrade head

# 3. Provision the initial Administrator account
python scripts/create_admin.py --username admin --email admin@footprintiq.local --password "SuperAdmin#2026!Secure" --non-interactive

# 4. Start the application web server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open your browser to: **`http://127.0.0.1:8000`**

---

## 3. Step-by-Step Demonstration Script

### Step 1: Secure Authentication
1. Navigate to `http://127.0.0.1:8000/login`.
2. Enter the provisioned credentials:
   - **Username or Email:** `admin`
   - **Password:** `SuperAdmin#2026!Secure`
3. Click **Sign In**.
4. **Demonstration Point:** Note that sessions use Argon2id password verification, cryptographically secure session tokens, and strict `HttpOnly` / `SameSite=Lax` cookies with CSRF defense.

### Step 2: Overview Dashboard & System Diagnostics
1. Review the executive metrics cards:
   - *Total Active Campaigns*
   - *Open Network Ports Discovered*
   - *Vulnerability Findings Matrix*
   - *Forensic Evidence Artifacts Archived*
2. Inspect the **Subsystem & Scanner Diagnostics** card:
   - **FastAPI Core & SQLAlchemy ORM:** Green / OPERATIONAL.
   - **Nmap Network Scanner:** Green / READY (displays detected version, e.g., 7.98).
   - **Greenbone / GVM Daemon:** Amber / NOT CONFIGURED (honestly reports that credentials/socket are unconfigured in environment; never fakes results).

### Step 3: Create an Investigation Campaign
1. Click **Investigations** in the top navigation bar.
2. Click **+ New Investigation**.
3. Fill in the modal form:
   - **Campaign Identifier:** `inv-demo-northstar`
   - **Campaign Name:** `NorthStar Analytics Perimeter Audit`
   - **Organization Name:** `NorthStar Analytics Ltd.`
   - **Target Scope:** `lab.example` (or `192.168.56.102`)
   - **Lead Investigator:** `admin`
4. Click **Create Campaign**.
5. Click **Open Workspace** on the newly created campaign.

### Step 4: Authorize Target for Active Operations
1. Click the **Target Authorizations** tab (Tab 2).
2. Click **+ Authorize Target**.
3. Enter:
   - **Target Address:** `192.168.56.102`
   - **Target Type:** `IP`
   - **Allowed Operations:** Check `SCAN_PORTS` and `SCAN_VULN`.
   - **Authorization Reference:** `AUTH-DEMO-2026`
   - **Validity Window:** `14 Days`
4. Click **Issue Authorization**.
5. **Demonstration Point:** Show that active scans are strictly blocked by the backend until an explicit, unrevoked, non-expired authorization record is persisted.

### Step 5: Execute Passive OSINT Reconnaissance
1. Click the **Passive Recon & Entities** tab (Tab 3).
2. Click **Run Passive Recon**.
3. The orchestrator dispatches asynchronous tasks across configured public sources (RDAP, DNS, crt.sh).
4. Refresh to view discovered subdomains, IP addresses, nameservers, and mail exchangers.
5. Note that each entity is deduplicated and retains a link to its evidence ID.

### Step 6: Execute Real Nmap Active Port Scan
1. Click the **Active Nmap Ports** tab (Tab 4).
2. Click **+ Dispatch Nmap Scan**.
3. Select:
   - **Target:** `192.168.56.102` (or your authorized lab IP / localhost `127.0.0.1`).
   - **Scan Profile:** `Quick Network Discovery` (`-sT -T4 --top-ports 100`).
4. Click **Execute Scan Subprocess**.
5. **Demonstration Point:** The scan is invoked safely using `subprocess.Popen` with an argument array (`shell=False`).
6. Upon completion, the normalized host inventory and open port table appear showing port number, protocol, state, and detected service.

### Step 7: Inspect Honest Vulnerability Status
1. Click the **Vulnerabilities** tab (Tab 5).
2. Observe that because Greenbone GVM is not running locally, the tab honestly states:
   - *Greenbone Vulnerability Manager Offline or Not Configured.*
   - *No vulnerabilities reported because scanner is unconfigured; does not falsely imply the target is secure.*

### Step 8: Review Forensic Evidence & SHA-256 Ledger
1. Click the **Forensic Evidence** tab (Tab 6).
2. Inspect the raw archived XML and JSON payloads.
3. Show the cryptographic **SHA-256 content hash** generated at collection time for non-repudiation.

### Step 9: 5-Factor Exposure Score Breakdown
1. Click the **Score & Report** tab (Tab 8).
2. Review the genuine calculated exposure score:
   - **Formula:** $E = (0.20 \cdot P) + (0.15 \cdot D) + (0.25 \cdot S) + (0.35 \cdot V) + (0.05 \cdot C)$
   - Review component scores for Public Footprint ($P$), Domain Hygiene ($D$), Service Exposure ($S$), Vulnerability Severity ($V$), and Correlation Confidence ($C$).
   - Show the assigned Risk Tier (Minimal, Low, Moderate, High, or Critical).
   - Point out that this score is distinct from standard CVSS vulnerability ratings.

### Step 10: Generate & Download Consolidated PDF Dossier
1. On Tab 8, click **Generate & Download PDF Dossier**.
2. Open the downloaded PDF (`FootprintIQ-Dossier-inv-demo-northstar.pdf`).
3. Point out publication-grade features:
   - Two-pass `NumberedCanvas` showing page numbers ("Page X of Y") and confidentiality headers.
   - Comprehensive 17-section structure (Executive Summary, Target Authorization Table, Discovered Entities, Network Ports Table, Vulnerability Findings, Evidence Provenance, and Prioritized Remediation).
   - Clear indicators of unavailable or unconfigured integrations.

### Step 11: Export Knowledge Graph (GraphML XML)
1. On Tab 8, click **Export Knowledge Graph (GraphML XML)**.
2. Open the downloaded file (`FootprintIQ-KnowledgeGraph-inv-demo-northstar.graphml`) in a text editor or import it into Gephi/Cytoscape.
3. Show that all investigation nodes, discovered subdomains, network hosts, and open ports are structured with directed edges representing their relationships (`DISCOVERED_ENTITY`, `RESOLVED_HOST`, `EXPOSES_PORT`).

### Step 12: Administrative Allowlist & Security Audit Trail
1. In the top navigation, click **Admin**.
2. Click **Target Authorizations** to view and revoke authorized targets across all campaigns.
3. Click **Scanner Diagnostics** to see live availability checks for Nmap and Greenbone.
4. Click **Audit Trail** in the top navigation to review the chronological, tamper-evident log of all logins, authorizations, scan launches, and report downloads.

---

## 4. Troubleshooting Guide

| Issue | Cause | Resolution |
| :--- | :--- | :--- |
| **Nmap Not Detected** | `nmap` is not in system PATH or common directories. | Install Nmap or set `NMAP_BIN="C:\\Program Files (x86)\\Nmap\\nmap.exe"` in `.env`. |
| **Login Fails with 401** | Account not provisioned or password mistyped. | Run `python scripts/create_admin.py` to reset credentials. |
| **Scan Fails with 403 Forbidden** | Target address is not explicitly authorized. | Go to Tab 2 ("Target Authorizations"), click "Authorize Target", and issue an allowlist record. |
| **Port Scan Times Out** | Target firewall dropping TCP probes. | Use local loopback `127.0.0.1` or authorized lab sandbox `192.168.56.102`. |
| **Database Locks on Windows** | SQLite accessed concurrently across multiple processes. | FootprintIQ automatically configures SQLite in `WAL` (Write-Ahead Logging) mode with a 30s timeout. |
