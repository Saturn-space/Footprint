"""
FootprintIQ - Privilege Consent & Authorization (PSA) Test Suite
Verifies:
1. Privilege detection for raw-socket operations (-sS, -sU, -O, ARP) vs unprivileged (-sT, -sV, DNS, WHOIS)
2. Scenario A: Fallback to safe unprivileged execution when consent is not granted
3. Scenario B: Authorized elevated execution with valid password re-verification and ephemeral ticket
4. Scenario C: Access denied and security audit logging when identity verification fails
5. Scenario D: Rejection of expired, reused, or cross-campaign authorization tickets
6. Scenario E: Honest capture of scanner execution failures and return codes (never inventing success)
7. Security controls: Strict shell=False argument allowlist rejection of shell metacharacters
"""

import os
import json
import time
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from src.api.app import app
from src.db.repository import FootprintIQRepository
from src.services.auth_service import AuthService
from src.security.privilege_detector import PrivilegeDetector, PrivilegeAnalysis
from src.security.psa_service import (
    PSAService,
    PSATicket,
    PSAIdentityVerificationError,
    PSATicketExpiredOrInvalidError,
)
from src.security.privileged_executor import (
    PrivilegedExecutor,
    PrivilegedExecutionError,
)
from src.orchestration.execution_manager import ExecutionManager


class TestPrivilegeConsentAuthorization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.repo = FootprintIQRepository()
        AuthService(repo=cls.repo)

        # Login test accounts
        cls.admin_token = cls._login("admin", "AdminPass2026!")
        cls.inv1_token = cls._login("investigator1", "Investigator1Pass2026!")
        cls.inv2_token = cls._login("investigator2", "Investigator2Pass2026!")

        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}
        cls.inv1_headers = {"Authorization": f"Bearer {cls.inv1_token}"}
        cls.inv2_headers = {"Authorization": f"Bearer {cls.inv2_token}"}

    @classmethod
    def _login(cls, username: str, password: str) -> str:
        resp = cls.client.post("/api/v1/auth/login", json={"username": username, "password": password})
        assert resp.status_code == 200, f"Login failed for {username}: {resp.text}"
        return resp.json()["access_token"]

    def _create_test_campaign(self, headers, name="PSA Assessment", target="192.168.56.111"):
        payload = {
            "name": name,
            "target_value": target,
            "target_type": "ipv4",
            "purpose": "Security Privilege Audit",
            "scope_description": "Controlled lab assessment",
            "selected_scan_types": "active",
            "authorization_confirmed": True
        }
        res = self.client.post("/api/v1/recon", json=payload, headers=headers)
        self.assertEqual(res.status_code, 201, f"Failed to create campaign: {res.text}")
        return res.json()

    # =========================================================================
    # 1. PRIVILEGE DETECTOR TESTS
    # =========================================================================

    def test_01_detect_privileged_operations(self):
        """Verifies that SYN (-sS), UDP (-sU), and OS detection (-O) require elevation."""
        cfg = {
            "selected_categories": ["active"],
            "active": {
                "tcp_scan_type": "tcp_syn",
                "os_detection": True,
                "udp_scan": True,
                "udp_port_mode": "udp_common"
            }
        }
        analysis = PrivilegeDetector.analyze_scan_config(cfg, scan_type="combined")
        self.assertTrue(analysis.requires_privilege)
        self.assertIn("tcp_syn", analysis.privileged_operations)
        self.assertIn("os_detection", analysis.privileged_operations)
        self.assertIn("udp_scan", analysis.privileged_operations)
        self.assertEqual(len(analysis.privileged_reasons), 3)

        # Check sanitized unprivileged fallback configuration
        sanitized = analysis.sanitized_config
        self.assertEqual(sanitized["active"]["tcp_scan_type"], "tcp_connect")
        self.assertFalse(sanitized["active"]["os_detection"])
        self.assertFalse(sanitized["active"]["udp_scan"])
        self.assertEqual(sanitized["active"]["udp_port_mode"], "none")
        self.assertEqual(len(analysis.skipped_operations), 3)

    def test_02_detect_unprivileged_safe_operations(self):
        """Verifies standard TCP Connect, service banners, and safe templates need no elevation."""
        cfg = {
            "selected_categories": ["active", "vulnerability"],
            "active": {
                "tcp_scan_type": "tcp_connect",
                "port_mode": "service_common",
                "service_version": True,
                "banner_grab": True,
                "os_detection": False
            },
            "vulnerability": {
                "engines": ["nse", "nuclei"],
                "nse_scripts": ["http-title", "ssl-cert", "banner"],
                "nuclei_profile": "http-security"
            }
        }
        analysis = PrivilegeDetector.analyze_scan_config(cfg, scan_type="combined")
        self.assertFalse(analysis.requires_privilege)
        self.assertEqual(len(analysis.privileged_operations), 0)
        self.assertEqual(len(analysis.skipped_operations), 0)

    def test_03_detect_passive_recon_never_requires_elevation(self):
        """Verifies Passive Reconnaissance is strictly immune from privilege requirements."""
        cfg = {
            "selected_categories": ["passive"],
            "passive": {
                "selected_checks": ["whois_lookup", "rdap_lookup", "dns_records", "asn_ip_hosting"],
                "allow_target_contact": False
            }
        }
        analysis = PrivilegeDetector.analyze_scan_config(cfg, scan_type="passive")
        self.assertFalse(analysis.requires_privilege)
        self.assertEqual(len(analysis.privileged_operations), 0)

    # =========================================================================
    # 2. PSA EPHEMERAL TICKET SERVICE TESTS
    # =========================================================================

    def test_04_psa_ticket_issuance_and_single_use_consumption(self):
        """Verifies correct password verification, ticket issuance, and single-use invalidation."""
        psa = PSAService(repo=self.repo)
        user = self.repo.get_user_by_username("investigator1")
        self.assertIsNotNone(user)

        # Issue ticket
        ticket_data = psa.verify_identity_and_issue_ticket(
            current_user=user,
            plain_password="Investigator1Pass2026!",
            recon_id="FIQ-REC-TEST-001",
            target="192.168.56.111",
            approved_operations=["tcp_syn", "os_detection"]
        )
        self.assertIn("ticket_token", ticket_data)
        self.assertTrue(ticket_data["ticket_token"].startswith("psa_"))
        self.assertEqual(ticket_data["username"], "investigator1")

        # Validate and consume ticket (First use -> SUCCESS)
        consumed_ticket = psa.validate_and_consume_ticket(
            token=ticket_data["ticket_token"],
            user_id=user["id"],
            recon_id="FIQ-REC-TEST-001"
        )
        self.assertTrue(consumed_ticket.consumed)

        # Replay attempt (Second use -> MUST FAIL)
        with self.assertRaises(PSATicketExpiredOrInvalidError) as ctx:
            psa.validate_and_consume_ticket(
                token=ticket_data["ticket_token"],
                user_id=user["id"],
                recon_id="FIQ-REC-TEST-001"
            )
        self.assertIn("already been used", str(ctx.exception))

    def test_05_psa_ticket_expiration_enforcement_scenario_d(self):
        """Verifies that expired tickets (TTL exceeded) are strictly rejected (Scenario D)."""
        psa = PSAService(repo=self.repo)
        user = self.repo.get_user_by_username("investigator1")

        # Create ticket with 0 second TTL
        ticket_data = psa.verify_identity_and_issue_ticket(
            current_user=user,
            plain_password="Investigator1Pass2026!",
            recon_id="FIQ-REC-EXPIRE-001",
            target="192.168.56.111",
            approved_operations=["tcp_syn"],
            ttl_seconds=-1  # Already expired
        )
        token = ticket_data["ticket_token"]

        with self.assertRaises(PSATicketExpiredOrInvalidError) as ctx:
            psa.validate_and_consume_ticket(token=token, user_id=user["id"], recon_id="FIQ-REC-EXPIRE-001")
        self.assertIn("expired", str(ctx.exception).lower())

    def test_06_psa_ticket_cross_campaign_and_user_mismatch_scenario_d(self):
        """Verifies ticket cannot be transferred across campaigns or users (Scenario D)."""
        psa = PSAService(repo=self.repo)
        u1 = self.repo.get_user_by_username("investigator1")
        u2 = self.repo.get_user_by_username("investigator2")

        ticket_data = psa.verify_identity_and_issue_ticket(
            current_user=u1,
            plain_password="Investigator1Pass2026!",
            recon_id="CAMP-A",
            target="192.168.56.111",
            approved_operations=["tcp_syn"]
        )
        tok = ticket_data["ticket_token"]

        # Scope mismatch: submitted against CAMP-B
        with self.assertRaises(PSATicketExpiredOrInvalidError) as ctx:
            psa.validate_and_consume_ticket(token=tok, user_id=u1["id"], recon_id="CAMP-B")
        self.assertIn("scope mismatch", str(ctx.exception).lower())

        # User identity mismatch: submitted by investigator2
        with self.assertRaises(PSATicketExpiredOrInvalidError) as ctx:
            psa.validate_and_consume_ticket(token=tok, user_id=u2["id"], recon_id="CAMP-A")
        self.assertIn("user identity mismatch", str(ctx.exception).lower())

    # =========================================================================
    # 3. API ENDPOINTS & SCENARIOS A, B, C TESTS
    # =========================================================================

    def test_07_api_psa_detect_endpoint(self):
        """Verifies POST /api/v1/recon/{recon_id}/psa/detect returns privilege requirements."""
        camp = self._create_test_campaign(self.inv1_headers, name="PSA Detect Test")
        rid = camp["recon_id"]

        priv_cfg = {
            "selected_categories": ["active"],
            "active": {"tcp_scan_type": "tcp_syn", "os_detection": True}
        }
        res = self.client.post(
            f"/api/v1/recon/{rid}/psa/detect",
            json={"scan_config": priv_cfg},
            headers=self.inv1_headers
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["requires_privilege"])
        self.assertIn("tcp_syn", data["privileged_operations"])
        self.assertIn("os_detection", data["privileged_operations"])

    def test_08_api_scenario_c_identity_verification_failure(self):
        """Scenario C: Invalid password returns 401, denies execution, and logs security audit."""
        camp = self._create_test_campaign(self.inv1_headers, name="PSA Scenario C Test")
        rid = camp["recon_id"]

        # Verify with wrong password
        res = self.client.post(
            f"/api/v1/recon/{rid}/psa/verify",
            json={"password": "IncorrectPassword123!"},
            headers=self.inv1_headers
        )
        self.assertEqual(res.status_code, 401)
        self.assertIn("verification failed", res.json()["detail"].lower())

        # Verify security audit log was created with outcome DENIED
        audit_logs = self.repo.list_audit_logs()
        failed_audits = [
            a for a in audit_logs
            if a.get("action") == "PSA_IDENTITY_VERIFICATION_FAILED" and a.get("target_resource") == rid
        ]
        self.assertTrue(len(failed_audits) > 0, "Expected security audit log for failed identity verification")
        self.assertEqual(failed_audits[-1].get("outcome"), "DENIED")

    def test_09_api_scenario_a_unprivileged_fallback_when_consent_unchecked(self):
        """Scenario A: Privileged scan requested without consent -> clean unprivileged fallback."""
        camp = self._create_test_campaign(self.inv1_headers, name="PSA Scenario A Fallback")
        rid = camp["recon_id"]

        priv_cfg = {
            "selected_categories": ["active"],
            "active": {
                "tcp_scan_type": "tcp_syn",
                "os_detection": True,
                "udp_scan": True,
                "port_mode": "top_100"
            }
        }

        # Start scan with privilege_consent = False (or omitted)
        res = self.client.post(
            f"/api/v1/recon/{rid}/start",
            json={
                "scan_config": priv_cfg,
                "privilege_consent": False
            },
            headers=self.inv1_headers
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        sid = data["scan_id"]

        # Check returned scan metadata
        self.assertFalse(data.get("privilege_consent_given"))
        self.assertTrue(data.get("privilege_elevation_required"))
        self.assertEqual(data.get("privilege_status"), "fallback_unprivileged")

        # Verify stored scan record
        scan_rec = self.repo.get_scan(sid)
        self.assertIsNotNone(scan_rec)
        self.assertFalse(scan_rec.get("privilege_consent_given"))
        self.assertTrue(scan_rec.get("privilege_elevation_required"))
        self.assertEqual(scan_rec.get("privilege_status"), "fallback_unprivileged")

    def test_10_api_scenario_b_elevated_execution_flow(self):
        """Scenario B: Consent granted + Identity verified -> elevated execution authorized."""
        camp = self._create_test_campaign(self.inv1_headers, name="PSA Scenario B Authorized")
        rid = camp["recon_id"]

        priv_cfg = {
            "selected_categories": ["active"],
            "active": {
                "tcp_scan_type": "tcp_syn",
                "os_detection": True,
                "port_mode": "top_100"
            }
        }

        # Step 1: Re-verify identity with valid password
        v_res = self.client.post(
            f"/api/v1/recon/{rid}/psa/verify",
            json={"password": "Investigator1Pass2026!", "scan_config": priv_cfg},
            headers=self.inv1_headers
        )
        self.assertEqual(v_res.status_code, 200)
        v_data = v_res.json()
        ticket_token = v_data["ticket_token"]
        self.assertTrue(ticket_token.startswith("psa_"))

        # Step 2: Start scan with consent and valid single-use ticket
        s_res = self.client.post(
            f"/api/v1/recon/{rid}/start",
            json={
                "scan_config": priv_cfg,
                "privilege_consent": True,
                "psa_ticket": ticket_token
            },
            headers=self.inv1_headers
        )
        self.assertEqual(s_res.status_code, 200)
        s_data = s_res.json()
        sid = s_data["scan_id"]

        # Assert elevated authorization state
        self.assertTrue(s_data.get("privilege_consent_given"))
        self.assertTrue(s_data.get("privilege_elevation_required"))
        self.assertEqual(s_data.get("privilege_status"), "authorized")

        scan_rec = self.repo.get_scan(sid)
        self.assertTrue(scan_rec.get("privilege_consent_given"))
        self.assertEqual(scan_rec.get("privilege_status"), "authorized")
        self.assertIsNotNone(scan_rec.get("privilege_authorized_at"))

        # Step 3: Verify ticket cannot be reused (replay protection)
        replay_res = self.client.post(
            f"/api/v1/recon/{rid}/start",
            json={
                "scan_config": priv_cfg,
                "privilege_consent": True,
                "psa_ticket": ticket_token
            },
            headers=self.inv1_headers
        )
        # Should be rejected with 403 Forbidden due to consumed ticket
        self.assertEqual(replay_res.status_code, 403)
        self.assertIn("already been used", replay_res.json()["detail"].lower())

    def test_11_api_scenario_d_missing_or_invalid_ticket_rejected(self):
        """Scenario D: Consent checked but ticket missing/forged -> rejected fail-closed."""
        camp = self._create_test_campaign(self.inv1_headers, name="PSA Scenario D Rejection")
        rid = camp["recon_id"]

        priv_cfg = {
            "selected_categories": ["active"],
            "active": {"tcp_scan_type": "tcp_syn"}
        }

        # Consent checked but no ticket provided
        res_no_ticket = self.client.post(
            f"/api/v1/recon/{rid}/start",
            json={"scan_config": priv_cfg, "privilege_consent": True},
            headers=self.inv1_headers
        )
        self.assertEqual(res_no_ticket.status_code, 403)
        self.assertIn("ticket", res_no_ticket.json()["detail"].lower())

        # Consent checked with fake/forged ticket
        res_fake_ticket = self.client.post(
            f"/api/v1/recon/{rid}/start",
            json={"scan_config": priv_cfg, "privilege_consent": True, "psa_ticket": "psa_forged_random_string"},
            headers=self.inv1_headers
        )
        self.assertEqual(res_fake_ticket.status_code, 403)
        self.assertIn("not found or already consumed", res_fake_ticket.json()["detail"].lower())

    # =========================================================================
    # 4. PRIVILEGED EXECUTOR SECURITY CONTROLS & SCENARIO E TESTS
    # =========================================================================

    def test_12_privileged_executor_argument_allowlist_rejects_metacharacters(self):
        """Security: Verifies argument validator rejects injection attempts fail-closed."""
        executor = PrivilegedExecutor()

        # Command chaining attempts
        with self.assertRaises(PrivilegedExecutionError):
            executor.validate_command_arguments(["-sS", "; cat /etc/passwd"], "192.168.56.111")

        with self.assertRaises(PrivilegedExecutionError):
            executor.validate_command_arguments(["-sS", "| ls -la"], "192.168.56.111")

        with self.assertRaises(PrivilegedExecutionError):
            executor.validate_command_arguments(["-sS", "`whoami`"], "192.168.56.111")

        # Disallowed flags
        with self.assertRaises(PrivilegedExecutionError):
            executor.validate_command_arguments(["-sS", "--interactive"], "192.168.56.111")

        with self.assertRaises(PrivilegedExecutionError):
            executor.validate_command_arguments(["-sS", "--script=../../bad.nse"], "192.168.56.111")

        # Valid allowlisted arguments should pass without exception
        executor.validate_command_arguments(
            ["-sS", "-sV", "-O", "-Pn", "-p", "22,80,443", "-T4"],
            "192.168.56.111"
        )

    def test_13_scenario_e_honest_execution_failure_capture(self):
        """Scenario E: If privileged scan fails, return code and stderr are captured honestly."""
        executor = PrivilegedExecutor()

        # Execute with an invalid port range that causes nmap to exit non-zero
        res = executor.execute_privileged_nmap(
            command_args=["-sT", "-p", "1-65536"],
            target="127.0.0.1",
            timeout=10,
            use_elevation=False
        )

        # Non-zero returncode and error message must be honestly reported
        self.assertNotEqual(res.returncode, 0)
        self.assertIsNotNone(res.error_message)
        self.assertTrue(len(res.stderr) > 0 or len(res.stdout) > 0)
        self.assertIn("65535", (res.stderr + res.stdout))


if __name__ == "__main__":
    unittest.main()
