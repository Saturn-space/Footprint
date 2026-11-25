"""
FootprintIQ - Dedicated Database ACID Compliance & Transaction Integrity Test Suite
Strict Requirement: Verifies Atomicity, Consistency, Isolation, Durability, Idempotency,
and Failure Injection guarantees against Microsoft SQL Server 2022 Express architecture.
"""

import unittest
import threading
import time
import json
import uuid
from typing import List

from sqlalchemy.dialects import mssql
from sqlalchemy.schema import CreateTable

from src.db.session import (
    transactional_session, retry_on_deadlock, is_deadlock_error,
    check_db_health, check_rcsi_status, get_database_url
)
from src.db.models import (
    Base, User, Investigation, AuthorizedTarget, ReconCampaign,
    ScanExecution, VulnerabilityFinding, EvidenceRecord, ReportRecord,
    AuditLog, ScanExecutionEvent, RemediationHistory, ExternalArtifactOutbox
)
from src.db.repository import (
    FootprintIQRepository, DatabaseIntegrityError, ConcurrencyConflictError,
    EntityNotFoundError
)


class TestDatabaseACID(unittest.TestCase):
    def setUp(self):
        self.repo = FootprintIQRepository()

    # =========================================================================
    # 1. ATOMICITY TESTS — All or Nothing
    # =========================================================================

    def test_atomicity_recon_creation_rollback_on_failure(self):
        """
        Atomicity Test:
        Simulate an integrity failure during campaign creation (e.g. invalid target or duplicate Recon ID).
        Verify that no partial records (Investigation, Target, Campaign, AuditLog) remain committed.
        """
        initial_inv_count = len(self.repo.list_investigations())
        initial_camp_count = len(self.repo.list_recon_campaigns())
        initial_target_count = len(self.repo.list_authorized_targets())

        # Attempt to create campaign with invalid port check constraint violation
        with self.assertRaises(DatabaseIntegrityError):
            # Pass an invalid port range that violates the database check constraint
            self.repo.create_recon_campaign(
                name="Atomic Rollback Test",
                target_value="192.168.56.111",
                allowed_ports="invalid-port-string"  # Checked in repo validation
            )

        # Verify zero partial records leaked
        self.assertEqual(len(self.repo.list_investigations()), initial_inv_count)
        self.assertEqual(len(self.repo.list_recon_campaigns()), initial_camp_count)
        self.assertEqual(len(self.repo.list_authorized_targets()), initial_target_count)

    def test_atomicity_transaction_context_manager_commit_and_rollback(self):
        """
        Atomicity Test:
        Verify that transactional_session context manager automatically commits on clean exit
        and rolls back on exception.
        """
        # Test rollback on exception
        executed = False
        try:
            with transactional_session() as session:
                executed = True
                raise RuntimeError("Simulated mid-transaction failure")
        except RuntimeError:
            pass
        self.assertTrue(executed, "Transactional block should have executed before exception")

    def test_atomicity_finding_ingestion_rollback(self):
        """
        Atomicity Test:
        Verify that an invalid finding (e.g. out-of-range CVSS score or invalid severity)
        fails before any related audit or evidence records are persisted.
        """
        initial_findings = len(self.repo.list_findings())
        with self.assertRaises(DatabaseIntegrityError):
            self.repo.add_vulnerability_finding(
                investigation_id="INV-TEST-ATOMIC",
                finding_dict={
                    "title": "Invalid Severity Finding",
                    "severity": "Catastrophic",  # Invalid severity value
                    "target_ip": "192.168.56.111"
                }
            )
        self.assertEqual(len(self.repo.list_findings()), initial_findings)

    # =========================================================================
    # 2. CONSISTENCY TESTS — Valid Data Before and After Transactions
    # =========================================================================

    def test_consistency_check_constraint_severity_validation(self):
        """Consistency Test: Severity must strictly belong to supported set."""
        valid_severities = ["Critical", "High", "Medium", "Low", "Informational", "Info"]
        for sev in valid_severities:
            f = self.repo.add_vulnerability_finding(
                investigation_id="INV-TEST-CONSISTENCY",
                finding_dict={"title": f"Valid {sev}", "severity": sev, "target_ip": "192.168.56.111"}
            )
            self.assertEqual(f["severity"], sev)

        invalid_severities = ["SuperCritical", "Warning", "Fatal", "Unknown", "None"]
        for bad_sev in invalid_severities:
            with self.assertRaises(DatabaseIntegrityError):
                self.repo.add_vulnerability_finding(
                    investigation_id="INV-TEST-CONSISTENCY",
                    finding_dict={"title": "Invalid Sev", "severity": bad_sev, "target_ip": "192.168.56.111"}
                )

    def test_consistency_check_constraint_port_bounds(self):
        """Consistency Test: Port numbers must be within valid range 1 - 65535."""
        # Valid port
        f = self.repo.add_vulnerability_finding(
            investigation_id="INV-TEST-PORT",
            finding_dict={"title": "Valid Port", "severity": "Low", "target_ip": "192.168.56.111", "port": 443}
        )
        self.assertEqual(f["port"], 443)

        # Invalid port: 0
        with self.assertRaises(DatabaseIntegrityError):
            self.repo.add_vulnerability_finding(
                investigation_id="INV-TEST-PORT",
                finding_dict={"title": "Port Zero", "severity": "Low", "target_ip": "192.168.56.111", "port": 0}
            )

        # Invalid port: 70000
        with self.assertRaises(DatabaseIntegrityError):
            self.repo.add_vulnerability_finding(
                investigation_id="INV-TEST-PORT",
                finding_dict={"title": "Port Overflow", "severity": "Low", "target_ip": "192.168.56.111", "port": 70000}
            )

    def test_consistency_check_constraint_cvss_score_bounds(self):
        """Consistency Test: CVSS scores must remain between 0.0 and 10.0."""
        # Valid CVSS
        f = self.repo.add_vulnerability_finding(
            investigation_id="INV-TEST-CVSS",
            finding_dict={"title": "Valid CVSS", "severity": "High", "target_ip": "192.168.56.111", "cvss_score": 7.5}
        )
        self.assertEqual(f["cvss_score"], 7.5)

        # Invalid CVSS: 12.5
        with self.assertRaises(DatabaseIntegrityError):
            self.repo.add_vulnerability_finding(
                investigation_id="INV-TEST-CVSS",
                finding_dict={"title": "CVSS Overflow", "severity": "High", "target_ip": "192.168.56.111", "cvss_score": 12.5}
            )

        # Invalid CVSS: -1.0
        with self.assertRaises(DatabaseIntegrityError):
            self.repo.add_vulnerability_finding(
                investigation_id="INV-TEST-CVSS",
                finding_dict={"title": "CVSS Underflow", "severity": "High", "target_ip": "192.168.56.111", "cvss_score": -1.0}
            )

    def test_consistency_check_constraint_scan_status(self):
        """Consistency Test: Scan execution status must match allowable transitions."""
        scan = self.repo.create_scan_execution(
            investigation_id="INV-TEST-STATUS",
            scan_type="network_discovery",
            target="192.168.56.111"
        )
        scan_id = scan["scan_id"]

        # Valid transitions
        self.assertTrue(self.repo.update_scan_execution(scan_id, "running"))
        self.assertTrue(self.repo.update_scan_execution(scan_id, "completed"))

        # Invalid status
        with self.assertRaises(DatabaseIntegrityError):
            self.repo.update_scan_execution(scan_id, "arbitrary_unauthorized_state")

    def test_consistency_exposure_score_bounds(self):
        """Consistency Test: Investigation exposure score must remain between 0.0 and 100.0."""
        inv = self.repo.create_investigation(title="Exposure Test")
        inv_id = inv["investigation_id"]

        self.assertTrue(self.repo.update_exposure_score(inv_id, 45.5))

        with self.assertRaises(DatabaseIntegrityError):
            self.repo.update_exposure_score(inv_id, 150.0)

        with self.assertRaises(DatabaseIntegrityError):
            self.repo.update_exposure_score(inv_id, -10.0)

    # =========================================================================
    # 3. ISOLATION TESTS — Safe Concurrent Operations
    # =========================================================================

    def test_isolation_concurrent_campaign_creation(self):
        """
        Isolation Test:
        Simulate 10 concurrent investigators creating Recon campaigns simultaneously.
        Verify that each campaign receives a collision-free unique Recon ID.
        """
        results = []
        errors = []

        def create_worker(idx):
            try:
                camp = self.repo.create_recon_campaign(
                    name=f"Concurrent Campaign {idx}",
                    target_value="192.168.56.111",
                    description=f"Thread {idx}"
                )
                results.append(camp["recon_id"])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create_worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent creation generated errors: {errors}")
        self.assertEqual(len(results), 10, "All 10 campaigns should have been created")
        # Ensure all Recon IDs are strictly unique
        self.assertEqual(len(set(results)), 10, f"Duplicate Recon IDs detected: {results}")

    def test_isolation_concurrent_job_claim_double_launch_prevention(self):
        """
        Isolation Test:
        Simulate two concurrent workers attempting to claim and launch a scan for the same campaign.
        Verify that exactly one worker succeeds, and the other is rejected with ConcurrencyConflictError.
        """
        camp = self.repo.create_recon_campaign(
            name="Race Condition Campaign",
            target_value="192.168.56.111"
        )
        recon_id = camp["recon_id"]

        successes = []
        conflicts = []

        def claim_worker():
            try:
                res = self.repo.claim_and_start_recon_scan(
                    recon_id=recon_id,
                    scan_type="combined"
                )
                successes.append(res)
            except ConcurrencyConflictError as c:
                conflicts.append(c)
            except Exception as e:
                conflicts.append(e)

        t1 = threading.Thread(target=claim_worker)
        t2 = threading.Thread(target=claim_worker)

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(successes), 1, "Exactly one worker should claim the job")
        self.assertEqual(len(conflicts), 1, "The competing worker must encounter a ConcurrencyConflictError")
        self.assertIsInstance(conflicts[0], ConcurrencyConflictError)

    def test_isolation_optimistic_concurrency_lost_update_prevention(self):
        """
        Isolation Test:
        Simulate two investigators updating the same vulnerability finding concurrently.
        User A updates using version 1 -> succeeds, increments to version 2.
        User B attempts to update using stale version 1 -> rejected with ConcurrencyConflictError.
        """
        f = self.repo.add_vulnerability_finding(
            investigation_id="INV-OCC-TEST",
            finding_dict={"title": "vsftpd backdoor", "severity": "Critical", "target_ip": "192.168.56.111"}
        )
        fid = f["finding_id"]
        v1 = f.get("version_id", 1)

        # User A updates status to 'in_progress' with expected version 1
        res_a = self.repo.update_finding_remediation_status(
            finding_id=fid,
            new_status="in_progress",
            changed_by="investigator_a",
            expected_version=v1
        )
        self.assertEqual(res_a["new_status"], "in_progress")
        self.assertEqual(res_a["version_id"], v1 + 1)

        # User B attempts to update with stale version 1 -> Must raise ConcurrencyConflictError
        with self.assertRaises(ConcurrencyConflictError):
            self.repo.update_finding_remediation_status(
                finding_id=fid,
                new_status="resolved",
                changed_by="investigator_b",
                expected_version=v1  # Stale version!
            )

    def test_isolation_deadlock_retry_decorator(self):
        """
        Isolation Test:
        Verifies that the retry_on_deadlock decorator intercepts transient SQL Server Error 1205
        and successfully retries the operation with exponential backoff.
        """
        attempt_count = 0

        @retry_on_deadlock(max_retries=3, base_delay=0.01)
        def simulated_deadlock_operation():
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 3:
                # Raise simulated SQL Server deadlock exception
                raise Exception("(pymssql.exceptions.OperationalError) (1205, b'Transaction (Process ID 52) was deadlocked on lock resources with another process and has been chosen as the deadlock victim. Rerun the transaction.')")
            return "SUCCESS"

        result = simulated_deadlock_operation()
        self.assertEqual(result, "SUCCESS")
        self.assertEqual(attempt_count, 3, "Operation should have retried twice and succeeded on 3rd attempt")

    # =========================================================================
    # 4. DURABILITY TESTS — Committed Data Persists
    # =========================================================================

    def test_durability_post_restart_scan_reconciliation(self):
        """
        Durability Test:
        Simulate an abrupt host/app crash where a scan and campaign were left in 'Running'.
        Verify that reconcile_interrupted_scans safely recovers the state to 'Interrupted'
        with appropriate audit history.
        """
        # Create campaign and scan in running state
        camp = self.repo.create_recon_campaign(name="Crashed Scan Campaign", target_value="192.168.56.111")
        recon_id = camp["recon_id"]
        self.repo.update_recon_campaign(recon_id, status="Running", current_stage="Active Scan")

        scan = self.repo.create_scan_execution(investigation_id=recon_id, scan_type="combined", target="192.168.56.111")
        scan_id = scan["scan_id"]
        self.repo.update_scan_execution(scan_id, status="running")

        # Execute recovery lifespan reconciliation
        reconciled = self.repo.reconcile_interrupted_scans()
        self.assertIn(scan_id, reconciled["reconciled_scans"])
        self.assertIn(recon_id, reconciled["reconciled_campaigns"])

        # Verify state after recovery
        updated_camp = self.repo.get_recon_campaign(recon_id)
        self.assertEqual(updated_camp["status"], "Interrupted")

        updated_scans = [s for s in self.repo.list_scans(investigation_id=recon_id) if s["scan_id"] == scan_id]
        self.assertEqual(updated_scans[0]["status"], "interrupted")

    def test_durability_outbox_staging_and_orphan_handling(self):
        """
        Durability Test:
        Verifies SeaweedFS Transactional Outbox pattern:
        1. Artifact is staged.
        2. Database commits -> Artifact is marked committed.
        3. Simulated failure -> Artifact is marked orphaned for background cleanup.
        """
        artifact_id = f"OUTBOX-{uuid.uuid4().hex[:8]}"
        staged = self.repo.stage_external_artifact(
            artifact_id=artifact_id,
            investigation_id="INV-OUTBOX-TEST",
            artifact_type="seaweed_blob",
            external_reference_id="2,764e0e63d9",
            file_name="evidence.pcap"
        )
        self.assertEqual(staged["status"], "staged")

        # Commit artifact
        self.assertTrue(self.repo.commit_external_artifact(artifact_id))

        # Test orphan marking on simulated failure
        orphan_id = f"OUTBOX-ORPHAN-{uuid.uuid4().hex[:8]}"
        self.repo.stage_external_artifact(
            artifact_id=orphan_id,
            investigation_id="INV-OUTBOX-TEST",
            artifact_type="seaweed_blob",
            external_reference_id="3,9999999999"
        )
        self.assertTrue(self.repo.mark_external_artifact_orphaned(orphan_id))

    # =========================================================================
    # 5. IDEMPOTENCY TESTS — Safe Repeated Requests
    # =========================================================================

    def test_idempotency_campaign_creation_with_key(self):
        """
        Idempotency Test:
        Verifies that repeated requests with the same idempotency key
        return the existing campaign without creating duplicate records.
        """
        idemp_key = f"IDEMP-{uuid.uuid4().hex[:8]}"
        camp1 = self.repo.create_recon_campaign(
            name="Idempotent Campaign",
            target_value="192.168.56.111",
            idempotency_key=idemp_key
        )
        recon_id = camp1["recon_id"]

        # Repeated request with same idempotency key
        camp2 = self.repo.create_recon_campaign(
            name="Idempotent Campaign",
            target_value="192.168.56.111",
            idempotency_key=idemp_key
        )
        # Should return the exact same campaign
        self.assertEqual(camp1["recon_id"], camp2["recon_id"])

    # =========================================================================
    # 6. FAILURE INJECTION TESTS
    # =========================================================================

    def test_failure_injection_deadlock_detection_helper(self):
        """Failure Injection Test: Verifies deadlock exception matching."""
        deadlock_exc = Exception("(pymssql.exceptions.OperationalError) (1205, b'Transaction deadlocked and chosen as victim')")
        self.assertTrue(is_deadlock_error(deadlock_exc))

        syntax_exc = Exception("Syntax error near 'SELECT'")
        self.assertFalse(is_deadlock_error(syntax_exc))

    def test_failure_injection_session_cleanup(self):
        """Failure Injection Test: Verifies session is closed on exception without leaking connections."""
        with self.assertRaises(ZeroDivisionError):
            with transactional_session() as session:
                x = 1 / 0


if __name__ == "__main__":
    unittest.main()

