"""
FootprintIQ - Unit Tests for Microsoft SQL Server 2022 Models & Schema
Strict Rule: Pure Microsoft SQL Server dialect and architecture.
"""

import unittest
from sqlalchemy.dialects import mssql
from sqlalchemy.schema import CreateTable
from src.db.models import (
    Base, User, Investigation, Campaign, AuthorizedTarget,
    ScanExecution, VulnerabilityFinding, EvidenceRecord,
    ReportRecord, AuditLog
)
from src.db.session import check_db_health, get_database_url


class TestSQLServerModels(unittest.TestCase):
    def test_database_url_dialect(self):
        url = get_database_url()
        self.assertTrue(url.startswith("mssql+"), f"Expected mssql dialect, got: {url}")

    def test_tables_registered_in_metadata(self):
        tables = Base.metadata.tables.keys()
        expected = [
            "users", "investigations", "campaigns", "authorized_targets",
            "scan_executions", "vulnerability_findings", "evidence_records",
            "report_records", "audit_logs"
        ]
        for t in expected:
            self.assertIn(t, tables)

    def test_mssql_ddl_compilation(self):
        """Verifies that all models compile cleanly into valid Microsoft SQL Server T-SQL."""
        dialect = mssql.dialect()
        for table in Base.metadata.sorted_tables:
            stmt = CreateTable(table).compile(dialect=dialect)
            sql = str(stmt).upper()
            self.assertIn("CREATE TABLE", sql)
            # Check for primary key
            self.assertIn("PRIMARY KEY", sql)

    def test_db_health_check_structure(self):
        health = check_db_health()
        self.assertIn("status", health)
        self.assertIn("database_product", health)
        self.assertEqual(health["database_product"], "Microsoft SQL Server 2022 Express" if health["status"] == "OFFLINE" else "Microsoft SQL Server")


if __name__ == "__main__":
    unittest.main()

