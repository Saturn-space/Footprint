"""Add active_scan_jobs, scan_hosts, and scan_ports tables for Nmap reconnaissance

Revision ID: 0004_nmap
Revises: 0003_recon
Create Date: 2026-10-28 04:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0004_nmap"
down_revision: Union[str, None] = "0003_recon"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. active_scan_jobs table
    op.create_table(
        "active_scan_jobs",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("investigation_id", sa.String(length=64), nullable=False),
        sa.Column("requested_by", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("resolved_ips", sa.JSON(), nullable=False),
        sa.Column("scan_profile", sa.String(length=64), nullable=False),
        sa.Column("scan_profile_version", sa.String(length=32), nullable=False, server_default="1.0"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="QUEUED"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("evidence_id", sa.String(length=64), nullable=True),
        sa.Column("error_category", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("cancellation_reason", sa.Text(), nullable=True),
        sa.Column("command_summary", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_active_scan_jobs_id"), "active_scan_jobs", ["id"], unique=False)
    op.create_index(op.f("ix_active_scan_jobs_investigation_id"), "active_scan_jobs", ["investigation_id"], unique=False)
    op.create_index(op.f("ix_active_scan_jobs_requested_by"), "active_scan_jobs", ["requested_by"], unique=False)
    op.create_index(op.f("ix_active_scan_jobs_target"), "active_scan_jobs", ["target"], unique=False)
    op.create_index(op.f("ix_active_scan_jobs_scan_profile"), "active_scan_jobs", ["scan_profile"], unique=False)
    op.create_index(op.f("ix_active_scan_jobs_status"), "active_scan_jobs", ["status"], unique=False)
    op.create_index(op.f("ix_active_scan_jobs_evidence_id"), "active_scan_jobs", ["evidence_id"], unique=False)

    # 2. scan_hosts table
    op.create_table(
        "scan_hosts",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("investigation_id", sa.String(length=64), nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("address", sa.String(length=255), nullable=False),
        sa.Column("address_type", sa.String(length=16), nullable=False, server_default="ipv4"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="up"),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("os_match", sa.String(length=255), nullable=True),
        sa.Column("evidence_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["job_id"], ["active_scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scan_hosts_id"), "scan_hosts", ["id"], unique=False)
    op.create_index(op.f("ix_scan_hosts_investigation_id"), "scan_hosts", ["investigation_id"], unique=False)
    op.create_index(op.f("ix_scan_hosts_job_id"), "scan_hosts", ["job_id"], unique=False)
    op.create_index(op.f("ix_scan_hosts_address"), "scan_hosts", ["address"], unique=False)
    op.create_index(op.f("ix_scan_hosts_hostname"), "scan_hosts", ["hostname"], unique=False)

    # 3. scan_ports table
    op.create_table(
        "scan_ports",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("host_id", sa.String(length=64), nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False, server_default="tcp"),
        sa.Column("port_number", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("service_name", sa.String(length=64), nullable=True),
        sa.Column("product", sa.String(length=128), nullable=True),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column("extra_info", sa.String(length=255), nullable=True),
        sa.Column("cpe", sa.String(length=255), nullable=True),
        sa.Column("method", sa.String(length=32), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["scan_hosts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["job_id"], ["active_scan_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scan_ports_id"), "scan_ports", ["id"], unique=False)
    op.create_index(op.f("ix_scan_ports_host_id"), "scan_ports", ["host_id"], unique=False)
    op.create_index(op.f("ix_scan_ports_job_id"), "scan_ports", ["job_id"], unique=False)
    op.create_index(op.f("ix_scan_ports_port_number"), "scan_ports", ["port_number"], unique=False)
    op.create_index(op.f("ix_scan_ports_state"), "scan_ports", ["state"], unique=False)
    op.create_index(op.f("ix_scan_ports_service_name"), "scan_ports", ["service_name"], unique=False)


def downgrade() -> None:
    op.drop_table("scan_ports")
    op.drop_table("scan_hosts")
    op.drop_table("active_scan_jobs")
