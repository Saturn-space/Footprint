"""acid_constraints_and_indexes

Revision ID: 003_acid_constraints
Revises: 002_recon_campaigns
Create Date: 2026-11-11 02:10:00.000000

Adds complete ACID constraints, transactional outbox table,
foreign keys, check constraints, indexes, and optimistic concurrency version columns.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '003_acid_constraints'
down_revision = '002_recon_campaigns'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Create Transactional Outbox table for SeaweedFS & external scanner reconciliation
    op.create_table(
        'external_artifacts_outbox',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('artifact_id', sa.String(length=64), nullable=False),
        sa.Column('investigation_id', sa.String(length=64), nullable=False),
        sa.Column('recon_id', sa.String(length=64), nullable=True),
        sa.Column('artifact_type', sa.String(length=50), nullable=False),
        sa.Column('external_reference_id', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='staged'),
        sa.Column('file_name', sa.String(length=255), nullable=True),
        sa.Column('sha256_hash', sa.String(length=64), nullable=True),
        sa.Column('details_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('artifact_id')
    )
    op.create_index('ix_outbox_artifact_id', 'external_artifacts_outbox', ['artifact_id'])
    op.create_index('ix_outbox_investigation_id', 'external_artifacts_outbox', ['investigation_id'])
    op.create_index('ix_outbox_status_type', 'external_artifacts_outbox', ['status', 'artifact_type'])

    # 2. Add optimistic concurrency version_id columns
    op.add_column(
        'recon_campaigns',
        sa.Column('version_id', sa.Integer(), nullable=False, server_default=sa.text('1'))
    )
    op.add_column(
        'vulnerability_findings',
        sa.Column('version_id', sa.Integer(), nullable=False, server_default=sa.text('1'))
    )

    # 3. Add missing foreign key constraints
    op.create_foreign_key(
        'fk_scan_executions_recon_id',
        'scan_executions', 'recon_campaigns',
        ['recon_id'], ['recon_id'],
        ondelete='SET NULL'
    )
    op.create_foreign_key(
        'fk_report_records_recon_id',
        'report_records', 'recon_campaigns',
        ['recon_id'], ['recon_id'],
        ondelete='SET NULL'
    )
    op.create_foreign_key(
        'fk_remediation_history_finding_id',
        'remediation_history', 'vulnerability_findings',
        ['finding_id'], ['finding_id'],
        ondelete='CASCADE'
    )

    # 4. Add SQL Server CHECK constraints for data integrity
    op.create_check_constraint(
        'chk_recon_campaigns_status',
        'recon_campaigns',
        "status IN ('Draft', 'Pending Authorization', 'Authorized', 'Queued', 'Running', 'Completed', 'Partially Completed', 'Failed', 'Cancelled', 'Interrupted')"
    )
    op.create_check_constraint(
        'chk_recon_campaigns_progress',
        'recon_campaigns',
        "progress >= 0 AND progress <= 100"
    )
    op.create_check_constraint(
        'chk_scan_executions_status',
        'scan_executions',
        "status IN ('queued', 'running', 'completed', 'failed', 'cancelled', 'interrupted', 'partially_completed')"
    )
    op.create_check_constraint(
        'chk_vulnerability_findings_severity',
        'vulnerability_findings',
        "severity IN ('Critical', 'High', 'Medium', 'Low', 'Informational', 'Info')"
    )
    op.create_check_constraint(
        'chk_vulnerability_findings_status',
        'vulnerability_findings',
        "finding_status IN ('open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive')"
    )
    op.create_check_constraint(
        'chk_vulnerability_findings_port',
        'vulnerability_findings',
        "port IS NULL OR (port >= 1 AND port <= 65535)"
    )
    op.create_check_constraint(
        'chk_vulnerability_findings_cvss',
        'vulnerability_findings',
        "cvss_score IS NULL OR (cvss_score >= 0.0 AND cvss_score <= 10.0)"
    )
    op.create_check_constraint(
        'chk_vulnerability_findings_confidence',
        'vulnerability_findings',
        "confidence >= 0.0 AND confidence <= 1.0"
    )
    op.create_check_constraint(
        'chk_investigations_exposure_score',
        'investigations',
        "exposure_score >= 0.0 AND exposure_score <= 100.0"
    )
    op.create_check_constraint(
        'chk_authorized_targets_status',
        'authorized_targets',
        "authorization_status IN ('AUTHORIZED_LOCAL_LAB', 'AUTHORIZED', 'PENDING_AUTHORIZATION', 'REVOKED')"
    )


def downgrade() -> None:
    op.drop_constraint('chk_authorized_targets_status', 'authorized_targets', type_='check')
    op.drop_constraint('chk_investigations_exposure_score', 'investigations', type_='check')
    op.drop_constraint('chk_vulnerability_findings_confidence', 'vulnerability_findings', type_='check')
    op.drop_constraint('chk_vulnerability_findings_cvss', 'vulnerability_findings', type_='check')
    op.drop_constraint('chk_vulnerability_findings_port', 'vulnerability_findings', type_='check')
    op.drop_constraint('chk_vulnerability_findings_status', 'vulnerability_findings', type_='check')
    op.drop_constraint('chk_vulnerability_findings_severity', 'vulnerability_findings', type_='check')
    op.drop_constraint('chk_scan_executions_status', 'scan_executions', type_='check')
    op.drop_constraint('chk_recon_campaigns_progress', 'recon_campaigns', type_='check')
    op.drop_constraint('chk_recon_campaigns_status', 'recon_campaigns', type_='check')

    op.drop_constraint('fk_remediation_history_finding_id', 'remediation_history', type_='foreignkey')
    op.drop_constraint('fk_report_records_recon_id', 'report_records', type_='foreignkey')
    op.drop_constraint('fk_scan_executions_recon_id', 'scan_executions', type_='foreignkey')

    op.drop_column('vulnerability_findings', 'version_id')
    op.drop_column('recon_campaigns', 'version_id')

    op.drop_index('ix_outbox_status_type', table_name='external_artifacts_outbox')
    op.drop_index('ix_outbox_investigation_id', table_name='external_artifacts_outbox')
    op.drop_index('ix_outbox_artifact_id', table_name='external_artifacts_outbox')
    op.drop_table('external_artifacts_outbox')

