"""initial_sql_server_schema

Revision ID: 001_initial_mssql
Revises: 
Create Date: 2026-11-10 21:20:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '001_initial_mssql'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('uuid', sa.String(length=36), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False, server_default='investigator'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('is_approved', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('uuid'),
        sa.UniqueConstraint('username'),
        sa.UniqueConstraint('email')
    )
    op.create_index('ix_users_username', 'users', ['username'])
    op.create_index('ix_users_email', 'users', ['email'])

    # 2. Investigations table
    op.create_table(
        'investigations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('investigation_id', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('creator_id', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='active'),
        sa.Column('exposure_score', sa.Float(), nullable=False, server_default=sa.text('0.0')),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['creator_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('investigation_id')
    )
    op.create_index('ix_investigations_investigation_id', 'investigations', ['investigation_id'])

    # 3. Campaigns table
    op.create_table(
        'campaigns',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('campaign_id', sa.String(length=64), nullable=False),
        sa.Column('investigation_id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('campaign_id')
    )
    op.create_index('ix_campaigns_campaign_id', 'campaigns', ['campaign_id'])

    # 4. Authorized Targets table
    op.create_table(
        'authorized_targets',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('target_id', sa.String(length=64), nullable=False),
        sa.Column('investigation_id', sa.Integer(), nullable=False),
        sa.Column('target', sa.String(length=255), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('category', sa.String(length=100), nullable=False),
        sa.Column('scope', sa.String(length=255), nullable=False),
        sa.Column('permitted_profiles', sa.String(length=255), nullable=False),
        sa.Column('allowed_ports', sa.String(length=100), nullable=False),
        sa.Column('authorization_status', sa.String(length=50), nullable=False),
        sa.Column('authorized_by', sa.String(length=100), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('target_id')
    )
    op.create_index('ix_authorized_targets_target', 'authorized_targets', ['target'])

    # 5. Scan Executions table
    op.create_table(
        'scan_executions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.String(length=64), nullable=False),
        sa.Column('investigation_id', sa.Integer(), nullable=False),
        sa.Column('scan_type', sa.String(length=50), nullable=False),
        sa.Column('target', sa.String(length=255), nullable=False),
        sa.Column('profile', sa.String(length=100), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='queued'),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('result_summary_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('scan_id')
    )
    op.create_index('ix_scan_investigation_status', 'scan_executions', ['investigation_id', 'status'])

    # 6. Vulnerability Findings table
    op.create_table(
        'vulnerability_findings',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('finding_id', sa.String(length=64), nullable=False),
        sa.Column('investigation_id', sa.Integer(), nullable=False),
        sa.Column('scan_execution_id', sa.Integer(), nullable=True),
        sa.Column('target_ip', sa.String(length=100), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(length=20), nullable=False, server_default='tcp'),
        sa.Column('service', sa.String(length=100), nullable=True),
        sa.Column('service_version', sa.String(length=100), nullable=True),
        sa.Column('title', sa.String(length=300), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('cve_identifiers', sa.String(length=500), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default=sa.text('1.0')),
        sa.Column('detection_source', sa.String(length=50), nullable=False),
        sa.Column('scanner_vt_id', sa.String(length=100), nullable=True),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('evidence_reference', sa.String(length=255), nullable=True),
        sa.Column('verification_status', sa.String(length=50), nullable=False, server_default='unverified'),
        sa.Column('finding_status', sa.String(length=50), nullable=False, server_default='open'),
        sa.Column('first_detected', sa.DateTime(), nullable=False),
        sa.Column('last_detected', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_execution_id'], ['scan_executions.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('finding_id')
    )
    op.create_index('ix_vulnerability_target_port', 'vulnerability_findings', ['target_ip', 'port'])
    op.create_index('ix_vulnerability_investigation_severity', 'vulnerability_findings', ['investigation_id', 'severity'])

    # 7. Evidence Records table
    op.create_table(
        'evidence_records',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('evidence_id', sa.String(length=64), nullable=False),
        sa.Column('investigation_id', sa.Integer(), nullable=False),
        sa.Column('scan_execution_id', sa.Integer(), nullable=True),
        sa.Column('evidence_type', sa.String(length=50), nullable=False),
        sa.Column('file_name', sa.String(length=255), nullable=False),
        sa.Column('file_size', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('content_type', sa.String(length=100), nullable=False),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('seaweed_fid', sa.String(length=100), nullable=True),
        sa.Column('seaweed_url', sa.String(length=255), nullable=True),
        sa.Column('local_path', sa.String(length=500), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_execution_id'], ['scan_executions.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('evidence_id')
    )
    op.create_index('ix_evidence_investigation_type', 'evidence_records', ['investigation_id', 'evidence_type'])
    op.create_index('ix_evidence_sha256', 'evidence_records', ['sha256_hash'])

    # 8. Report Records table
    op.create_table(
        'report_records',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('report_id', sa.String(length=64), nullable=False),
        sa.Column('investigation_id', sa.Integer(), nullable=False),
        sa.Column('report_type', sa.String(length=50), nullable=False, server_default='pdf'),
        sa.Column('file_name', sa.String(length=255), nullable=False),
        sa.Column('file_size', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('seaweed_fid', sa.String(length=100), nullable=True),
        sa.Column('generated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('report_id')
    )

    # 9. Audit Logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('target_resource', sa.String(length=255), nullable=True),
        sa.Column('details_json', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(length=50), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('report_records')
    op.drop_table('evidence_records')
    op.drop_table('vulnerability_findings')
    op.drop_table('scan_executions')
    op.drop_table('authorized_targets')
    op.drop_table('campaigns')
    op.drop_table('investigations')
    op.drop_table('users')

