"""recon_campaigns_and_events

Revision ID: 002_recon_campaigns
Revises: 001_initial_mssql
Create Date: 2026-11-10 23:25:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '002_recon_campaigns'
down_revision = '001_initial_mssql'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Recon Campaigns table
    op.create_table(
        'recon_campaigns',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('recon_id', sa.String(length=64), nullable=False),
        sa.Column('investigation_id', sa.String(length=64), nullable=True),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('purpose', sa.String(length=255), nullable=True),
        sa.Column('scope_description', sa.Text(), nullable=True),
        sa.Column('target_type', sa.String(length=50), nullable=False, server_default='ipv4'),
        sa.Column('target_value', sa.String(length=255), nullable=False),
        sa.Column('excluded_targets', sa.Text(), nullable=True),
        sa.Column('excluded_ports', sa.String(length=255), nullable=True),
        sa.Column('allowed_methods', sa.String(length=255), nullable=False, server_default='all'),
        sa.Column('allowed_ports', sa.String(length=255), nullable=False, server_default='1-65535'),
        sa.Column('authorization_status', sa.String(length=50), nullable=False, server_default='Authorized'),
        sa.Column('authorized_by', sa.String(length=100), nullable=False, server_default='asip_ali'),
        sa.Column('authorized_at', sa.DateTime(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='Draft'),
        sa.Column('selected_scan_types', sa.Text(), nullable=True),
        sa.Column('scan_config_json', sa.Text(), nullable=True),
        sa.Column('progress', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('current_stage', sa.String(length=100), nullable=True),
        sa.Column('creator_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['creator_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('recon_id')
    )
    op.create_index('ix_recon_campaigns_recon_id', 'recon_campaigns', ['recon_id'])
    op.create_index('ix_recon_campaigns_status', 'recon_campaigns', ['status'])

    # 2. Scan Execution Events table (Terminal live log & state persistence)
    op.create_table(
        'scan_execution_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.String(length=64), nullable=False),
        sa.Column('recon_id', sa.String(length=64), nullable=True),
        sa.Column('event_type', sa.String(length=50), nullable=False, server_default='log'),
        sa.Column('stage', sa.String(length=100), nullable=True),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('details_json', sa.Text(), nullable=True),
        sa.Column('progress', sa.Integer(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['recon_id'], ['recon_campaigns.recon_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scan_execution_events_scan_id', 'scan_execution_events', ['scan_id'])
    op.create_index('ix_scan_execution_events_timestamp', 'scan_execution_events', ['scan_id', 'timestamp'])

    # 3. Saved Scan Profiles table
    op.create_table(
        'saved_scan_profiles',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(length=50), nullable=False, server_default='general'),
        sa.Column('config_json', sa.Text(), nullable=False),
        sa.Column('is_builtin', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('created_by', sa.String(length=100), nullable=False, server_default='system'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )

    # 4. Remediation History table
    op.create_table(
        'remediation_history',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('finding_id', sa.String(length=64), nullable=False),
        sa.Column('previous_status', sa.String(length=50), nullable=False),
        sa.Column('new_status', sa.String(length=50), nullable=False),
        sa.Column('changed_by', sa.String(length=100), nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_remediation_history_finding_id', 'remediation_history', ['finding_id'])

    # 5. Add columns to scan_executions and report_records
    op.add_column('scan_executions', sa.Column('recon_id', sa.String(length=64), nullable=True))
    op.add_column('report_records', sa.Column('recon_id', sa.String(length=64), nullable=True))
    op.add_column('vulnerability_findings', sa.Column('remediation_notes', sa.Text(), nullable=True))
    op.add_column('vulnerability_findings', sa.Column('status_updated_by', sa.String(length=100), nullable=True))
    op.add_column('vulnerability_findings', sa.Column('status_updated_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column('vulnerability_findings', 'status_updated_at')
    op.drop_column('vulnerability_findings', 'status_updated_by')
    op.drop_column('vulnerability_findings', 'remediation_notes')
    op.drop_column('report_records', 'recon_id')
    op.drop_column('scan_executions', 'recon_id')
    op.drop_table('remediation_history')
    op.drop_table('saved_scan_profiles')
    op.drop_table('scan_execution_events')
    op.drop_table('recon_campaigns')

