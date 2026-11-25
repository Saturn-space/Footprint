"""upgrade_runs_reports_settings

Revision ID: 005_upgrade_runs_reports
Revises: 004_rbac_audit_reports
Create Date: 2026-11-12 00:18:00.000000

Adds SQL Server 2022 schema support for:
- Repeatable scan runs under one investigation (run_number, per-run scanner/config/version metadata, duration, initiator)
- Report linkage to exact scan runs and investigation metadata (scan_execution_id, scan_id, run_number, scan_type, investigation_name, report_status)
- Evidence linkage & attribution (scan_id, run_number, scanner_source, target)
- Investigator profile, last_login_at, theme/timezone/notification preferences, and token_version
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '005_upgrade_runs_reports'
down_revision = '004_rbac_audit_reports'
branch_labels = None
depends_on = None


def _drop_mssql_default_constraint(table_name: str, column_name: str) -> None:
    """Safely drop auto-generated SQL Server DEFAULT constraint before dropping a column."""
    op.execute(
        f"""
        DECLARE @c sysname;
        SELECT @c = dc.name
        FROM sys.default_constraints dc
        INNER JOIN sys.columns col
            ON dc.parent_object_id = col.object_id AND dc.parent_column_id = col.column_id
        WHERE dc.parent_object_id = OBJECT_ID('{table_name}')
          AND col.name = '{column_name}';
        IF @c IS NOT NULL
            EXEC('ALTER TABLE [{table_name}] DROP CONSTRAINT [' + @c + ']');
        """
    )


def upgrade() -> None:
    # 1. Users profile, preferences, session version & last_login_at
    op.add_column('users', sa.Column('full_name', sa.String(length=150), nullable=True))
    op.add_column('users', sa.Column('last_login_at', sa.DateTime(), nullable=True))
    op.add_column(
        'users',
        sa.Column('theme_preference', sa.String(length=20), nullable=False, server_default='light')
    )
    op.add_column(
        'users',
        sa.Column('timezone_preference', sa.String(length=64), nullable=False, server_default='Asia/Kolkata')
    )
    op.add_column('users', sa.Column('notification_preferences_json', sa.Text(), nullable=True))
    op.add_column(
        'users',
        sa.Column('token_version', sa.Integer(), nullable=False, server_default='1')
    )
    op.create_check_constraint(
        'chk_users_theme_preference',
        'users',
        "theme_preference IN ('light', 'dark', 'system')"
    )

    # 2. ScanExecution repeatable run metadata
    op.add_column(
        'scan_executions',
        sa.Column('run_number', sa.Integer(), nullable=False, server_default='1')
    )
    op.add_column('scan_executions', sa.Column('initiating_user_id', sa.Integer(), nullable=True))
    op.add_column('scan_executions', sa.Column('initiated_by', sa.String(length=100), nullable=True))
    op.add_column('scan_executions', sa.Column('selected_scanners_json', sa.Text(), nullable=True))
    op.add_column('scan_executions', sa.Column('selected_components_json', sa.Text(), nullable=True))
    op.add_column('scan_executions', sa.Column('scan_config_json', sa.Text(), nullable=True))
    op.add_column('scan_executions', sa.Column('scanner_versions_json', sa.Text(), nullable=True))
    op.add_column('scan_executions', sa.Column('target_authorization_ref', sa.String(length=128), nullable=True))
    op.add_column('scan_executions', sa.Column('duration_seconds', sa.Float(), nullable=True))
    op.create_foreign_key(
        'fk_scan_executions_initiating_user',
        'scan_executions', 'users',
        ['initiating_user_id'], ['id'],
        ondelete='NO ACTION'
    )
    op.create_index('ix_scan_executions_inv_run', 'scan_executions', ['investigation_id', 'run_number'])

    # 3. EvidenceRecord run & scanner linkage
    op.add_column('evidence_records', sa.Column('scan_id', sa.String(length=64), nullable=True))
    op.add_column('evidence_records', sa.Column('run_number', sa.Integer(), nullable=True))
    op.add_column('evidence_records', sa.Column('scanner_source', sa.String(length=64), nullable=True))
    op.add_column('evidence_records', sa.Column('target', sa.String(length=255), nullable=True))
    op.create_index('ix_evidence_records_scan_id', 'evidence_records', ['scan_id'])
    op.create_index('ix_evidence_records_scanner_source', 'evidence_records', ['scanner_source'])

    # 4. ReportRecord scan run linkage & investigation-based metadata
    op.add_column('report_records', sa.Column('scan_execution_id', sa.Integer(), nullable=True))
    op.add_column('report_records', sa.Column('scan_id', sa.String(length=64), nullable=True))
    op.add_column('report_records', sa.Column('run_number', sa.Integer(), nullable=True))
    op.add_column('report_records', sa.Column('scan_type', sa.String(length=50), nullable=True))
    op.add_column('report_records', sa.Column('investigation_name', sa.String(length=200), nullable=True))
    op.add_column(
        'report_records',
        sa.Column('report_status', sa.String(length=40), nullable=False, server_default='completed')
    )
    op.create_foreign_key(
        'fk_report_records_scan_execution',
        'report_records', 'scan_executions',
        ['scan_execution_id'], ['id'],
        ondelete='NO ACTION'
    )
    op.create_index('ix_report_records_scan_id', 'report_records', ['scan_id'])


def downgrade() -> None:
    op.drop_index('ix_report_records_scan_id', table_name='report_records')
    op.drop_constraint('fk_report_records_scan_execution', 'report_records', type_='foreignkey')
    _drop_mssql_default_constraint('report_records', 'report_status')
    op.drop_column('report_records', 'report_status')
    op.drop_column('report_records', 'investigation_name')
    op.drop_column('report_records', 'scan_type')
    op.drop_column('report_records', 'run_number')
    op.drop_column('report_records', 'scan_id')
    op.drop_column('report_records', 'scan_execution_id')

    op.drop_index('ix_evidence_records_scanner_source', table_name='evidence_records')
    op.drop_index('ix_evidence_records_scan_id', table_name='evidence_records')
    op.drop_column('evidence_records', 'target')
    op.drop_column('evidence_records', 'scanner_source')
    op.drop_column('evidence_records', 'run_number')
    op.drop_column('evidence_records', 'scan_id')

    op.drop_index('ix_scan_executions_inv_run', table_name='scan_executions')
    op.drop_constraint('fk_scan_executions_initiating_user', 'scan_executions', type_='foreignkey')
    op.drop_column('scan_executions', 'duration_seconds')
    op.drop_column('scan_executions', 'target_authorization_ref')
    op.drop_column('scan_executions', 'scanner_versions_json')
    op.drop_column('scan_executions', 'scan_config_json')
    op.drop_column('scan_executions', 'selected_components_json')
    op.drop_column('scan_executions', 'selected_scanners_json')
    op.drop_column('scan_executions', 'initiated_by')
    op.drop_column('scan_executions', 'initiating_user_id')
    _drop_mssql_default_constraint('scan_executions', 'run_number')
    op.drop_column('scan_executions', 'run_number')

    op.drop_constraint('chk_users_theme_preference', 'users', type_='check')
    _drop_mssql_default_constraint('users', 'token_version')
    _drop_mssql_default_constraint('users', 'timezone_preference')
    _drop_mssql_default_constraint('users', 'theme_preference')
    op.drop_column('users', 'token_version')
    op.drop_column('users', 'notification_preferences_json')
    op.drop_column('users', 'timezone_preference')
    op.drop_column('users', 'theme_preference')
    op.drop_column('users', 'last_login_at')
    op.drop_column('users', 'full_name')

