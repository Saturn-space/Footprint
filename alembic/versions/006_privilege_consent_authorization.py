"""privilege_consent_authorization

Revision ID: 006_privilege_consent_auth
Revises: 005_upgrade_runs_reports
Create Date: 2026-11-17 23:45:00.000000

Adds SQL Server 2022 schema support for Privilege Consent & Authorization (PSA):
- privilege_consent_given (BIT)
- privilege_elevation_required (BIT)
- privilege_status (VARCHAR(32))
- privilege_authorized_at (DATETIME)
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '006_privilege_consent_auth'
down_revision = '005_upgrade_runs_reports'
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
    # 1. Add PSA columns to scan_executions
    op.add_column(
        'scan_executions',
        sa.Column('privilege_consent_given', sa.Boolean(), nullable=False, server_default=sa.text('0'))
    )
    op.add_column(
        'scan_executions',
        sa.Column('privilege_elevation_required', sa.Boolean(), nullable=False, server_default=sa.text('0'))
    )
    op.add_column(
        'scan_executions',
        sa.Column('privilege_status', sa.String(length=32), nullable=False, server_default='none')
    )
    op.add_column(
        'scan_executions',
        sa.Column('privilege_authorized_at', sa.DateTime(), nullable=True)
    )


def downgrade() -> None:
    _drop_mssql_default_constraint('scan_executions', 'privilege_consent_given')
    op.drop_column('scan_executions', 'privilege_consent_given')

    _drop_mssql_default_constraint('scan_executions', 'privilege_elevation_required')
    op.drop_column('scan_executions', 'privilege_elevation_required')

    _drop_mssql_default_constraint('scan_executions', 'privilege_status')
    op.drop_column('scan_executions', 'privilege_status')

    op.drop_column('scan_executions', 'privilege_authorized_at')
