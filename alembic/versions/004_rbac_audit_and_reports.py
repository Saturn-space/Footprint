"""rbac_audit_and_reports

Revision ID: 004_rbac_audit_reports
Revises: 003_acid_constraints
Create Date: 2026-11-11 19:05:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '004_rbac_audit_reports'
down_revision = '003_acid_constraints'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Enrich audit_logs with actor_role and outcome tracking
    op.add_column('audit_logs', sa.Column('actor_role', sa.String(length=50), nullable=True))
    op.add_column(
        'audit_logs',
        sa.Column('outcome', sa.String(length=30), nullable=False, server_default='SUCCESS')
    )
    op.create_index('ix_audit_logs_outcome', 'audit_logs', ['outcome'])
    op.create_index('ix_audit_logs_timestamp', 'audit_logs', ['timestamp'])
    op.create_check_constraint(
        'chk_audit_logs_outcome',
        'audit_logs',
        "outcome IN ('SUCCESS', 'DENIED', 'FAILED')"
    )

    # 2. Enrich report_records with generating actor attribution (NO ACTION avoids MSSQL cascade cycles)
    op.add_column('report_records', sa.Column('generated_by_user_id', sa.Integer(), nullable=True))
    op.add_column('report_records', sa.Column('generated_by_username', sa.String(length=100), nullable=True))
    op.create_foreign_key(
        'fk_report_records_generated_by',
        'report_records', 'users',
        ['generated_by_user_id'], ['id'],
        ondelete='NO ACTION'
    )

    # 3. Enforce strict valid user role domain ('admin', 'investigator')
    op.create_check_constraint(
        'chk_users_role',
        'users',
        "role IN ('admin', 'investigator')"
    )

    # 4. Create investigation_shares table for explicit cross-investigator sharing
    op.create_table(
        'investigation_shares',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('investigation_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('granted_by_id', sa.Integer(), nullable=True),
        sa.Column('permission_level', sa.String(length=30), nullable=False, server_default='read_write'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='NO ACTION'),
        sa.ForeignKeyConstraint(['granted_by_id'], ['users.id'], ondelete='NO ACTION'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('investigation_id', 'user_id', name='uq_investigation_share_user')
    )
    op.create_index('ix_investigation_shares_investigation_id', 'investigation_shares', ['investigation_id'])
    op.create_index('ix_investigation_shares_user_id', 'investigation_shares', ['user_id'])


def downgrade() -> None:
    op.drop_index('ix_investigation_shares_user_id', table_name='investigation_shares')
    op.drop_index('ix_investigation_shares_investigation_id', table_name='investigation_shares')
    op.drop_table('investigation_shares')

    op.drop_constraint('chk_users_role', 'users', type_='check')

    op.drop_constraint('fk_report_records_generated_by', 'report_records', type_='foreignkey')
    op.drop_column('report_records', 'generated_by_username')
    op.drop_column('report_records', 'generated_by_user_id')

    op.drop_constraint('chk_audit_logs_outcome', 'audit_logs', type_='check')
    op.drop_index('ix_audit_logs_timestamp', table_name='audit_logs')
    op.drop_index('ix_audit_logs_outcome', table_name='audit_logs')
    op.drop_column('audit_logs', 'outcome')
    op.drop_column('audit_logs', 'actor_role')
