"""Initial investigation foundation schema

Revision ID: 0001_initial
Revises: 
Create Date: 2026-10-27 22:50:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("organization_name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("lead_investigator", sa.String(length=128), nullable=False),
        sa.Column("team_members", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("owned_domains", sa.JSON(), nullable=False),
        sa.Column("approved_ips", sa.JSON(), nullable=False),
        sa.Column("approved_cidrs", sa.JSON(), nullable=False),
        sa.Column("active_targets", sa.JSON(), nullable=False),
        sa.Column("active_scanning_enabled", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("authorization_reference", sa.String(length=128), nullable=True),
        sa.Column("authorization_expiry", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index(op.f("ix_investigations_id"), "investigations", ["id"], unique=False)
    op.create_index(op.f("ix_investigations_name"), "investigations", ["name"], unique=False)
    op.create_index(op.f("ix_investigations_status"), "investigations", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_investigations_status"), table_name="investigations")
    op.drop_index(op.f("ix_investigations_name"), table_name="investigations")
    op.drop_index(op.f("ix_investigations_id"), table_name="investigations")
    op.drop_table("investigations")
