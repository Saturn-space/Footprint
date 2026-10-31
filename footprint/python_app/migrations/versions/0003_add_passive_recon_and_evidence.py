"""Add target authorizations, collection jobs, evidence, and entities tables

Revision ID: 0003_recon
Revises: 0002_auth
Create Date: 2026-10-28 03:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0003_recon"
down_revision: Union[str, None] = "0002_auth"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. target_authorizations table
    op.create_table(
        "target_authorizations",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("investigation_id", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=False),
        sa.Column("allowed_operations", sa.JSON(), nullable=False),
        sa.Column("authorization_reference", sa.String(length=128), nullable=False),
        sa.Column("approved_by", sa.String(length=64), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index(op.f("ix_target_authorizations_id"), "target_authorizations", ["id"], unique=False)
    op.create_index(op.f("ix_target_authorizations_investigation_id"), "target_authorizations", ["investigation_id"], unique=False)
    op.create_index(op.f("ix_target_authorizations_target"), "target_authorizations", ["target"], unique=False)
    op.create_index(op.f("ix_target_authorizations_is_revoked"), "target_authorizations", ["is_revoked"], unique=False)

    # 2. collection_jobs table
    op.create_table(
        "collection_jobs",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("investigation_id", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("collector_name", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="QUEUED"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_summary", sa.JSON(), nullable=False),
        sa.Column("error_category", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index(op.f("ix_collection_jobs_id"), "collection_jobs", ["id"], unique=False)
    op.create_index(op.f("ix_collection_jobs_investigation_id"), "collection_jobs", ["investigation_id"], unique=False)
    op.create_index(op.f("ix_collection_jobs_target"), "collection_jobs", ["target"], unique=False)
    op.create_index(op.f("ix_collection_jobs_collector_name"), "collection_jobs", ["collector_name"], unique=False)
    op.create_index(op.f("ix_collection_jobs_status"), "collection_jobs", ["status"], unique=False)

    # 3. evidence table
    op.create_table(
        "evidence",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("investigation_id", sa.String(length=64), nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=True),
        sa.Column("source_type", sa.String(length=64), nullable=False),
        sa.Column("source_name", sa.String(length=128), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("collection_status", sa.String(length=32), nullable=False, server_default="SUCCESS"),
        sa.Column("raw_content_path", sa.String(length=512), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("content_size_bytes", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("source_metadata", sa.JSON(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["job_id"], ["collection_jobs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index(op.f("ix_evidence_id"), "evidence", ["id"], unique=False)
    op.create_index(op.f("ix_evidence_investigation_id"), "evidence", ["investigation_id"], unique=False)
    op.create_index(op.f("ix_evidence_job_id"), "evidence", ["job_id"], unique=False)
    op.create_index(op.f("ix_evidence_source_type"), "evidence", ["source_type"], unique=False)
    op.create_index(op.f("ix_evidence_target"), "evidence", ["target"], unique=False)

    # 4. entities table
    op.create_table(
        "entities",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("investigation_id", sa.String(length=64), nullable=False),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("canonical_value", sa.String(length=512), nullable=False),
        sa.Column("original_value", sa.Text(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id")
    )
    op.create_index(op.f("ix_entities_id"), "entities", ["id"], unique=False)
    op.create_index(op.f("ix_entities_investigation_id"), "entities", ["investigation_id"], unique=False)
    op.create_index(op.f("ix_entities_entity_type"), "entities", ["entity_type"], unique=False)
    op.create_index(op.f("ix_entities_canonical_value"), "entities", ["canonical_value"], unique=False)


def downgrade() -> None:
    # Drop entities
    op.drop_index(op.f("ix_entities_canonical_value"), table_name="entities")
    op.drop_index(op.f("ix_entities_entity_type"), table_name="entities")
    op.drop_index(op.f("ix_entities_investigation_id"), table_name="entities")
    op.drop_index(op.f("ix_entities_id"), table_name="entities")
    op.drop_table("entities")

    # Drop evidence
    op.drop_index(op.f("ix_evidence_target"), table_name="evidence")
    op.drop_index(op.f("ix_evidence_source_type"), table_name="evidence")
    op.drop_index(op.f("ix_evidence_job_id"), table_name="evidence")
    op.drop_index(op.f("ix_evidence_investigation_id"), table_name="evidence")
    op.drop_index(op.f("ix_evidence_id"), table_name="evidence")
    op.drop_table("evidence")

    # Drop collection_jobs
    op.drop_index(op.f("ix_collection_jobs_status"), table_name="collection_jobs")
    op.drop_index(op.f("ix_collection_jobs_collector_name"), table_name="collection_jobs")
    op.drop_index(op.f("ix_collection_jobs_target"), table_name="collection_jobs")
    op.drop_index(op.f("ix_collection_jobs_investigation_id"), table_name="collection_jobs")
    op.drop_index(op.f("ix_collection_jobs_id"), table_name="collection_jobs")
    op.drop_table("collection_jobs")

    # Drop target_authorizations
    op.drop_index(op.f("ix_target_authorizations_is_revoked"), table_name="target_authorizations")
    op.drop_index(op.f("ix_target_authorizations_target"), table_name="target_authorizations")
    op.drop_index(op.f("ix_target_authorizations_investigation_id"), table_name="target_authorizations")
    op.drop_index(op.f("ix_target_authorizations_id"), table_name="target_authorizations")
    op.drop_table("target_authorizations")
