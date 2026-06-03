"""multiempresa base

Revision ID: 9d1c7f2a4b3e
Revises: 4b2c91786e36
Create Date: 2026-06-03 10:10:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "9d1c7f2a4b3e"
down_revision: Union[str, None] = "4b2c91786e36"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "empresas",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("rut_emisor", sa.String(length=12), nullable=False),
        sa.Column("rut_envia", sa.String(length=12), nullable=False),
        sa.Column("razon_social_emisor", sa.String(length=150), nullable=False),
        sa.Column("giro_emisor", sa.String(length=150), nullable=False),
        sa.Column("acteco_emisor", sa.Integer(), nullable=False),
        sa.Column("dir_origen", sa.String(length=200), nullable=False),
        sa.Column("cmna_origen", sa.String(length=100), nullable=False),
        sa.Column("ciudad_origen", sa.String(length=100), nullable=False),
        sa.Column("sii_ambiente", sa.String(length=20), nullable=False),
        sa.Column("sii_fecha_resolucion", sa.String(length=10), nullable=False),
        sa.Column("sii_numero_resolucion", sa.Integer(), nullable=False),
        sa.Column("brand_name", sa.String(length=150), nullable=True),
        sa.Column("brand_logo_url", sa.String(length=500), nullable=True),
        sa.Column("brand_accent_1", sa.String(length=20), nullable=True),
        sa.Column("brand_accent_2", sa.String(length=20), nullable=True),
        sa.Column("api_key", sa.String(length=120), nullable=True),
        sa.Column("cert_pfx_path", sa.String(length=255), nullable=True),
        sa.Column("cert_pfx_base64", sa.Text(), nullable=True),
        sa.Column("cert_pfx_password", sa.String(length=255), nullable=True),
        sa.Column("es_default", sa.Boolean(), nullable=False),
        sa.Column("activo", sa.Boolean(), nullable=False),
        sa.Column("fecha_creacion", sa.DateTime(), nullable=True),
        sa.Column("fecha_actualizacion", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("api_key"),
    )

    op.add_column("cafs", sa.Column("empresa_id", sa.Integer(), nullable=True))
    op.add_column("dtes", sa.Column("empresa_id", sa.Integer(), nullable=True))
    op.add_column("sii_log", sa.Column("empresa_id", sa.Integer(), nullable=True))

    op.create_foreign_key("fk_cafs_empresas", "cafs", "empresas", ["empresa_id"], ["id"])
    op.create_foreign_key("fk_dtes_empresas", "dtes", "empresas", ["empresa_id"], ["id"])
    op.create_foreign_key("fk_sii_log_empresas", "sii_log", "empresas", ["empresa_id"], ["id"])


def downgrade() -> None:
    op.drop_constraint("fk_sii_log_empresas", "sii_log", type_="foreignkey")
    op.drop_constraint("fk_dtes_empresas", "dtes", type_="foreignkey")
    op.drop_constraint("fk_cafs_empresas", "cafs", type_="foreignkey")

    op.drop_column("sii_log", "empresa_id")
    op.drop_column("dtes", "empresa_id")
    op.drop_column("cafs", "empresa_id")
    op.drop_table("empresas")
