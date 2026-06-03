"""empresa branding

Revision ID: 1b0e3f7c9a21
Revises: 9d1c7f2a4b3e
Create Date: 2026-06-03 12:10:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "1b0e3f7c9a21"
down_revision: Union[str, None] = "9d1c7f2a4b3e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("empresas", sa.Column("brand_name", sa.String(length=150), nullable=True))
    op.add_column("empresas", sa.Column("brand_logo_url", sa.String(length=500), nullable=True))
    op.add_column("empresas", sa.Column("brand_accent_1", sa.String(length=20), nullable=True))
    op.add_column("empresas", sa.Column("brand_accent_2", sa.String(length=20), nullable=True))


def downgrade() -> None:
    op.drop_column("empresas", "brand_accent_2")
    op.drop_column("empresas", "brand_accent_1")
    op.drop_column("empresas", "brand_logo_url")
    op.drop_column("empresas", "brand_name")
