"""add use_exclusive_c14n to empresas

Revision ID: 2a6f9b8c4d12
Revises: 1b0e3f7c9a21
Create Date: 2026-06-16 12:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "2a6f9b8c4d12"
down_revision: Union[str, None] = "1b0e3f7c9a21"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    empresa_columns = {c["name"] for c in inspector.get_columns("empresas")}

    if "use_exclusive_c14n" not in empresa_columns:
        op.add_column("empresas", sa.Column("use_exclusive_c14n", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("empresas", "use_exclusive_c14n")
