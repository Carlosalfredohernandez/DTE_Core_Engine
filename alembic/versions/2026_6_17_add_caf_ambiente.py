"""
add caf.ambiente column

Revision ID: 2026_6_17_add_caf_ambiente
Revises: 2026_6_3_0011_empresa_branding
Create Date: 2026-06-17 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '2026_6_17_add_caf_ambiente'
down_revision = '1b0e3f7c9a21'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('cafs', sa.Column('ambiente', sa.String(length=20), nullable=True))


def downgrade():
    op.drop_column('cafs', 'ambiente')
