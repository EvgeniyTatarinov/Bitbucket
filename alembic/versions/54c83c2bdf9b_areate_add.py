"""areate add

Revision ID: 54c83c2bdf9b
Revises: 245d4057a9e0
Create Date: 2020-10-21 22:26:57.566150

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '54c83c2bdf9b'
down_revision = '245d4057a9e0'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'user',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('username', sa.String(50)),
        sa.Column('password', sa.String(255)),
    )


def downgrade():
    pass
