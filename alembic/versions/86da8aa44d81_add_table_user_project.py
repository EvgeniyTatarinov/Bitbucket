"""add table user project

Revision ID: 86da8aa44d81
Revises: 1c4e4838e136
Create Date: 2020-10-25 21:13:18.577947

"""
from sqlalchemy import func

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '86da8aa44d81'
down_revision = '1c4e4838e136'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'user',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('username', sa.String(50), unique=True),
        sa.Column('password', sa.String(255)),
    )


def downgrade():
    pass
