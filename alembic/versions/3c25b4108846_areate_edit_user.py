"""areate edit user

Revision ID: 3c25b4108846
Revises: 54c83c2bdf9b
Create Date: 2020-10-21 22:28:34.828473

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3c25b4108846'
down_revision = '54c83c2bdf9b'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'user',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('username', sa.String(50), unique=True),
        sa.Column('password', sa.String(255)),
    )


def downgrade():
    pass
