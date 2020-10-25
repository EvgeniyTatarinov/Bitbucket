"""add table url project

Revision ID: 9f877029913e
Revises: 86da8aa44d81
Create Date: 2020-10-25 21:21:54.952147

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9f877029913e'
down_revision = '86da8aa44d81'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'url',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('datetime', sa.DateTime(timezone=True), server_default=func.now()),
        sa.Column('full_address', sa.String(255)),
        sa.Column('abbreviated_address', sa.String(255), unique=True),
        sa.Column('access_level', sa.String(10), default='general'),
        sa.Column('rating', sa.Integer, default=0),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('user.id'))
    )


def downgrade():
    pass
