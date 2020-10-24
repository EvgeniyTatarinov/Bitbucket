"""new table

Revision ID: b670bfdbcedf
Revises: a4e2a57fb347
Create Date: 2020-10-21 22:39:25.823925

"""
from alembic import op
from sqlalchemy import Column, INTEGER, ForeignKey
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b670bfdbcedf'
down_revision = 'a4e2a57fb347'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'url',
        sa.Column('id', sa.Integer, primary_key=True),
        # sa.Column('date', sa.Date()),
        sa.Column('full_address', sa.String(255)),
        sa.Column('abbreviated_address', sa.String(255), unique=True),
        sa.Column('access_level', sa.String(10), default='general'),
        sa.Column('rating', sa.Integer, default=0),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('user.id'))
    )


def downgrade():
    op.drop_table('account')
