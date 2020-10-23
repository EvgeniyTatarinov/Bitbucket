"""delete table account

Revision ID: a4e2a57fb347
Revises: 3c25b4108846
Create Date: 2020-10-21 22:30:16.081774

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a4e2a57fb347'
down_revision = '3c25b4108846'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'url',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('full_address', sa.String(255)),
        sa.Column('abbreviated_address', sa.String(255), unique=True),
        sa.Column('access_level', sa.String(10), default='general'),
        sa.Column('rating', sa.Integer, default=0),
        sa.Column('user_id', sa.ForeignKey('user.id'))
    )


def downgrade():
    op.drop_table('account')
