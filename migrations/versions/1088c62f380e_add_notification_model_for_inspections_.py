"""Add Notification model for inspections on behalf of others

Revision ID: 1088c62f380e
Revises: a63a28f46464
Create Date: 2024-11-11 14:16:32.113625

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1088c62f380e'
down_revision = 'a63a28f46464'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('notification',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('message', sa.String(length=256), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=False),
    sa.Column('is_read', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('notification')
    # ### end Alembic commands ###
