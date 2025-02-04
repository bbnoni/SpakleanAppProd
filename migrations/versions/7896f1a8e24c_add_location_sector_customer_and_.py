"""Add Location, Sector, Customer, and Building models

Revision ID: 7896f1a8e24c
Revises: 2d87ded02b5f
Create Date: 2024-12-19 01:38:35.437793

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '7896f1a8e24c'
down_revision = '2d87ded02b5f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('location',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('sector',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('location_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['location_id'], ['location.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('customer',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('sector_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['sector_id'], ['sector.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('building',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('customer_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['customer_id'], ['customer.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('notification', schema=None) as batch_op:
        batch_op.alter_column('message',
               existing_type=sa.VARCHAR(length=255),
               type_=sa.String(length=256),
               existing_nullable=False)
        batch_op.alter_column('timestamp',
               existing_type=postgresql.TIMESTAMP(),
               nullable=False,
               existing_server_default=sa.text('CURRENT_TIMESTAMP'))
        batch_op.alter_column('is_read',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('false'))
        batch_op.create_foreign_key(None, 'user', ['user_id'], ['id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('notification', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.alter_column('is_read',
               existing_type=sa.BOOLEAN(),
               nullable=True,
               existing_server_default=sa.text('false'))
        batch_op.alter_column('timestamp',
               existing_type=postgresql.TIMESTAMP(),
               nullable=True,
               existing_server_default=sa.text('CURRENT_TIMESTAMP'))
        batch_op.alter_column('message',
               existing_type=sa.String(length=256),
               type_=sa.VARCHAR(length=255),
               existing_nullable=False)

    op.drop_table('building')
    op.drop_table('customer')
    op.drop_table('sector')
    op.drop_table('location')
    # ### end Alembic commands ###
