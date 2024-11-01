"""Add MonthlyScoreSummary table

Revision ID: dedd899c0957
Revises: 3754f074d7ed
Create Date: 2024-11-01 04:21:49.849799

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'dedd899c0957'
down_revision = '3754f074d7ed'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('monthly_score_summary',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('month', sa.Integer(), nullable=False),
    sa.Column('year', sa.Integer(), nullable=False),
    sa.Column('office_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('zone_name', sa.String(length=120), nullable=True),
    sa.Column('total_zone_score', sa.Float(), nullable=True),
    sa.Column('total_facility_score', sa.Float(), nullable=True),
    sa.ForeignKeyConstraint(['office_id'], ['office.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('room', schema=None) as batch_op:
        batch_op.alter_column('user_id',
               existing_type=sa.INTEGER(),
               nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('room', schema=None) as batch_op:
        batch_op.alter_column('user_id',
               existing_type=sa.INTEGER(),
               nullable=True)

    op.drop_table('monthly_score_summary')
    # ### end Alembic commands ###
