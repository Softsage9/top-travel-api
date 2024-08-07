"""Add SessionID to Payment model

Revision ID: 16c5b531ec16
Revises: 45dbc087bf0b
Create Date: 2024-08-01 15:32:11.928688

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '16c5b531ec16'
down_revision: Union[str, None] = '45dbc087bf0b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    op.add_column('payments', sa.Column('SessionID', sa.String(length=255), nullable=True))


def downgrade():
    op.drop_column('payments', 'SessionID')
