"""Initial setup

Revision ID: 3ed68359c1af
Revises: daf523668026
Create Date: 2024-08-22 14:23:45.891614

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3ed68359c1af'
down_revision: Union[str, None] = 'daf523668026'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
