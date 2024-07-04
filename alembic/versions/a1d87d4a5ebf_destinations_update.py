"""Destinations update

Revision ID: a1d87d4a5ebf
Revises: 24f3422cebf7
Create Date: 2024-07-04 00:19:14.643981

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1d87d4a5ebf'
down_revision: Union[str, None] = '24f3422cebf7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
