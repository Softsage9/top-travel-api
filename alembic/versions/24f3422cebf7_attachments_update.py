"""Attachments update

Revision ID: 24f3422cebf7
Revises: 6a3e5e98e22a
Create Date: 2024-07-01 16:24:39.150318

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '24f3422cebf7'
down_revision: Union[str, None] = '6a3e5e98e22a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
