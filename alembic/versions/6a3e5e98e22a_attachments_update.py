"""Attachments update

Revision ID: 6a3e5e98e22a
Revises: a5eb20869d08
Create Date: 2024-07-01 04:10:36.006609

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6a3e5e98e22a'
down_revision: Union[str, None] = 'a5eb20869d08'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
