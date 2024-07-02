"""Attachments update

Revision ID: a5eb20869d08
Revises: 56eda4dd8e5e
Create Date: 2024-06-30 15:29:46.310091

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a5eb20869d08'
down_revision: Union[str, None] = '56eda4dd8e5e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
