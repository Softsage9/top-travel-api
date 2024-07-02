"""Add rawFile to attachments

Revision ID: 56eda4dd8e5e
Revises: aa5e0634c0c9
Create Date: 2024-06-30 13:54:07.692365

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '56eda4dd8e5e'
down_revision: Union[str, None] = 'aa5e0634c0c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
