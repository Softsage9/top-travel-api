"""Add Guest User

Revision ID: 39e12053f86f
Revises: 8d67d82c5ce5
Create Date: 2024-09-23 15:46:21.910080

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '39e12053f86f'
down_revision: Union[str, None] = '8d67d82c5ce5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
