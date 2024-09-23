"""Added nullable UserID for guest bookings

Revision ID: 8d67d82c5ce5
Revises: 3ed68359c1af
Create Date: 2024-09-23 15:33:24.107933

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8d67d82c5ce5'
down_revision: Union[str, None] = '3ed68359c1af'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
