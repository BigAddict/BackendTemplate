"""Initial migration

Revision ID: b27fc138362a
Revises: 
Create Date: 2025-04-11 15:41:23.046054

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b27fc138362a'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index('ix_verificationtoken_code', table_name='verificationtoken')
    op.create_index(op.f('ix_verificationtoken_code'), 'verificationtoken', ['code'], unique=True)
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_verificationtoken_code'), table_name='verificationtoken')
    op.create_index('ix_verificationtoken_code', 'verificationtoken', ['code'], unique=False)
    # ### end Alembic commands ###
