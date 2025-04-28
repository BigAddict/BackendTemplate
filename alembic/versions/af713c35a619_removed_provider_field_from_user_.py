"""Removed provider field from user credentials

Revision ID: af713c35a619
Revises: b27fc138362a
Create Date: 2025-04-28 10:38:05.570387

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

# revision identifiers, used by Alembic.
revision: str = 'af713c35a619'
down_revision: Union[str, None] = 'b27fc138362a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    
    # Drop provider column
    op.drop_column('usercredential', 'provider')
    
    # SQLite-compatible column type change
    if conn.engine.name == 'sqlite':
        # For SQLite, we need to recreate the table
        with op.batch_alter_table('verificationtoken') as batch_op:
            batch_op.alter_column('code', type_=sa.Integer())
    else:
        # For other databases, use standard ALTER
        op.alter_column('verificationtoken', 'code',
                   existing_type=sa.VARCHAR(),
                   type_=sa.Integer(),
                   existing_nullable=False)


def downgrade() -> None:
    """Downgrade schema."""
    conn = op.get_bind()
    
    # Add provider column back
    op.add_column('usercredential', sa.Column('provider', sa.VARCHAR(), nullable=False))
    
    # SQLite-compatible column type change
    if conn.engine.name == 'sqlite':
        with op.batch_alter_table('verificationtoken') as batch_op:
            batch_op.alter_column('code', type_=sa.String())
    else:
        op.alter_column('verificationtoken', 'code',
                   existing_type=sa.Integer(),
                   type_=sa.VARCHAR(),
                   existing_nullable=False)