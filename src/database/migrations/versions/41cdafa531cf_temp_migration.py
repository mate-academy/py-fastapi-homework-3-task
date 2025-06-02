"""add is_used column to token tables

Revision ID: 41cdafa531cf
Revises: 32b1054a69e3
Create Date: 2024-03-19 10:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "41cdafa531cf"
down_revision: Union[str, None] = "32b1054a69e3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add is_used column to activation_tokens
    op.add_column(
        "activation_tokens",
        sa.Column("is_used", sa.Boolean(), nullable=False, server_default="false"),
    )

    # Add is_used column to password_reset_tokens
    op.add_column(
        "password_reset_tokens",
        sa.Column("is_used", sa.Boolean(), nullable=False, server_default="false"),
    )

    # Add is_used column to refresh_tokens
    op.add_column(
        "refresh_tokens",
        sa.Column("is_used", sa.Boolean(), nullable=False, server_default="false"),
    )


def downgrade() -> None:
    # Remove is_used column from activation_tokens
    op.drop_column("activation_tokens", "is_used")

    # Remove is_used column from password_reset_tokens
    op.drop_column("password_reset_tokens", "is_used")

    # Remove is_used column from refresh_tokens
    op.drop_column("refresh_tokens", "is_used")
