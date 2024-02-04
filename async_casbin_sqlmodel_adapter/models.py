"""SQLModel-based Casbin adapter models."""

from sqlmodel import Field, SQLModel
from typing_extensions import Self  # noqa: UP035


class CasbinRule(SQLModel, table=True):  # type: ignore[call-arg]
    """CasbinRule class for SQLModel-based Casbin adapter."""

    __tablename__ = "casbin_rule"

    id: int = Field(primary_key=True)
    ptype: str = Field(max_length=255)
    v0: str = Field(max_length=255)
    v1: str = Field(max_length=255)
    v2: str | None = Field(max_length=255, default=None)
    v3: str | None = Field(max_length=255, default=None)
    v4: str | None = Field(max_length=255, default=None)
    v5: str | None = Field(max_length=255, default=None)

    def __str__(self: Self) -> str:
        """Return the string representation of the CasbinRule."""
        arr = [self.ptype]
        # pylint: disable=invalid-name
        for v in (self.v0, self.v1, self.v2, self.v3, self.v4, self.v5):
            if v is None:
                break
            arr.append(v)
        return ", ".join(arr)

    def __repr__(self: Self) -> str:
        """Return the string representation of the CasbinRule."""
        return f'<CasbinRule {self.id}: "{self!s}">'
