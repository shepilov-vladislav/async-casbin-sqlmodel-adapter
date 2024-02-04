"""Adapter for Casbin with SQLModel."""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, ClassVar

from casbin_async_sqlalchemy_adapter.adapter import Adapter as AsyncAdapter
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from typing_extensions import Self

if TYPE_CHECKING:
    from sqlmodel import SQLModel


class AdapterError(Exception):
    """AdapterError."""


class Filter:
    """Filter class for SQLModel-based Casbin adapter."""

    ptype: ClassVar[list[str]] = []
    v0: ClassVar[list[str]] = []
    v1: ClassVar[list[str]] = []
    v2: ClassVar[list[str]] = []
    v3: ClassVar[list[str]] = []
    v4: ClassVar[list[str]] = []
    v5: ClassVar[list[str]] = []


class Adapter(AsyncAdapter):
    """Adapter class for ormar-based Casbin adapter."""

    cols = ["ptype"] + [f"v{i}" for i in range(6)]

    def __init__(
        self: Self,
        engine: AsyncEngine | str,
        db_class: SQLModel | None = None,
        filtered: bool = False,  # noqa: FBT001,FBT002
        warning: bool = True,  # noqa: FBT001,FBT002
    ) -> None:
        """Initialize the Adapter.

        :param engine: The SQLAlchemy engine, or a string which can be used to create an engine.
        :param db_class: The Database class to be used, if not provided, the default CasbinRule class will be used.
        :param filtered: Whether the adapter is filtered or not.
        :param warning: Whether to show the warning message when using the default CasbinRule class.

        :raises AdapterError: If the db_class does not have the required attributes.
        """
        if isinstance(engine, str):
            self._engine = create_async_engine(engine, future=True)
        else:
            self._engine = engine

        if db_class is None:
            from .models import (  # noqa: PLC0415
                CasbinRule,
            )

            db_class = CasbinRule
            if warning:
                warnings.warn(
                    "Using default CasbinRule table, please note the use of the 'Adapter().create_table()' method"
                    " to create the table, and ignore this warning if you are using a custom CasbinRule table.",
                    category=RuntimeWarning,
                    stacklevel=2,
                )
        else:
            for attr in (
                "id",
                "ptype",
                "v0",
                "v1",
                "v2",
                "v3",
                "v4",
                "v5",
            ):  # id attr was used by filter
                if not hasattr(db_class, attr):
                    msg = f"{attr} not found in custom DatabaseClass."
                    raise AdapterError(msg)

        self._db_class = db_class
        self.session_local = sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        self._filtered: bool = filtered
