from collections.abc import AsyncGenerator

from casbin import Model
from casbin_async_sqlalchemy_adapter.adapter import Adapter as AsyncAdapter
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel.sql.expression import SelectOfScalar
from typing_extensions import Self

from .adapter import Filter

class Adapter(AsyncAdapter):
    cols: list[str]

    async def _session_scope(self: Self) -> AsyncGenerator[AsyncSession, None]: ...
    async def load_policy(self: Self, model: Model) -> None: ...
    def is_filtered(self: Self) -> bool: ...
    async def load_filtered_policy(
        self: Self,
        model: Model,
        filter_: Filter,
    ) -> None: ...
    async def filter_query(
        self: Self,
        querydb: SelectOfScalar,
        filter_: Filter,
    ) -> SelectOfScalar: ...
    async def _save_policy_line(self: Self, ptype: str, rule: list[str]) -> None: ...
    async def save_policy(self: Self, model: Model) -> bool: ...
    async def add_policy(self: Self, sec: str, ptype: str, rule: list[str]) -> None: ...
    async def add_policies(
        self: Self,
        sec: str,
        ptype: str,
        rules: tuple[tuple[str]],
    ) -> None: ...
    async def remove_policy(
        self: Self,
        sec: str,
        ptype: str,
        rule: list[str],
    ) -> bool: ...
    async def remove_policies(
        self: Self,
        sec: str,
        ptype: str,
        rules: tuple[tuple[str]],
    ) -> None: ...
    async def remove_filtered_policy(
        self: Self,
        sec: str,
        ptype: str,
        field_index: int,
        *field_values: tuple[str],
    ) -> bool: ...
    async def update_policy(
        self: Self,
        sec: str,
        ptype: str,
        old_rule: list[str],
        new_rule: list[str],
    ) -> None: ...
    async def update_policies(
        self: Self,
        sec: str,
        ptype: str,
        old_rules: list[list[str]],
        new_rules: list[list[str]],
    ) -> None: ...
    async def update_filtered_policies(
        self: Self,
        sec: str,
        ptype: str,
        new_rules: list[list[str]],
        field_index: int,
        *field_values: tuple[str],
    ) -> list[list[str]]: ...
    async def _update_filtered_policies(
        self: Self,
        new_rules: list[list[str]],
        filter: Filter,  # noqa: A002
    ) -> list[list[str]]: ...
