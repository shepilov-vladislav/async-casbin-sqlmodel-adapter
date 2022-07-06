# Stdlib:
from contextlib import asynccontextmanager
from typing import AsyncGenerator

# Thirdparty:
from casbin import Model, persist
from casbin.persist import Adapter as BaseAdapter
from casbin.persist.adapters.update_adapter import UpdateAdapter
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.dml import Delete
from sqlmodel import Field, SQLModel, delete, or_, select
from sqlmodel.sql.expression import SelectOfScalar


class AdapterException(Exception):
    """AdapterException"""


class CasbinRule(SQLModel, table=True):  # type: ignore
    """
    CasbinRule class for SQLModel-based Casbin adapter.
    """

    __tablename__ = "casbin_rule"

    id: int = Field(primary_key=True)
    ptype: str = Field(max_length=255)
    v0: str = Field(max_length=255)
    v1: str = Field(max_length=255)
    v2: str | None = Field(max_length=255, default=None)
    v3: str | None = Field(max_length=255, default=None)
    v4: str | None = Field(max_length=255, default=None)
    v5: str | None = Field(max_length=255, default=None)

    def __str__(self) -> str:
        arr = [self.ptype]
        # pylint: disable=invalid-name
        for v in (self.v0, self.v1, self.v2, self.v3, self.v4, self.v5):
            if v is None:
                break
            arr.append(v)
        return ", ".join(arr)

    def __repr__(self) -> str:
        return f'<CasbinRule {self.id}: "{str(self)}">'


class Filter:  # pylint: disable=too-few-public-methods
    """
    Filter class for SQLModel-based Casbin adapter.
    """

    ptype: list[str] = []
    v0: list[str] = []
    v1: list[str] = []
    v2: list[str] = []
    v3: list[str] = []
    v4: list[str] = []
    v5: list[str] = []


class Adapter(BaseAdapter, UpdateAdapter):
    """
    Adapter class for ormar-based Casbin adapter.
    """

    cols = ["ptype"] + [f"v{i}" for i in range(6)]

    def __init__(
        self,
        engine: AsyncEngine | str,
        db_class: SQLModel | None = None,
        filtered: bool = False,
    ):
        if isinstance(engine, str):
            self._engine = create_async_engine(engine)
        else:
            self._engine = engine

        if db_class is None:
            db_class = CasbinRule
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
                    raise AdapterException(f"{attr} not found in custom DatabaseClass.")

        self._db_class = db_class
        self.session_local = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        self._filtered: bool = filtered

    @asynccontextmanager
    async def _session_scope(self) -> AsyncGenerator[AsyncSession, None]:
        """Provide a transactional scope around a series of operations."""

        async with self.session_local() as session:
            try:
                yield session
                await session.commit()
            except Exception as err:  # pragma: no cover
                await session.rollback()
                raise err
            finally:
                await session.close()

    async def load_policy(self, model: Model) -> None:
        """loads all policy rules from the storage."""

        async with self._session_scope() as session:
            lines = (await session.execute(select(self._db_class))).scalars().all()
            for line in lines:
                persist.load_policy_line(str(line), model)

    def is_filtered(self) -> bool:
        """returns whether the adapter is filtered or not."""

        return self._filtered

    async def load_filtered_policy(self, model: Model, filter_: Filter) -> None:
        """loads all policy rules from the storage."""

        async with self._session_scope() as session:
            query: SelectOfScalar = select(self._db_class)
            filters = await self.filter_query(query, filter_)
            filters = (await session.execute(filters)).scalars().all()

            for line in filters:
                persist.load_policy_line(str(line), model)
            self._filtered = True

    async def filter_query(
        self, querydb: SelectOfScalar, filter_: Filter
    ) -> SelectOfScalar:
        """filters the query based on the filter_."""

        for attr in ("ptype", "v0", "v1", "v2", "v3", "v4", "v5"):
            if len(getattr(filter_, attr)) > 0:
                querydb = querydb.filter(
                    getattr(self._db_class, attr).in_(getattr(filter_, attr))
                )
        return querydb.order_by(self._db_class.id)

    async def _save_policy_line(self, ptype: str, rule: list[str]) -> None:
        async with self._session_scope() as session:
            line = self._db_class(ptype=ptype)
            for i, v in enumerate(rule):  # pylint: disable=invalid-name
                setattr(line, f"v{i}", v)
            session.add(line)

    async def save_policy(self, model: Model) -> bool:
        """saves all policy rules to the storage."""

        async with self._session_scope() as session:
            query: SelectOfScalar = select(self._db_class)
            results = (await session.execute(query)).scalars().all()
            for line in results:
                await session.delete(line)
            for sec in ["p", "g"]:
                if sec not in model.model.keys():  # pragma: no cover
                    continue
                for ptype, ast in model.model[sec].items():
                    for rule in ast.policy:
                        await self._save_policy_line(ptype, rule)
        return True

    # pylint: disable=unused-argument
    async def add_policy(self, sec: str, ptype: str, rule: list[str]) -> None:
        """adds a policy rule to the storage."""

        await self._save_policy_line(ptype, rule)

    # pylint: disable=unused-argument
    async def add_policies(
        self, sec: str, ptype: str, rules: tuple[tuple[str]]
    ) -> None:
        """adds a policy rules to the storage."""

        for rule in rules:
            await self._save_policy_line(ptype, list(rule))

    # pylint: disable=unused-argument
    async def remove_policy(self, sec: str, ptype: str, rule: list[str]) -> bool:
        """removes a policy rule from the storage."""

        async with self._session_scope() as session:
            query: Delete = delete(self._db_class)
            query = query.filter(self._db_class.ptype == ptype)
            for i, v in enumerate(rule):  # pylint: disable=invalid-name
                query = query.filter(getattr(self._db_class, f"v{i}") == v)
            res = (await session.execute(query)).rowcount
        return res > 0  # pragma: no cover

    async def remove_policies(
        self, sec: str, ptype: str, rules: tuple[tuple[str]]
    ) -> None:
        """remove policy rules from the storage."""

        if not rules:  # pragma: no cover
            return
        async with self._session_scope() as session:
            query: Delete = delete(self._db_class)
            query = query.filter(self._db_class.ptype == ptype)
            _rules = zip(*rules)
            for i, rule in enumerate(_rules):
                query = query.filter(
                    or_(getattr(self._db_class, f"v{i}") == v for v in rule)
                )
            await session.execute(query)

    # pylint: disable=unused-argument
    async def remove_filtered_policy(
        self, sec: str, ptype: str, field_index: int, *field_values: tuple[str]
    ) -> bool:
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """

        async with self._session_scope() as session:
            query: Delete = delete(self._db_class)
            query = query.filter(self._db_class.ptype == ptype)

            if not 0 <= field_index <= 5:  # pragma: no cover
                return False
            if not 1 <= field_index + len(field_values) <= 6:  # pragma: no cover
                return False
            for i, v in enumerate(field_values):  # pylint: disable=invalid-name
                if v != "":
                    v_value = getattr(self._db_class, f"v{field_index + i}")
                    query = query.filter(v_value == v)
            res = (await session.execute(query)).rowcount

        return res > 0

    async def update_policy(
        self, sec: str, ptype: str, old_rule: list[str], new_rule: list[str]
    ) -> None:
        """
        Update the old_rule with the new_rule in the database (storage).
        :param sec: section type
        :param ptype: policy type
        :param old_rule: the old rule that needs to be modified
        :param new_rule: the new rule to replace the old rule
        :return: None
        """

        async with self._session_scope() as session:
            query: SelectOfScalar = select(self._db_class)
            query = query.filter(self._db_class.ptype == ptype)

            # locate the old rule
            for index, value in enumerate(old_rule):
                v_value = getattr(self._db_class, f"v{index}")
                query = query.filter(v_value == value)

            # need the length of the longest_rule to perform overwrite
            longest_rule = old_rule if len(old_rule) > len(new_rule) else new_rule
            results = await session.execute(query)
            old_rule_line = results.scalar_one()

            # overwrite the old rule with the new rule
            for index in range(len(longest_rule)):
                if index < len(new_rule):
                    setattr(old_rule_line, f"v{index}", new_rule[index])
                else:  # pragma: no cover
                    setattr(old_rule_line, f"v{index}", None)

    async def update_policies(
        self,
        sec: str,
        ptype: str,
        old_rules: list[list[str]],
        new_rules: list[list[str]],
    ) -> None:
        """
        Update the old_rules with the new_rules in the database (storage).
        :param sec: section type
        :param ptype: policy type
        :param old_rules: the old rules that need to be modified
        :param new_rules: the new rules to replace the old rules
        :return: None
        """

        for i, rule in enumerate(old_rules):
            await self.update_policy(sec, ptype, rule, new_rules[i])
