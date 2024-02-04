from pathlib import Path

import casbin
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import Field, SQLModel, delete

from async_casbin_sqlmodel_adapter import Adapter
from async_casbin_sqlmodel_adapter.models import CasbinRule


@pytest.fixture(name="engine")
def engine_fixture() -> AsyncEngine:
    return create_async_engine("sqlite+aiosqlite:///")


@pytest.fixture(name="session")
async def session_fixture(engine: AsyncEngine) -> AsyncSession:
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
        await conn.run_sync(SQLModel.metadata.create_all)

    session_local = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_local() as session:
        yield session


@pytest.fixture(name="rbac_model_conf")
def rbac_model_conf_fixture() -> str:
    dir_path = Path(__file__).resolve().parent
    return str(dir_path / "rbac_model.conf")


@pytest.fixture(name="enforcer")
async def enforcer_fixture(
    engine: AsyncEngine,
    session: AsyncSession,
    rbac_model_conf: str,
) -> casbin.AsyncEnforcer:
    await session.execute(delete(CasbinRule))
    session.add_all(
        [
            CasbinRule(ptype="p", v0="alice", v1="data1", v2="read"),
            CasbinRule(ptype="p", v0="bob", v1="data2", v2="write"),
            CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="read"),
            CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="write"),
            CasbinRule(ptype="g", v0="alice", v1="data2_admin"),
        ],
    )
    await session.commit()
    await session.close()

    adapter = Adapter(engine)
    enforcer = casbin.AsyncEnforcer(rbac_model_conf, adapter)
    await enforcer.load_policy()
    return enforcer


@pytest.fixture(name="CustomRule")
async def CustomRule_fixture() -> type[SQLModel]:  # noqa: N802
    class CustomRule(SQLModel, table=True):
        __tablename__ = "casbin_rule2"

        id: int = Field(primary_key=True)
        ptype: str | None = Field(max_length=255, default=None)
        v0: str | None = Field(max_length=255, default=None)
        v1: str | None = Field(max_length=255, default=None)
        v2: str | None = Field(max_length=255, default=None)
        v3: str | None = Field(max_length=255, default=None)
        v4: str | None = Field(max_length=255, default=None)
        v5: str | None = Field(max_length=255, default=None)
        not_exist: str | None = Field(max_length=255, default=None)

    return CustomRule


@pytest.fixture(name="CustomRuleBroken")
async def CustomRuleBroken_fixture() -> type[SQLModel]:  # noqa: N802
    class CustomRuleBroken(SQLModel, table=True):
        __tablename__ = "casbin_rule3"

        id: int = Field(primary_key=True)
        not_exist: str | None = Field(max_length=255, default=None)

    return CustomRuleBroken
