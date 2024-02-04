# Stdlib:
import re

# Thirdparty:
import pytest
from casbin import AsyncEnforcer
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlmodel import SQLModel, select

# Firstparty:
from async_casbin_sqlmodel_adapter import Adapter, AdapterError, Filter
from async_casbin_sqlmodel_adapter.models import CasbinRule


async def test_custom_db_class(
    engine: AsyncEngine,
    session: AsyncSession,
    CustomRule: SQLModel,  # noqa: N803
    CustomRuleBroken: SQLModel,  # noqa: N803
) -> None:
    with pytest.raises(AdapterError):
        Adapter("sqlite+aiosqlite:///", CustomRuleBroken)

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    adapter = Adapter(engine, CustomRule)
    assert adapter._db_class == CustomRule  # noqa: SLF001

    session.add(CustomRule(not_exist="NotNone"))
    await session.commit()

    from_db: CustomRule = (await session.execute(select(CustomRule))).scalars().all()[0]
    assert from_db.not_exist == "NotNone"


async def test_enforcer_basic(enforcer: AsyncEnforcer) -> None:
    assert enforcer.enforce("alice", "data1", "read")
    assert not enforcer.enforce("alice", "data1", "write")
    assert not enforcer.enforce("bob", "data1", "read")
    assert not enforcer.enforce("bob", "data1", "write")
    assert enforcer.enforce("bob", "data2", "write")
    assert not enforcer.enforce("bob", "data2", "read")
    assert enforcer.enforce("alice", "data2", "read")
    assert enforcer.enforce("alice", "data2", "write")


async def test_add_policy(enforcer: AsyncEnforcer) -> None:
    assert not enforcer.enforce("eve", "data3", "read")
    res = await enforcer.add_policies(
        (("eve", "data3", "read"), ("eve", "data4", "read")),
    )
    assert res
    assert enforcer.enforce("eve", "data3", "read")
    assert enforcer.enforce("eve", "data4", "read")


async def test_add_policies(enforcer: AsyncEnforcer) -> None:
    assert not enforcer.enforce("eve", "data3", "read")
    res = await enforcer.add_permission_for_user("eve", "data3", "read")
    assert res
    assert enforcer.enforce("eve", "data3", "read")


async def test_save_policy(enforcer: AsyncEnforcer) -> None:
    assert not enforcer.enforce("alice", "data4", "read")

    model = enforcer.get_model()
    model.clear_policy()

    model.add_policy("p", "p", ["alice", "data4", "read"])

    adapter = enforcer.get_adapter()
    await adapter.save_policy(model)
    assert enforcer.enforce("alice", "data4", "read")


async def test_remove_policy(enforcer: AsyncEnforcer) -> None:
    assert not enforcer.enforce("alice", "data5", "read")
    await enforcer.add_permission_for_user("alice", "data5", "read")
    assert enforcer.enforce("alice", "data5", "read")
    await enforcer.delete_permission_for_user("alice", "data5", "read")
    assert not enforcer.enforce("alice", "data5", "read")


async def test_remove_policies(enforcer: AsyncEnforcer) -> None:
    assert not enforcer.enforce("alice", "data5", "read")
    assert not enforcer.enforce("alice", "data6", "read")
    await enforcer.add_policies(
        (("alice", "data5", "read"), ("alice", "data6", "read")),
    )
    assert enforcer.enforce("alice", "data5", "read")
    assert enforcer.enforce("alice", "data6", "read")
    await enforcer.remove_policies(
        (("alice", "data5", "read"), ("alice", "data6", "read")),
    )
    assert not enforcer.enforce("alice", "data5", "read")
    assert not enforcer.enforce("alice", "data6", "read")


async def test_remove_filtered_policy(enforcer: AsyncEnforcer) -> None:
    assert enforcer.enforce("alice", "data1", "read")
    await enforcer.remove_filtered_policy(1, "data1")
    assert not enforcer.enforce("alice", "data1", "read")

    assert enforcer.enforce("bob", "data2", "write")
    assert enforcer.enforce("alice", "data2", "read")
    assert enforcer.enforce("alice", "data2", "write")

    await enforcer.remove_filtered_policy(1, "data2", "read")

    assert enforcer.enforce("bob", "data2", "write")
    assert not enforcer.enforce("alice", "data2", "read")
    assert enforcer.enforce("alice", "data2", "write")

    await enforcer.remove_filtered_policy(2, "write")

    assert not enforcer.enforce("bob", "data2", "write")
    assert not enforcer.enforce("alice", "data2", "write")


async def test_str() -> None:
    rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
    assert str(rule) == "p, alice, data1, read"
    rule = CasbinRule(ptype="p", v0="bob", v1="data2", v2="write")
    assert str(rule) == "p, bob, data2, write"
    rule = CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="read")
    assert str(rule) == "p, data2_admin, data2, read"
    rule = CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="write")
    assert str(rule) == "p, data2_admin, data2, write"
    rule = CasbinRule(ptype="g", v0="alice", v1="data2_admin")
    assert str(rule) == "g, alice, data2_admin"


async def test_repr(engine: AsyncEngine, session: AsyncSession) -> None:
    rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
    assert repr(rule) == '<CasbinRule None: "p, alice, data1, read">'
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    session.add(rule)
    await session.commit()
    assert re.match(r'<CasbinRule \d+: "p, alice, data1, read">', repr(rule))
    await session.close()


async def test_filtered_policy(enforcer: AsyncEnforcer) -> None:  # noqa: PLR0915
    _filter = Filter()

    _filter.ptype = ["p"]
    await enforcer.load_filtered_policy(_filter)
    assert enforcer.enforce("alice", "data1", "read")
    assert not enforcer.enforce("alice", "data1", "write")
    assert not enforcer.enforce("alice", "data2", "read")
    assert not enforcer.enforce("alice", "data2", "write")
    assert not enforcer.enforce("bob", "data1", "read")
    assert not enforcer.enforce("bob", "data1", "write")
    assert not enforcer.enforce("bob", "data2", "read")
    assert enforcer.enforce("bob", "data2", "write")

    _filter.ptype = []
    _filter.v0 = ["alice"]
    await enforcer.load_filtered_policy(_filter)
    assert enforcer.enforce("alice", "data1", "read")
    assert not enforcer.enforce("alice", "data1", "write")
    assert not enforcer.enforce("alice", "data2", "read")
    assert not enforcer.enforce("alice", "data2", "write")
    assert not enforcer.enforce("bob", "data1", "read")
    assert not enforcer.enforce("bob", "data1", "write")
    assert not enforcer.enforce("bob", "data2", "read")
    assert not enforcer.enforce("bob", "data2", "write")
    assert not enforcer.enforce("data2_admin", "data2", "read")
    assert not enforcer.enforce("data2_admin", "data2", "write")

    _filter.v0 = ["bob"]
    await enforcer.load_filtered_policy(_filter)
    assert not enforcer.enforce("alice", "data1", "read")
    assert not enforcer.enforce("alice", "data1", "write")
    assert not enforcer.enforce("alice", "data2", "read")
    assert not enforcer.enforce("alice", "data2", "write")
    assert not enforcer.enforce("bob", "data1", "read")
    assert not enforcer.enforce("bob", "data1", "write")
    assert not enforcer.enforce("bob", "data2", "read")
    assert enforcer.enforce("bob", "data2", "write")
    assert not enforcer.enforce("data2_admin", "data2", "read")
    assert not enforcer.enforce("data2_admin", "data2", "write")

    _filter.v0 = ["data2_admin"]
    await enforcer.load_filtered_policy(_filter)
    assert enforcer.enforce("data2_admin", "data2", "read")
    assert enforcer.enforce("data2_admin", "data2", "read")
    assert not enforcer.enforce("alice", "data1", "read")
    assert not enforcer.enforce("alice", "data1", "write")
    assert not enforcer.enforce("alice", "data2", "read")
    assert not enforcer.enforce("alice", "data2", "write")
    assert not enforcer.enforce("bob", "data1", "read")
    assert not enforcer.enforce("bob", "data1", "write")
    assert not enforcer.enforce("bob", "data2", "read")
    assert not enforcer.enforce("bob", "data2", "write")

    _filter.v0 = ["alice", "bob"]
    await enforcer.load_filtered_policy(_filter)
    assert enforcer.enforce("alice", "data1", "read")
    assert not enforcer.enforce("alice", "data1", "write")
    assert not enforcer.enforce("alice", "data2", "read")
    assert not enforcer.enforce("alice", "data2", "write")
    assert not enforcer.enforce("bob", "data1", "read")
    assert not enforcer.enforce("bob", "data1", "write")
    assert not enforcer.enforce("bob", "data2", "read")
    assert enforcer.enforce("bob", "data2", "write")
    assert not enforcer.enforce("data2_admin", "data2", "read")
    assert not enforcer.enforce("data2_admin", "data2", "write")

    _filter.v0 = []
    _filter.v1 = ["data1"]
    await enforcer.load_filtered_policy(_filter)
    assert enforcer.enforce("alice", "data1", "read")
    assert not enforcer.enforce("alice", "data1", "write")
    assert not enforcer.enforce("alice", "data2", "read")
    assert not enforcer.enforce("alice", "data2", "write")
    assert not enforcer.enforce("bob", "data1", "read")
    assert not enforcer.enforce("bob", "data1", "write")
    assert not enforcer.enforce("bob", "data2", "read")
    assert not enforcer.enforce("bob", "data2", "write")
    assert not enforcer.enforce("data2_admin", "data2", "read")
    assert not enforcer.enforce("data2_admin", "data2", "write")

    _filter.v1 = ["data2"]
    await enforcer.load_filtered_policy(_filter)
    assert not enforcer.enforce("alice", "data1", "read")
    assert not enforcer.enforce("alice", "data1", "write")
    assert not enforcer.enforce("alice", "data2", "read")
    assert not enforcer.enforce("alice", "data2", "write")
    assert not enforcer.enforce("bob", "data1", "read")
    assert not enforcer.enforce("bob", "data1", "write")
    assert not enforcer.enforce("bob", "data2", "read")
    assert enforcer.enforce("bob", "data2", "write")
    assert enforcer.enforce("data2_admin", "data2", "read")
    assert enforcer.enforce("data2_admin", "data2", "write")

    _filter.v1 = []
    _filter.v2 = ["read"]
    await enforcer.load_filtered_policy(_filter)
    assert enforcer.enforce("alice", "data1", "read")
    assert not enforcer.enforce("alice", "data1", "write")
    assert not enforcer.enforce("alice", "data2", "read")
    assert not enforcer.enforce("alice", "data2", "write")
    assert not enforcer.enforce("bob", "data1", "read")
    assert not enforcer.enforce("bob", "data1", "write")
    assert not enforcer.enforce("bob", "data2", "read")
    assert not enforcer.enforce("bob", "data2", "write")
    assert enforcer.enforce("data2_admin", "data2", "read")
    assert not enforcer.enforce("data2_admin", "data2", "write")

    _filter.v2 = ["write"]
    await enforcer.load_filtered_policy(_filter)
    assert not enforcer.enforce("alice", "data1", "read")
    assert not enforcer.enforce("alice", "data1", "write")
    assert not enforcer.enforce("alice", "data2", "read")
    assert not enforcer.enforce("alice", "data2", "write")
    assert not enforcer.enforce("bob", "data1", "read")
    assert not enforcer.enforce("bob", "data1", "write")
    assert not enforcer.enforce("bob", "data2", "read")
    assert enforcer.enforce("bob", "data2", "write")
    assert not enforcer.enforce("data2_admin", "data2", "read")
    assert enforcer.enforce("data2_admin", "data2", "write")


async def test_update_policy(enforcer: AsyncEnforcer) -> None:
    example_p = ["mike", "cookie", "eat"]

    assert enforcer.enforce("alice", "data1", "read")
    await enforcer.update_policy(
        ["alice", "data1", "read"],
        ["alice", "data1", "no_read"],
    )
    assert not enforcer.enforce("alice", "data1", "read")

    assert not enforcer.enforce("bob", "data1", "read")
    await enforcer.add_policy(example_p)
    await enforcer.update_policy(example_p, ["bob", "data1", "read"])
    assert enforcer.enforce("bob", "data1", "read")

    assert not enforcer.enforce("bob", "data1", "write")
    await enforcer.update_policy(["bob", "data1", "read"], ["bob", "data1", "write"])
    assert enforcer.enforce("bob", "data1", "write")

    assert enforcer.enforce("bob", "data2", "write")
    await enforcer.update_policy(["bob", "data2", "write"], ["bob", "data2", "read"])
    assert not enforcer.enforce("bob", "data2", "write")

    assert enforcer.enforce("bob", "data2", "read")
    await enforcer.update_policy(["bob", "data2", "read"], ["carl", "data2", "write"])
    assert not enforcer.enforce("bob", "data2", "write")

    assert enforcer.enforce("carl", "data2", "write")
    await enforcer.update_policy(
        ["carl", "data2", "write"],
        ["carl", "data2", "no_write"],
    )
    assert not enforcer.enforce("bob", "data2", "write")


async def test_update_policies(enforcer: AsyncEnforcer) -> None:
    old_rule_0 = ["alice", "data1", "read"]
    old_rule_1 = ["bob", "data2", "write"]
    old_rule_2 = ["data2_admin", "data2", "read"]
    old_rule_3 = ["data2_admin", "data2", "write"]

    new_rule_0 = ["alice", "data_test", "read"]
    new_rule_1 = ["bob", "data_test", "write"]
    new_rule_2 = ["data2_admin", "data_test", "read"]
    new_rule_3 = ["data2_admin", "data_test", "write"]

    old_rules = [old_rule_0, old_rule_1, old_rule_2, old_rule_3]
    new_rules = [new_rule_0, new_rule_1, new_rule_2, new_rule_3]

    await enforcer.update_policies(old_rules, new_rules)

    assert not enforcer.enforce("alice", "data1", "read")
    assert enforcer.enforce("alice", "data_test", "read")

    assert not enforcer.enforce("bob", "data2", "write")
    assert enforcer.enforce("bob", "data_test", "write")

    assert not enforcer.enforce("data2_admin", "data2", "read")
    assert enforcer.enforce("data2_admin", "data_test", "read")

    assert not enforcer.enforce("data2_admin", "data2", "write")
    assert enforcer.enforce("data2_admin", "data_test", "write")


async def test_update_filtered_policies(enforcer: AsyncEnforcer) -> None:
    await enforcer.update_filtered_policies(
        [
            ["data2_admin", "data3", "read"],
            ["data2_admin", "data3", "write"],
        ],
        0,
        "data2_admin",
    )
    assert enforcer.enforce("data2_admin", "data3", "write")
    assert enforcer.enforce("data2_admin", "data3", "read")

    await enforcer.update_filtered_policies([["alice", "data1", "write"]], 0, "alice")
    assert enforcer.enforce("alice", "data1", "write")

    await enforcer.update_filtered_policies([["bob", "data2", "read"]], 0, "bob")
    assert enforcer.enforce("bob", "data2", "read")


async def test_is_filtered(
    engine: AsyncEngine,
    session: AsyncSession,  # noqa: ARG001
    rbac_model_conf: str,
) -> None:
    adapter1 = Adapter(engine)
    enforcer1 = AsyncEnforcer(rbac_model_conf, adapter1)
    await enforcer1.load_policy()
    assert not enforcer1.is_filtered()

    adapter1 = Adapter(engine, filtered=True)
    enforcer1 = AsyncEnforcer(rbac_model_conf, adapter1)
    await enforcer1.load_policy()
    assert enforcer1.is_filtered()
