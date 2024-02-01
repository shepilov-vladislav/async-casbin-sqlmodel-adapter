# Stdlib:
import re

# Thirdparty:
import pytest
from casbin import AsyncEnforcer
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlmodel import SQLModel, select

# Firstparty:
from async_casbin_sqlmodel_adapter import AsyncAdapter, AdapterException, Filter
from async_casbin_sqlmodel_adapter.models import CasbinRule


async def test_custom_db_class(
    engine: AsyncEngine, session: AsyncSession, CustomRule, CustomRuleBroken
):
    with pytest.raises(AdapterException):
        AsyncAdapter("sqlite+aiosqlite:///", CustomRuleBroken)

    adapter = AsyncAdapter(engine, CustomRule)
    assert adapter._db_class == CustomRule

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    session.add(CustomRule(not_exist="NotNone"))
    await session.commit()

    from_db: CustomRule = (await session.execute(select(CustomRule))).scalars().all()[0]
    assert from_db.not_exist == "NotNone"


async def test_enforcer_basic(async_enforcer: AsyncEnforcer):
    assert async_enforcer.enforce("alice", "data1", "read")
    assert not async_enforcer.enforce("alice", "data1", "write")
    assert not async_enforcer.enforce("bob", "data1", "read")
    assert not async_enforcer.enforce("bob", "data1", "write")
    assert async_enforcer.enforce("bob", "data2", "write")
    assert not async_enforcer.enforce("bob", "data2", "read")
    assert async_enforcer.enforce("alice", "data2", "read")
    assert async_enforcer.enforce("alice", "data2", "write")


async def test_add_policy(async_enforcer: AsyncEnforcer):
    assert not async_enforcer.enforce("eve", "data3", "read")
    res = await async_enforcer.add_policies(
        (("eve", "data3", "read"), ("eve", "data4", "read"))
    )
    assert res
    assert async_enforcer.enforce("eve", "data3", "read")
    assert async_enforcer.enforce("eve", "data4", "read")


async def test_add_policies(async_enforcer: AsyncEnforcer):
    assert not async_enforcer.enforce("eve", "data3", "read")
    res = await async_enforcer.add_permission_for_user("eve", "data3", "read")
    assert res
    assert async_enforcer.enforce("eve", "data3", "read")


async def test_save_policy(async_enforcer: AsyncEnforcer):
    assert not async_enforcer.enforce("alice", "data4", "read")

    model = async_enforcer.get_model()
    model.clear_policy()

    model.add_policy("p", "p", ["alice", "data4", "read"])

    adapter = async_enforcer.get_adapter()
    await adapter.save_policy(model)
    assert async_enforcer.enforce("alice", "data4", "read")


async def test_remove_policy(async_enforcer: AsyncEnforcer):
    assert not async_enforcer.enforce("alice", "data5", "read")
    assert not await async_enforcer.delete_permission_for_user("alice", "data5", "read")
    await async_enforcer.add_permission_for_user("alice", "data5", "read")
    assert async_enforcer.enforce("alice", "data5", "read")
    assert await async_enforcer.delete_permission_for_user("alice", "data5", "read")
    assert not async_enforcer.enforce("alice", "data5", "read")


async def test_remove_policies(async_enforcer: AsyncEnforcer):
    assert not async_enforcer.enforce("alice", "data5", "read")
    assert not async_enforcer.enforce("alice", "data6", "read")
    await async_enforcer.add_policies(
        (("alice", "data5", "read"), ("alice", "data6", "read"))
    )
    assert async_enforcer.enforce("alice", "data5", "read")
    assert async_enforcer.enforce("alice", "data6", "read")
    assert await async_enforcer.remove_policies(
        (("alice", "data5", "read"), ("alice", "data6", "read"))
    )
    assert not async_enforcer.enforce("alice", "data5", "read")
    assert not async_enforcer.enforce("alice", "data6", "read")


async def test_remove_filtered_policy(async_enforcer: AsyncEnforcer):
    assert async_enforcer.enforce("alice", "data1", "read")
    await async_enforcer.remove_filtered_policy(1, "data1")
    assert not async_enforcer.enforce("alice", "data1", "read")

    assert async_enforcer.enforce("bob", "data2", "write")
    assert async_enforcer.enforce("alice", "data2", "read")
    assert async_enforcer.enforce("alice", "data2", "write")

    await async_enforcer.remove_filtered_policy(1, "data2", "read")

    assert async_enforcer.enforce("bob", "data2", "write")
    assert not async_enforcer.enforce("alice", "data2", "read")
    assert async_enforcer.enforce("alice", "data2", "write")

    await async_enforcer.remove_filtered_policy(2, "write")

    assert not async_enforcer.enforce("bob", "data2", "write")
    assert not async_enforcer.enforce("alice", "data2", "write")

    # await async_enforcer.add_permission_for_user("alice", "data6", "delete")
    # await async_enforcer.add_permission_for_user("bob", "data6", "delete")
    # await async_enforcer.add_permission_for_user("eve", "data6", "delete")
    # assert async_enforcer.enforce("alice", "data6", "delete")
    # assert async_enforcer.enforce("bob", "data6", "delete")
    # assert async_enforcer.enforce("eve", "data6", "delete")
    # await async_enforcer.remove_filtered_policy(0, "alice", None, "delete")
    # assert not async_enforcer.enforce("alice", "data6", "delete")
    # await async_enforcer.remove_filtered_policy(0, None, None, "delete")
    # assert not async_enforcer.enforce("bob", "data6", "delete")
    # assert not async_enforcer.enforce("eve", "data6", "delete")


async def test_str():
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


async def test_repr(engine: AsyncEngine, session: AsyncSession):
    rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
    assert repr(rule) == '<CasbinRule None: "p, alice, data1, read">'
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    session.add(rule)
    await session.commit()
    re.search(repr(rule), r'<CasbinRule \d+: "p, alice, data1, read">')
    await session.close()


async def test_filtered_policy(async_enforcer: AsyncEnforcer):
    filter = Filter()

    filter.ptype = ["p"]
    await async_enforcer.load_filtered_policy(filter)
    assert async_enforcer.enforce("alice", "data1", "read")
    assert not async_enforcer.enforce("alice", "data1", "write")
    assert not async_enforcer.enforce("alice", "data2", "read")
    assert not async_enforcer.enforce("alice", "data2", "write")
    assert not async_enforcer.enforce("bob", "data1", "read")
    assert not async_enforcer.enforce("bob", "data1", "write")
    assert not async_enforcer.enforce("bob", "data2", "read")
    assert async_enforcer.enforce("bob", "data2", "write")

    filter.ptype = []
    filter.v0 = ["alice"]
    await async_enforcer.load_filtered_policy(filter)
    assert async_enforcer.enforce("alice", "data1", "read")
    assert not async_enforcer.enforce("alice", "data1", "write")
    assert not async_enforcer.enforce("alice", "data2", "read")
    assert not async_enforcer.enforce("alice", "data2", "write")
    assert not async_enforcer.enforce("bob", "data1", "read")
    assert not async_enforcer.enforce("bob", "data1", "write")
    assert not async_enforcer.enforce("bob", "data2", "read")
    assert not async_enforcer.enforce("bob", "data2", "write")
    assert not async_enforcer.enforce("data2_admin", "data2", "read")
    assert not async_enforcer.enforce("data2_admin", "data2", "write")

    filter.v0 = ["bob"]
    await async_enforcer.load_filtered_policy(filter)
    assert not async_enforcer.enforce("alice", "data1", "read")
    assert not async_enforcer.enforce("alice", "data1", "write")
    assert not async_enforcer.enforce("alice", "data2", "read")
    assert not async_enforcer.enforce("alice", "data2", "write")
    assert not async_enforcer.enforce("bob", "data1", "read")
    assert not async_enforcer.enforce("bob", "data1", "write")
    assert not async_enforcer.enforce("bob", "data2", "read")
    assert async_enforcer.enforce("bob", "data2", "write")
    assert not async_enforcer.enforce("data2_admin", "data2", "read")
    assert not async_enforcer.enforce("data2_admin", "data2", "write")

    filter.v0 = ["data2_admin"]
    await async_enforcer.load_filtered_policy(filter)
    assert async_enforcer.enforce("data2_admin", "data2", "read")
    assert async_enforcer.enforce("data2_admin", "data2", "read")
    assert not async_enforcer.enforce("alice", "data1", "read")
    assert not async_enforcer.enforce("alice", "data1", "write")
    assert not async_enforcer.enforce("alice", "data2", "read")
    assert not async_enforcer.enforce("alice", "data2", "write")
    assert not async_enforcer.enforce("bob", "data1", "read")
    assert not async_enforcer.enforce("bob", "data1", "write")
    assert not async_enforcer.enforce("bob", "data2", "read")
    assert not async_enforcer.enforce("bob", "data2", "write")

    filter.v0 = ["alice", "bob"]
    await async_enforcer.load_filtered_policy(filter)
    assert async_enforcer.enforce("alice", "data1", "read")
    assert not async_enforcer.enforce("alice", "data1", "write")
    assert not async_enforcer.enforce("alice", "data2", "read")
    assert not async_enforcer.enforce("alice", "data2", "write")
    assert not async_enforcer.enforce("bob", "data1", "read")
    assert not async_enforcer.enforce("bob", "data1", "write")
    assert not async_enforcer.enforce("bob", "data2", "read")
    assert async_enforcer.enforce("bob", "data2", "write")
    assert not async_enforcer.enforce("data2_admin", "data2", "read")
    assert not async_enforcer.enforce("data2_admin", "data2", "write")

    filter.v0 = []
    filter.v1 = ["data1"]
    await async_enforcer.load_filtered_policy(filter)
    assert async_enforcer.enforce("alice", "data1", "read")
    assert not async_enforcer.enforce("alice", "data1", "write")
    assert not async_enforcer.enforce("alice", "data2", "read")
    assert not async_enforcer.enforce("alice", "data2", "write")
    assert not async_enforcer.enforce("bob", "data1", "read")
    assert not async_enforcer.enforce("bob", "data1", "write")
    assert not async_enforcer.enforce("bob", "data2", "read")
    assert not async_enforcer.enforce("bob", "data2", "write")
    assert not async_enforcer.enforce("data2_admin", "data2", "read")
    assert not async_enforcer.enforce("data2_admin", "data2", "write")

    filter.v1 = ["data2"]
    await async_enforcer.load_filtered_policy(filter)
    assert not async_enforcer.enforce("alice", "data1", "read")
    assert not async_enforcer.enforce("alice", "data1", "write")
    assert not async_enforcer.enforce("alice", "data2", "read")
    assert not async_enforcer.enforce("alice", "data2", "write")
    assert not async_enforcer.enforce("bob", "data1", "read")
    assert not async_enforcer.enforce("bob", "data1", "write")
    assert not async_enforcer.enforce("bob", "data2", "read")
    assert async_enforcer.enforce("bob", "data2", "write")
    assert async_enforcer.enforce("data2_admin", "data2", "read")
    assert async_enforcer.enforce("data2_admin", "data2", "write")

    filter.v1 = []
    filter.v2 = ["read"]
    await async_enforcer.load_filtered_policy(filter)
    assert async_enforcer.enforce("alice", "data1", "read")
    assert not async_enforcer.enforce("alice", "data1", "write")
    assert not async_enforcer.enforce("alice", "data2", "read")
    assert not async_enforcer.enforce("alice", "data2", "write")
    assert not async_enforcer.enforce("bob", "data1", "read")
    assert not async_enforcer.enforce("bob", "data1", "write")
    assert not async_enforcer.enforce("bob", "data2", "read")
    assert not async_enforcer.enforce("bob", "data2", "write")
    assert async_enforcer.enforce("data2_admin", "data2", "read")
    assert not async_enforcer.enforce("data2_admin", "data2", "write")

    filter.v2 = ["write"]
    await async_enforcer.load_filtered_policy(filter)
    assert not async_enforcer.enforce("alice", "data1", "read")
    assert not async_enforcer.enforce("alice", "data1", "write")
    assert not async_enforcer.enforce("alice", "data2", "read")
    assert not async_enforcer.enforce("alice", "data2", "write")
    assert not async_enforcer.enforce("bob", "data1", "read")
    assert not async_enforcer.enforce("bob", "data1", "write")
    assert not async_enforcer.enforce("bob", "data2", "read")
    assert async_enforcer.enforce("bob", "data2", "write")
    assert not async_enforcer.enforce("data2_admin", "data2", "read")
    assert async_enforcer.enforce("data2_admin", "data2", "write")


async def test_update_policy(async_enforcer: AsyncEnforcer):
    example_p = ["mike", "cookie", "eat"]

    assert async_enforcer.enforce("alice", "data1", "read")
    await async_enforcer.update_policy(
        ["alice", "data1", "read"], ["alice", "data1", "no_read"]
    )
    assert not async_enforcer.enforce("alice", "data1", "read")

    assert not async_enforcer.enforce("bob", "data1", "read")
    await async_enforcer.add_policy(example_p)
    await async_enforcer.update_policy(example_p, ["bob", "data1", "read"])
    assert async_enforcer.enforce("bob", "data1", "read")

    assert not async_enforcer.enforce("bob", "data1", "write")
    await async_enforcer.update_policy(["bob", "data1", "read"], ["bob", "data1", "write"])
    assert async_enforcer.enforce("bob", "data1", "write")

    assert async_enforcer.enforce("bob", "data2", "write")
    await async_enforcer.update_policy(["bob", "data2", "write"], ["bob", "data2", "read"])
    assert not async_enforcer.enforce("bob", "data2", "write")

    assert async_enforcer.enforce("bob", "data2", "read")
    await async_enforcer.update_policy(["bob", "data2", "read"], ["carl", "data2", "write"])
    assert not async_enforcer.enforce("bob", "data2", "write")

    assert async_enforcer.enforce("carl", "data2", "write")
    await async_enforcer.update_policy(
        ["carl", "data2", "write"], ["carl", "data2", "no_write"]
    )
    assert not async_enforcer.enforce("bob", "data2", "write")


async def test_update_policies(async_enforcer: AsyncEnforcer):
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

    await async_enforcer.update_policies(old_rules, new_rules)

    assert not async_enforcer.enforce("alice", "data1", "read")
    assert async_enforcer.enforce("alice", "data_test", "read")

    assert not async_enforcer.enforce("bob", "data2", "write")
    assert async_enforcer.enforce("bob", "data_test", "write")

    assert not async_enforcer.enforce("data2_admin", "data2", "read")
    assert async_enforcer.enforce("data2_admin", "data_test", "read")

    assert not async_enforcer.enforce("data2_admin", "data2", "write")
    assert async_enforcer.enforce("data2_admin", "data_test", "write")


async def test_is_filtered(engine: AsyncEngine, session: AsyncSession, rbac_model_conf):
    adapter1 = AsyncAdapter(engine)
    enforcer1 = AsyncEnforcer(rbac_model_conf, adapter1)
    await enforcer1.load_policy()
    assert not enforcer1.is_filtered()

    adapter1 = AsyncAdapter(engine, filtered=True)
    enforcer1 = AsyncEnforcer(rbac_model_conf, adapter1)
    await enforcer1.load_policy()
    assert enforcer1.is_filtered()
