Async SQLModel Adapter for PyCasbin
====

## Repo
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/shepilov-vladislav/async-casbin-sqlmodel-adapter/Pytest?logo=github&style=for-the-badge)](https://github.com/shepilov-vladislav/async-casbin-sqlmodel-adapter)
[![Codecov](https://img.shields.io/codecov/c/github/shepilov-vladislav/async-casbin-sqlmodel-adapter?logo=codecov&style=for-the-badge)](https://github.com/shepilov-vladislav/async-casbin-sqlmodel-adapter)
[![Code Climate maintainability](https://img.shields.io/codeclimate/maintainability/shepilov-vladislav/async-casbin-sqlmodel-adapter?logo=code%20climate&style=for-the-badge)](https://github.com/shepilov-vladislav/async-casbin-sqlmodel-adapter)
[![Dependabot](https://img.shields.io/badge/dependabot-Active-brightgreen?logo=dependabot&style=for-the-badge)](https://github.com/shepilov-vladislav/async-casbin-sqlmodel-adapter)


## GitHub

[![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/shepilov-vladislav/async-casbin-sqlmodel-adapter?label=latest%20stable&sort=semver&style=for-the-badge)](https://github.com/shepilov-vladislav/async-casbin-sqlmodel-adapter/releases)
[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/shepilov-vladislav/async-casbin-sqlmodel-adapter?label=latest%20unstable&style=for-the-badge)](https://github.com/shepilov-vladislav/async-casbin-sqlmodel-adapter/releases)
[![GitHub last commit](https://img.shields.io/github/last-commit/shepilov-vladislav/async-casbin-sqlmodel-adapter?style=for-the-badge)](https://github.com/shepilov-vladislav/async-casbin-sqlmodel-adapter/commits/master)

## PyPI

[![PyPI - Version](https://img.shields.io/pypi/v/async-casbin-sqlmodel-adapter?style=for-the-badge)](https://pypi.org/project/async-casbin-sqlmodel-adapter)
[![PyPI - Python Versions](https://img.shields.io/pypi/pyversions/async-casbin-sqlmodel-adapter?style=for-the-badge)](https://pypi.org/project/async-casbin-sqlmodel-adapter)
[![PyPI - Python Wheel](https://img.shields.io/pypi/wheel/async-casbin-sqlmodel-adapter?style=for-the-badge)](https://pypi.org/project/async-casbin-sqlmodel-adapter)
[![PyPI - Format](https://img.shields.io/pypi/format/async-casbin-sqlmodel-adapter?style=for-the-badge)](https://pypi.org/project/async-casbin-sqlmodel-adapter)
[![PyPI - Status](https://img.shields.io/pypi/status/async-casbin-sqlmodel-adapter?style=for-the-badge)](https://pypi.org/project/async-casbin-sqlmodel-adapter)
[![PyPI - Downloads](https://img.shields.io/pypi/dd/async-casbin-sqlmodel-adapter?style=for-the-badge)](https://pypi.org/project/async-casbin-sqlmodel-adapter)
[![PyPI - License](https://img.shields.io/pypi/l/async-casbin-sqlmodel-adapter?style=for-the-badge)](https://pypi.org/project/async-casbin-sqlmodel-adapter)

Async SQLModel Adapter is the [SQLModel](https://github.com/tiangolo/sqlmodel) adapter for [PyCasbin](https://github.com/casbin/pycasbin). With this library, Casbin can load policy from SQLModel supported database or save policy to it.

Based on [Officially Supported Databases](https://github.com/tiangolo/sqlmodel), The current supported databases are:

- PostgreSQL
- MySQL
- SQLite

## Installation

```
pip install async_casbin_sqlmodel_adapter
```

or

```
poetry add async-casbin-sqlmodel-adapter
```

## Simple Example

```python
# Stdlib:
import asyncio

# Thirdparty:
import casbin
from async_casbin_sqlmodel_adapter import Adapter
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import Field, SQLModel

engine = create_async_engine("sqlite+aiosqlite:///")


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


async def main():
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    adapter = Adapter(engine)

    e = casbin.Enforcer("path/to/model.conf", adapter, True)

    sub = "alice"  # the user that wants to access a resource.
    obj = "data1"  # the resource that is going to be accessed.
    act = "read"  # the operation that the user performs on the resource.

    if e.enforce(sub, obj, act):
        # permit alice to read data1async_casbin_sqlmodel_adapter
        pass
    else:
        # deny the request, show an error
        pass


asyncio.run(main())
```


### Getting Help

- [PyCasbin](https://github.com/casbin/pycasbin)

### License

This project is licensed under the [Apache 2.0 license](LICENSE).
