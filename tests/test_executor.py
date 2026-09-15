from contextlib import asynccontextmanager

import pytest

from app.domain import CatalogRecord, Role, Sensitivity
from app.executor import (
    ExecutionError,
    QueryBudgetExceeded,
    QueryExecutor,
    bind_query,
    parse_plan_estimate,
    validate_parameter_values,
)
from app.sql_validation import content_hash


def record(sql: str = "SELECT id FROM findings WHERE owner = :owner") -> CatalogRecord:
    return CatalogRecord(
        id="findings-by-owner",
        name="Findings by owner",
        description="Open findings for one owner",
        sql_text=sql,
        sql_hash=content_hash(sql),
        parameters={"owner": {"type": "string"}},
        min_role=Role.analyst,
        sensitivity=Sensitivity.medium,
    )


def test_parameter_values_are_never_interpolated() -> None:
    attack = "sam'; DROP TABLE findings; --"
    query, arguments = bind_query(record().sql_text, {"owner": attack})
    assert query.endswith("owner = $1")
    assert attack not in query
    assert arguments == [attack]

    psycopg_query, psycopg_arguments = bind_query(
        "SELECT id FROM findings WHERE owner = %(owner)s", {"owner": attack}
    )
    assert psycopg_query.endswith("owner = $1")
    assert psycopg_arguments == [attack]


def test_parameters_must_match_exactly() -> None:
    with pytest.raises(ExecutionError):
        bind_query(record().sql_text, {"owner": "sam", "sql": "SELECT secret"})


def test_parameter_contract_constraints_are_enforced() -> None:
    with pytest.raises(ExecutionError, match="maximum"):
        validate_parameter_values(
            {"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
            {"limit": 1000},
        )
    with pytest.raises(ExecutionError, match="format"):
        validate_parameter_values(
            {"cve_id": {"type": "string", "pattern": r"^CVE-\d{4}-\d{4,}$"}},
            {"cve_id": "anything'; DROP TABLE vulnerabilities; --"},
        )


class Transaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class FakeConnection:
    def __init__(self) -> None:
        self.executed = []

    def transaction(self, **kwargs):
        assert kwargs == {"readonly": True}
        return Transaction()

    async def execute(self, statement: str):
        self.executed.append(statement)

    async def fetchval(self, query: str, *args, **kwargs):
        self.executed.append(query)
        return [{"Plan": {"Total Cost": 12.5, "Plan Rows": 4}}]

    async def fetch(self, query: str, *args, **kwargs):
        self.executed.append(query)
        return [{"id": 7}]


class FakeDatabase:
    def __init__(self) -> None:
        self.conn = FakeConnection()

    @asynccontextmanager
    async def connection(self):
        yield self.conn


@pytest.mark.asyncio
async def test_executor_checks_role_hash_and_readonly_transaction() -> None:
    database = FakeDatabase()
    executor = QueryExecutor(database, timeout_ms=1000, row_cap=10)
    result = await executor.execute(record(), Role.analyst, {"owner": "sam"})
    assert result["rows"] == [{"id": 7}]
    assert result["estimated_cost"] == 12.5
    assert result["estimated_rows"] == 4
    assert database.conn.executed[0].startswith("SET LOCAL statement_timeout")
    assert database.conn.executed[1].startswith("EXPLAIN (FORMAT JSON)")

    tampered = record()
    tampered.sql_text += " AND true"
    with pytest.raises(ExecutionError, match="integrity"):
        await executor.execute(tampered, Role.admin, {"owner": "sam"})

    with pytest.raises(PermissionError):
        await executor.execute(record(), Role.viewer, {"owner": "sam"})


def test_plan_estimate_parsing_and_budget_rejection() -> None:
    assert parse_plan_estimate('[{"Plan":{"Total Cost":42.25,"Plan Rows":12}}]') == (42.25, 12)
    nested = [
        {
            "Plan": {
                "Total Cost": 20,
                "Plan Rows": 10,
                "Plans": [{"Total Cost": 19, "Plan Rows": 500}],
            }
        }
    ]
    assert parse_plan_estimate(nested) == (20.0, 500)


@pytest.mark.asyncio
async def test_executor_rejects_over_budget_query_before_fetch() -> None:
    database = FakeDatabase()
    executor = QueryExecutor(
        database,
        timeout_ms=1000,
        row_cap=10,
        max_plan_cost=10,
        max_plan_rows=100,
    )
    with pytest.raises(QueryBudgetExceeded) as raised:
        await executor.execute(record(), Role.analyst, {"owner": "sam"})
    assert raised.value.catalog_id == "findings-by-owner"
    assert not any(statement.startswith("SELECT *") for statement in database.conn.executed)
