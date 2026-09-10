import re
from datetime import date, datetime
from typing import Any

from app.catalog import can_access
from app.database import PoolManager
from app.domain import CatalogRecord, Role
from app.sql_validation import (
    COLON_PARAMETER_PATTERN,
    PSYCOPG_PARAMETER_PATTERN,
    content_hash,
    extract_parameters,
    validate_approved_sql,
)


class ExecutionError(ValueError):
    pass


def validate_parameter_values(specs: dict[str, Any], values: dict[str, Any]) -> None:
    if set(values) != set(specs):
        raise ExecutionError(
            f"Parameters must match exactly (required={sorted(specs)}, supplied={sorted(values)})"
        )
    checks = {
        "string": lambda value: isinstance(value, str),
        "integer": lambda value: isinstance(value, int) and not isinstance(value, bool),
        "number": lambda value: isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": lambda value: isinstance(value, bool),
        "date": lambda value: isinstance(value, str) and _is_iso_date(value),
        "datetime": lambda value: isinstance(value, str) and _is_iso_datetime(value),
        "array": lambda value: isinstance(value, list),
    }
    for name, specification in specs.items():
        if not isinstance(specification, dict):
            continue
        value = values[name]
        if value is None and not specification.get("required", True):
            continue
        expected = specification.get("type", "string")
        if expected not in checks or not checks[expected](value):
            raise ExecutionError(f"Parameter '{name}' must be {expected}")
        if "enum" in specification and value not in specification["enum"]:
            raise ExecutionError(f"Parameter '{name}' is not an allowed value")
        if "pattern" in specification and not re.fullmatch(specification["pattern"], value):
            raise ExecutionError(f"Parameter '{name}' does not match its required format")
        if "minimum" in specification and value < specification["minimum"]:
            raise ExecutionError(f"Parameter '{name}' is below its minimum")
        if "maximum" in specification and value > specification["maximum"]:
            raise ExecutionError(f"Parameter '{name}' exceeds its maximum")
        if "min_length" in specification and len(value) < specification["min_length"]:
            raise ExecutionError(f"Parameter '{name}' is too short")
        if "max_length" in specification and len(value) > specification["max_length"]:
            raise ExecutionError(f"Parameter '{name}' is too long")


def _is_iso_date(value: str) -> bool:
    try:
        date.fromisoformat(value)
        return True
    except ValueError:
        return False


def _is_iso_datetime(value: str) -> bool:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def bind_query(sql: str, values: dict[str, Any]) -> tuple[str, list[Any]]:
    required = extract_parameters(sql)
    if set(values) != required:
        detail = f"required={sorted(required)}, supplied={sorted(values)}"
        raise ExecutionError(
            f"Parameters must match exactly ({detail})"
        )
    positions: dict[str, int] = {}
    arguments: list[Any] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in positions:
            positions[name] = len(arguments) + 1
            arguments.append(values[name])
        return f"${positions[name]}"

    query = COLON_PARAMETER_PATTERN.sub(replace, sql)
    query = PSYCOPG_PARAMETER_PATTERN.sub(replace, query)
    return query, arguments


class QueryExecutor:
    def __init__(self, database: PoolManager, timeout_ms: int, row_cap: int) -> None:
        self.database = database
        self.timeout_ms = timeout_ms
        self.row_cap = row_cap

    async def execute(
        self, record: CatalogRecord, role: Role, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        if not can_access(role, record.min_role):
            raise PermissionError("Role cannot access this query")
        validate_approved_sql(record.sql_text, record.parameters)
        if content_hash(record.sql_text) != record.sql_hash:
            raise ExecutionError("Catalog SQL integrity check failed")
        validate_parameter_values(record.parameters, parameters)
        query, arguments = bind_query(record.sql_text, parameters)
        query = query.rstrip().removesuffix(";")
        limited_query = (
            f"SELECT * FROM ({query}) AS approved_result LIMIT {self.row_cap + 1}"
        )

        async with self.database.connection() as connection:
            async with connection.transaction(readonly=True):
                await connection.execute(f"SET LOCAL statement_timeout = '{self.timeout_ms}ms'")
                rows = await connection.fetch(
                    limited_query, *arguments, timeout=self.timeout_ms / 1000
                )
        truncated = len(rows) > self.row_cap
        output = [dict(row) for row in rows[: self.row_cap]]
        return {"rows": output, "row_count": len(output), "truncated": truncated}
