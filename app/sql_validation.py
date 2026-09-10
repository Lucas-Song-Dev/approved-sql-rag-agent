import hashlib
import re
from typing import Any

import sqlglot
from sqlglot import exp

COLON_PARAMETER_PATTERN = re.compile(r"(?<!:):([A-Za-z_][A-Za-z0-9_]*)")
PSYCOPG_PARAMETER_PATTERN = re.compile(r"%\(([A-Za-z_][A-Za-z0-9_]*)\)s")
FORBIDDEN_NODES = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Create,
    exp.Drop,
    exp.Alter,
    exp.Command,
    exp.Copy,
    exp.Merge,
    exp.Into,
)


class SqlValidationError(ValueError):
    pass


def extract_parameters(sql: str) -> set[str]:
    return set(COLON_PARAMETER_PATTERN.findall(sql)) | set(
        PSYCOPG_PARAMETER_PATTERN.findall(sql)
    )


def validate_approved_sql(sql: str, declared_parameters: dict[str, Any] | None = None) -> set[str]:
    if not sql.strip():
        raise SqlValidationError("SQL is empty")
    # Replace bind markers with a parseable literal. Values remain separately bound at runtime.
    parseable_sql = COLON_PARAMETER_PATTERN.sub("NULL", sql)
    parseable_sql = PSYCOPG_PARAMETER_PATTERN.sub("NULL", parseable_sql)
    try:
        statements = sqlglot.parse(parseable_sql, read="postgres")
    except sqlglot.errors.ParseError as exc:
        raise SqlValidationError(f"Invalid PostgreSQL SQL: {exc}") from exc
    if len(statements) != 1:
        raise SqlValidationError("Exactly one SQL statement is required")
    statement = statements[0]
    if not isinstance(statement, (exp.Select, exp.Union, exp.Intersect, exp.Except)):
        raise SqlValidationError("Only SELECT queries are allowed")
    if any(statement.find(node) is not None for node in FORBIDDEN_NODES):
        raise SqlValidationError("Data-changing SQL is forbidden")

    used = extract_parameters(sql)
    declared = set((declared_parameters or {}).keys())
    if used != declared:
        missing = sorted(used - declared)
        unused = sorted(declared - used)
        raise SqlValidationError(f"Parameter mismatch (undeclared={missing}, unused={unused})")
    return used


def content_hash(sql: str) -> str:
    normalized = sql.replace("\r\n", "\n").strip()
    return hashlib.sha256(normalized.encode()).hexdigest()
