import pytest

from app.sql_validation import SqlValidationError, content_hash, validate_approved_sql


def test_accepts_single_parameterized_select() -> None:
    assert validate_approved_sql(
        "SELECT id FROM findings WHERE severity = :severity",
        {"severity": {"type": "string"}},
    ) == {"severity"}


def test_accepts_psycopg_named_parameters_from_source_repository() -> None:
    assert validate_approved_sql(
        "SELECT id FROM findings WHERE cve_id = %(cve_id)s",
        {"cve_id": {"type": "string"}},
    ) == {"cve_id"}


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM findings",
        "UPDATE findings SET severity='low'",
        "SELECT 1; DROP TABLE findings",
        "INSERT INTO findings(id) VALUES (1)",
        "SELECT * INTO archived_findings FROM findings",
    ],
)
def test_rejects_mutation_and_multiple_statements(sql: str) -> None:
    with pytest.raises(SqlValidationError):
        validate_approved_sql(sql, {})


def test_rejects_parameter_metadata_mismatch() -> None:
    with pytest.raises(SqlValidationError, match="Parameter mismatch"):
        validate_approved_sql("SELECT * FROM assets WHERE owner=:owner", {})


def test_content_hash_is_newline_stable() -> None:
    assert content_hash("SELECT 1\r\n") == content_hash("SELECT 1\n")
