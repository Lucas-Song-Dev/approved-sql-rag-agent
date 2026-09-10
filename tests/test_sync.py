from pathlib import Path

import pytest

from app.sync import load_queries, sync


def write_source(root: Path, sql: str, metadata: str) -> Path:
    directory = root / "approved_queries"
    directory.mkdir()
    (directory / "open-findings.sql").write_text(sql)
    (directory / "open-findings.yaml").write_text(metadata)
    return directory


def test_loads_and_validates_source_metadata(tmp_path: Path) -> None:
    write_source(
        tmp_path,
        "SELECT id FROM findings WHERE severity = :severity",
        """
id: open-findings
name: Open findings
description: Finds open vulnerabilities by severity
purpose: Prioritize findings
search_hints: [open findings, severity queue]
sql_file: open-findings.sql
min_role: viewer
sensitivity: medium
parameters:
  severity:
    type: string
result_columns:
  - {name: id, type: integer}
""",
    )
    queries = load_queries(tmp_path, "approved_queries/**/*.y*ml")
    assert len(queries) == 1
    assert queries[0].source_path == "approved_queries/open-findings.sql"
    assert len(queries[0].sql_hash) == 64


def test_rejects_source_path_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.sql"
    outside.write_text("SELECT 1")
    write_source(
        tmp_path,
        "SELECT 1",
        """
id: escaped
sql_file: ../../outside.sql
""",
    )
    with pytest.raises(ValueError, match="escapes"):
        load_queries(tmp_path, "approved_queries/**/*.y*ml")


class FakeTransaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class FakeConnection:
    def __init__(self) -> None:
        self.hashes: dict[str, str] = {}

    async def fetch(self, *_args):
        return [{"id": query_id, "catalog_hash": value} for query_id, value in self.hashes.items()]

    async def execute(self, statement, *args):
        if "INSERT INTO approved_queries" in statement:
            self.hashes[args[0]] = args[5]

    def transaction(self):
        return FakeTransaction()

    async def close(self):
        return None


class CountingEmbedder:
    def __init__(self) -> None:
        self.calls = 0

    def embed(self, texts):
        self.calls += 1
        return [[0.0] * 384 for _ in texts]


@pytest.mark.asyncio
async def test_unchanged_catalog_is_not_reembedded(tmp_path: Path, monkeypatch) -> None:
    write_source(
        tmp_path,
        "SELECT id FROM findings WHERE severity = %(severity)s",
        """
id: open-findings
name: Open findings
description: Finds open vulnerabilities by severity
purpose: Prioritize findings
search_hints: [open findings, severity queue]
min_role: viewer
sensitivity: medium
parameters:
  severity:
    type: string
result_columns:
  - {name: id, type: integer}
""",
    )
    queries = load_queries(tmp_path, "approved_queries/**/*.y*ml")
    connection = FakeConnection()

    async def connect(_database_url):
        return connection

    monkeypatch.setattr("app.sync.asyncpg.connect", connect)
    embedder = CountingEmbedder()
    await sync("postgresql://unused", queries, "commit-1", "https://example/source", embedder)
    await sync("postgresql://unused", queries, "commit-2", "https://example/source", embedder)
    assert embedder.calls == 1
