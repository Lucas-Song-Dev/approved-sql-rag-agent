from contextlib import asynccontextmanager

import pytest

from app.catalog import CatalogRepository, can_access
from app.domain import Role
from app.embedder import DeterministicEmbedder


class RecordingConnection:
    def __init__(self) -> None:
        self.query = ""
        self.args = ()

    async def fetch(self, query: str, *args: object) -> list[object]:
        self.query = query
        self.args = args
        return []


class FakePool:
    def __init__(self) -> None:
        self.conn = RecordingConnection()

    @asynccontextmanager
    async def connection(self):
        yield self.conn


def test_role_validation_and_access_matrix() -> None:
    assert can_access(Role.viewer, Role.viewer)
    assert not can_access(Role.viewer, Role.analyst)
    assert can_access(Role.admin, Role.analyst)


@pytest.mark.asyncio
async def test_access_filter_is_applied_before_vector_ranking() -> None:
    pool = FakePool()
    repository = CatalogRepository(pool, DeterministicEmbedder())
    await repository.search("critical findings", Role.viewer)
    normalized = " ".join(pool.conn.query.split())
    assert "WITH accessible AS" in normalized
    assert "min_role_level <= $2" in normalized
    assert normalized.index("WHERE min_role_level") < normalized.index("ORDER BY embedding")
    assert pool.conn.args[1] == 1
