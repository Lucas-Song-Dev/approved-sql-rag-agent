import json
from typing import Any

from app.database import PoolManager
from app.domain import ROLE_ACCESS, CatalogRecord, Role, Sensitivity
from app.embedder import Embedder


def _vector_literal(vector: list[float]) -> str:
    return "[" + ",".join(str(value) for value in vector) + "]"


class CatalogRepository:
    def __init__(self, database: PoolManager, embedder: Embedder) -> None:
        self.database = database
        self.embedder = embedder

    async def search(self, prompt: str, role: Role, limit: int = 3) -> list[CatalogRecord]:
        vector = _vector_literal(self.embedder.embed([prompt])[0])
        # Authorization is filtered before the distance expression ranks candidates.
        query = """
            WITH accessible AS (
              SELECT * FROM approved_queries
              WHERE min_role_level <= $2
            )
            SELECT id, name, description, sql_text, sql_hash, parameters,
                   min_role, sensitivity, source_commit, source_path, source_url,
                   embedding <=> $1::vector AS score
            FROM accessible
            ORDER BY embedding <=> $1::vector
            LIMIT $3
        """
        async with self.database.connection() as connection:
            rows = await connection.fetch(query, vector, int(ROLE_ACCESS[role]), limit)
        return [self._record(row) for row in rows]

    async def list_accessible(self, role: Role, limit: int = 100) -> list[CatalogRecord]:
        query = """
            SELECT id, name, description, sql_text, sql_hash, parameters,
                   min_role, sensitivity, source_commit, source_path, source_url
            FROM approved_queries
            WHERE min_role_level <= $1
            ORDER BY name LIMIT $2
        """
        async with self.database.connection() as connection:
            rows = await connection.fetch(query, int(ROLE_ACCESS[role]), limit)
        return [self._record(row) for row in rows]

    @staticmethod
    def _record(row: Any) -> CatalogRecord:
        parameters = row["parameters"]
        if isinstance(parameters, str):
            parameters = json.loads(parameters)
        values = dict(row)
        return CatalogRecord(
            id=str(values["id"]),
            name=values["name"],
            description=values["description"],
            sql_text=values["sql_text"],
            sql_hash=values["sql_hash"],
            parameters=parameters,
            min_role=Role(values["min_role"]),
            sensitivity=Sensitivity(values["sensitivity"]),
            source_commit=values["source_commit"],
            source_path=values["source_path"],
            source_url=values["source_url"],
            score=values.get("score"),
        )


def can_access(role: Role, min_role: Role) -> bool:
    return ROLE_ACCESS[role] >= ROLE_ACCESS[min_role]
