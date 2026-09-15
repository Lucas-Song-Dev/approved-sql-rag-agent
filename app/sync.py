import argparse
import asyncio
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import asyncpg
import yaml

from app.config import Settings
from app.domain import Role, Sensitivity
from app.embedder import FastEmbedder
from app.sql_validation import content_hash, validate_approved_sql


@dataclass
class SourceQuery:
    id: str
    name: str
    description: str
    sql_text: str
    sql_hash: str
    catalog_hash: str
    parameters: dict[str, Any]
    min_role: Role
    sensitivity: Sensitivity
    source_path: str
    purpose: str = ""
    search_hints: tuple[str, ...] = ()

    @property
    def embedding_text(self) -> str:
        hints = "\n".join(self.search_hints)
        return (
            f"{self.name}\n{self.description}\n{self.purpose}\n{hints}\n"
            f"Parameters: {', '.join(self.parameters)}"
        )


def load_queries(
    source_root: Path,
    metadata_glob: str = "approved_queries/**/*.y*ml",
) -> list[SourceQuery]:
    root = source_root.resolve()
    queries: list[SourceQuery] = []
    seen_ids: set[str] = set()
    for metadata_path in sorted(root.glob(metadata_glob)):
        raw = yaml.safe_load(metadata_path.read_text()) or {}
        entries = raw.get("queries", raw) if isinstance(raw, dict) else raw
        if isinstance(entries, dict):
            entries = [entries]
        for item in entries:
            sql_reference = item.get("sql_file") or item.get("sql")
            if not sql_reference:
                candidate = metadata_path.with_suffix(".sql")
                if not candidate.exists():
                    raise ValueError(f"{metadata_path}: sql_file is required")
                sql_path = candidate
            else:
                sql_path = (metadata_path.parent / sql_reference).resolve()
            if not sql_path.is_relative_to(root):
                raise ValueError(f"{metadata_path}: SQL path escapes source checkout")
            required_fields = {
                "id",
                "description",
                "purpose",
                "search_hints",
                "parameters",
                "min_role",
                "sensitivity",
                "result_columns",
            }
            missing_fields = required_fields - set(item)
            if missing_fields:
                raise ValueError(
                    f"{metadata_path}: missing required metadata {sorted(missing_fields)}"
                )
            sql_text = sql_path.read_text()
            parameters = item.get("parameters") or {}
            if isinstance(parameters, list):
                parameters = {entry["name"]: entry for entry in parameters}
            validate_approved_sql(sql_text, parameters)
            query_hash = content_hash(sql_text)
            expected_hash = item.get("content_hash") or item.get("sql_hash")
            if expected_hash and expected_hash != query_hash:
                raise ValueError(f"{metadata_path}: SQL content hash mismatch")
            query_id = str(item["id"])
            if query_id in seen_ids:
                raise ValueError(f"Duplicate query id: {query_id}")
            seen_ids.add(query_id)
            name = item.get("name") or metadata_path.stem.replace("_", " ").title()
            catalog_hash = content_hash(
                json.dumps(
                    {
                        "id": query_id,
                        "name": name,
                        "description": item.get("description") or "",
                        "purpose": item.get("purpose") or "",
                        "search_hints": item.get("search_hints") or [],
                        "parameters": parameters,
                        "min_role": item.get("min_role", "viewer"),
                        "sensitivity": item.get("sensitivity", "low"),
                        "sql_hash": query_hash,
                    },
                    sort_keys=True,
                )
            )
            queries.append(
                SourceQuery(
                    id=query_id,
                    name=name,
                    description=item.get("description") or "",
                    sql_text=sql_text,
                    sql_hash=query_hash,
                    catalog_hash=catalog_hash,
                    parameters=parameters,
                    min_role=Role(item["min_role"]),
                    sensitivity=Sensitivity(item["sensitivity"]),
                    source_path=str(sql_path.relative_to(root)),
                    purpose=item.get("purpose") or "",
                    search_hints=tuple(item.get("search_hints") or ()),
                )
            )
    return queries


def source_commit(root: Path) -> str:
    return subprocess.check_output(
        ["git", "-c", f"safe.directory={root.resolve()}", "-C", str(root), "rev-parse", "HEAD"],
        text=True,
    ).strip()


async def sync(
    database_url: str,
    queries: list[SourceQuery],
    commit: str,
    source_url: str,
    embedder: Any,
) -> None:
    connection = await asyncpg.connect(database_url)
    try:
        existing_rows = await connection.fetch(
            "SELECT id, catalog_hash FROM approved_queries WHERE source_url=$1",
            source_url,
        )
        existing = {str(row["id"]): row["catalog_hash"] for row in existing_rows}
        changed = [query for query in queries if existing.get(query.id) != query.catalog_hash]
        vectors = embedder.embed([query.embedding_text for query in changed]) if changed else []
        vectors_by_id = dict(zip((query.id for query in changed), vectors, strict=True))
        async with connection.transaction():
            active_ids = []
            for query in queries:
                active_ids.append(query.id)
                if query.id not in vectors_by_id:
                    await connection.execute(
                        """
                        UPDATE approved_queries
                        SET source_commit=$1, source_path=$2, synced_at=now()
                        WHERE id=$3 AND source_url=$4
                        """,
                        commit,
                        query.source_path,
                        query.id,
                        source_url,
                    )
                    continue
                vector = vectors_by_id[query.id]
                await connection.execute(
                    """
                    INSERT INTO approved_queries (
                      id, name, description, sql_text, sql_hash, catalog_hash, parameters,
                      min_role, min_role_level, sensitivity, sensitivity_level,
                      source_commit, source_path, source_url, embedding, synced_at
                    ) VALUES (
                      $1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12,$13,$14,$15::vector,now()
                    )
                    ON CONFLICT (id) DO UPDATE SET
                      name=EXCLUDED.name, description=EXCLUDED.description,
                      sql_text=EXCLUDED.sql_text, sql_hash=EXCLUDED.sql_hash,
                      catalog_hash=EXCLUDED.catalog_hash,
                      parameters=EXCLUDED.parameters, min_role=EXCLUDED.min_role,
                      min_role_level=EXCLUDED.min_role_level,
                      sensitivity=EXCLUDED.sensitivity,
                      sensitivity_level=EXCLUDED.sensitivity_level,
                      source_commit=EXCLUDED.source_commit, source_path=EXCLUDED.source_path,
                      source_url=EXCLUDED.source_url, embedding=EXCLUDED.embedding,
                      synced_at=now()
                    """,
                    query.id,
                    query.name,
                    query.description,
                    query.sql_text,
                    query.sql_hash,
                    query.catalog_hash,
                    json.dumps(query.parameters),
                    query.min_role.value,
                    {"viewer": 1, "analyst": 2, "admin": 3}[query.min_role.value],
                    query.sensitivity.value,
                    {"low": 1, "medium": 2, "high": 3}[query.sensitivity.value],
                    commit,
                    query.source_path,
                    source_url,
                    "[" + ",".join(str(value) for value in vector) + "]",
                )
            await connection.execute(
                "DELETE FROM approved_queries WHERE source_url=$1 AND NOT (id=ANY($2::text[]))",
                source_url,
                active_ids,
            )
    finally:
        await connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--source-commit")
    parser.add_argument("--metadata-glob", default="approved_queries/**/*.y*ml")
    args = parser.parse_args()
    settings = Settings()
    queries = load_queries(args.source_root, args.metadata_glob)
    commit = args.source_commit or source_commit(args.source_root)
    embedder = FastEmbedder(settings.embedding_model, settings.embedding_dimensions)
    asyncio.run(
        sync(
            os.environ.get("VECTOR_DATABASE_URL", settings.vector_database_url),
            queries,
            commit,
            args.source_url,
            embedder,
        )
    )


if __name__ == "__main__":
    main()
