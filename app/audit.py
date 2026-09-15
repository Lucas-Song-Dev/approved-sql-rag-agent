import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.database import PoolManager
from app.domain import Identity, Role


@dataclass
class AuditEvent:
    request_id: str
    identity: Identity
    outcome: str
    catalog_id: str | None = None
    sql_hash: str | None = None
    source_commit: str | None = None
    parameter_names: list[str] = field(default_factory=list)
    estimated_cost: float | None = None
    estimated_rows: int | None = None
    actual_rows: int | None = None
    duration_ms: float | None = None
    error_category: str | None = None


class AuditRepository:
    def __init__(self, database: PoolManager) -> None:
        self.database = database

    async def ensure_schema(self) -> None:
        async with self.database.connection() as connection:
            await connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                  request_id uuid NOT NULL UNIQUE,
                  user_id text NOT NULL,
                  user_email text NOT NULL,
                  organization_id text NOT NULL,
                  role text NOT NULL CHECK (role IN ('viewer', 'analyst', 'admin')),
                  outcome text NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
                  catalog_id text,
                  sql_hash char(64),
                  source_commit text,
                  parameter_names jsonb NOT NULL DEFAULT '[]'::jsonb,
                  estimated_cost double precision,
                  estimated_rows bigint,
                  actual_rows integer,
                  duration_ms double precision,
                  error_category text,
                  created_at timestamptz NOT NULL DEFAULT now()
                );
                CREATE INDEX IF NOT EXISTS audit_events_org_created_idx
                  ON audit_events (organization_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS audit_events_user_created_idx
                  ON audit_events (user_id, created_at DESC);
                """
            )

    async def write(self, event: AuditEvent) -> None:
        async with self.database.connection() as connection:
            await connection.execute(
                """
                INSERT INTO audit_events (
                    request_id, user_id, user_email, organization_id, role, outcome,
                    catalog_id, sql_hash, source_commit, parameter_names,
                    estimated_cost, estimated_rows, actual_rows, duration_ms, error_category
                )
                VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb,
                    $11, $12, $13, $14, $15
                )
                """,
                event.request_id,
                event.identity.user_id,
                event.identity.email,
                event.identity.organization_id,
                event.identity.role.value,
                event.outcome,
                event.catalog_id,
                event.sql_hash,
                event.source_commit,
                json.dumps(event.parameter_names),
                event.estimated_cost,
                event.estimated_rows,
                event.actual_rows,
                event.duration_ms,
                event.error_category,
            )

    async def recent(self, identity: Identity, limit: int = 20) -> list[dict[str, Any]]:
        where = "organization_id = $1"
        args: list[Any] = [identity.organization_id]
        if identity.role is not Role.admin:
            where += " AND user_id = $2"
            args.append(identity.user_id)
        args.append(limit)
        query = f"""
            SELECT request_id, user_email, role, outcome, catalog_id, parameter_names,
                   estimated_cost, estimated_rows, actual_rows, duration_ms,
                   error_category, created_at
            FROM audit_events
            WHERE {where}
            ORDER BY created_at DESC
            LIMIT ${len(args)}
        """
        async with self.database.connection() as connection:
            rows = await connection.fetch(query, *args)
        return [self._public(dict(row)) for row in rows]

    @staticmethod
    def _public(row: dict[str, Any]) -> dict[str, Any]:
        created = row.get("created_at")
        if isinstance(created, datetime):
            row["created_at"] = created.astimezone(UTC).isoformat()
        return row
