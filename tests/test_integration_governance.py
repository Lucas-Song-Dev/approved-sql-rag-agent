import os
from uuid import uuid4

import asyncpg
import pytest

from app.audit import AuditEvent, AuditRepository
from app.database import PoolManager
from app.domain import CatalogRecord, Identity, Role, Sensitivity
from app.executor import ExecutionError, QueryExecutor
from app.sql_validation import content_hash

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("RUN_INTEGRATION") != "1",
        reason="set RUN_INTEGRATION=1 with both PostgreSQL services running",
    ),
]


@pytest.mark.asyncio
async def test_real_database_cost_audit_and_readonly_controls() -> None:
    vector = PoolManager(os.environ["VECTOR_DATABASE_URL"])
    security = PoolManager(os.environ["SECURITY_DATABASE_URL"])
    try:
        async with vector.connection() as connection:
            assert await connection.fetchval("SELECT count(*) FROM approved_queries") == 7

        sql = "SELECT cve_id FROM vulnerabilities WHERE severity = %(severity)s"
        record = CatalogRecord(
            id="integration.critical.v1",
            name="Critical vulnerabilities",
            description="Integration fixture",
            sql_text=sql,
            sql_hash=content_hash(sql),
            parameters={
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                }
            },
            min_role=Role.viewer,
            sensitivity=Sensitivity.medium,
            source_commit="integration",
        )
        executor = QueryExecutor(
            security,
            timeout_ms=2000,
            row_cap=10,
            max_plan_cost=10000,
            max_plan_rows=10000,
        )
        result = await executor.execute(record, Role.viewer, {"severity": "critical"})
        assert result["estimated_cost"] > 0
        assert result["estimated_rows"] >= 0
        assert result["row_count"] > 0

        with pytest.raises(ExecutionError):
            await executor.execute(
                record,
                Role.viewer,
                {"severity": "critical'; DROP TABLE vulnerabilities; --"},
            )

        async with security.connection() as connection:
            with pytest.raises(asyncpg.PostgresError):
                await connection.execute(
                    "INSERT INTO vulnerabilities "
                    "(cve_id,title,description,severity,cvss_score,affected_asset,status,"
                    "discovered_at) VALUES "
                    "('CVE-2099-9999','x','x','low',1,'x','open',CURRENT_DATE)"
                )

        audit = AuditRepository(vector)
        await audit.ensure_schema()
        identity = Identity("integration-user", "ci@example.com", "ci-org", Role.viewer)
        await audit.write(
            AuditEvent(
                request_id=str(uuid4()),
                identity=identity,
                outcome="success",
                catalog_id=record.id,
                parameter_names=["severity"],
                estimated_cost=result["estimated_cost"],
                estimated_rows=result["estimated_rows"],
                actual_rows=result["row_count"],
                duration_ms=result["duration_ms"],
            )
        )
        events = await audit.recent(identity, limit=1)
        assert events[0]["catalog_id"] == record.id
        assert events[0]["parameter_names"] == ["severity"]
    finally:
        await vector.close()
        await security.close()
