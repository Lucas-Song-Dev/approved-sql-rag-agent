from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest

from app.audit import AuditEvent, AuditRepository
from app.domain import Identity, Role


class FakeConnection:
    def __init__(self) -> None:
        self.executed = None
        self.args = ()

    async def execute(self, query, *args):
        self.executed = query
        self.args = args

    async def fetch(self, query, *args):
        self.executed = query
        self.args = args
        return [
            {
                "request_id": "00000000-0000-0000-0000-000000000001",
                "user_email": "viewer@example.com",
                "role": "viewer",
                "outcome": "success",
                "catalog_id": "approved.v1",
                "parameter_names": ["cve_id"],
                "estimated_cost": 10.0,
                "estimated_rows": 1,
                "actual_rows": 1,
                "duration_ms": 2.0,
                "error_category": None,
                "created_at": datetime.now(UTC),
            }
        ]


class FakeDatabase:
    def __init__(self) -> None:
        self.connection_value = FakeConnection()

    @asynccontextmanager
    async def connection(self):
        yield self.connection_value


@pytest.mark.asyncio
async def test_audit_persists_only_parameter_names_and_scopes_viewers() -> None:
    database = FakeDatabase()
    repository = AuditRepository(database)
    identity = Identity("user_1", "viewer@example.com", "org_1", Role.viewer)
    await repository.write(
        AuditEvent(
            request_id="00000000-0000-0000-0000-000000000001",
            identity=identity,
            outcome="success",
            catalog_id="approved.v1",
            parameter_names=["cve_id"],
        )
    )
    serialized_args = repr(database.connection_value.args)
    assert "cve_id" in serialized_args
    assert "CVE-2024-SECRET" not in serialized_args

    events = await repository.recent(identity)
    assert "user_id = $2" in database.connection_value.executed
    assert events[0]["catalog_id"] == "approved.v1"
    assert events[0]["created_at"].endswith("+00:00")


@pytest.mark.asyncio
async def test_admin_audit_scope_is_organization_wide() -> None:
    database = FakeDatabase()
    repository = AuditRepository(database)
    admin = Identity("user_2", "admin@example.com", "org_1", Role.admin)
    await repository.recent(admin)
    assert "user_id = $2" not in database.connection_value.executed
