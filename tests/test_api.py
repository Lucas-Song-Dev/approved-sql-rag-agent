from fastapi.testclient import TestClient

from app.auth import AuthenticatedSession, require_identity
from app.config import Settings
from app.domain import CatalogRecord, Identity, Role, Sensitivity
from app.main import create_app
from app.sql_validation import content_hash

SQL = "SELECT count(*) AS count FROM findings"
RECORD = CatalogRecord(
    id="finding-count",
    name="Finding count",
    description="Counts findings",
    sql_text=SQL,
    sql_hash=content_hash(SQL),
    sensitivity=Sensitivity.low,
    source_commit="abcdef123456",
    source_path="approved_queries/finding-count.sql",
    source_url="https://github.com/example/security-vulnerability-api",
)


class FakeCatalog:
    async def list_accessible(self, role):
        return [RECORD]


class FakeChat:
    async def ask(self, message, role):
        return {
            "answer": "Finding count returned 1 row(s).",
            "selection_reason": "deterministic test",
            "query": RECORD.public(),
            "evidence": {"rows": [{"count": 12}], "row_count": 1, "truncated": False},
        }


class FakeAudit:
    def __init__(self) -> None:
        self.events = []

    async def write(self, event):
        self.events.append(event)

    async def recent(self, identity):
        return [{"outcome": "success", "role": identity.role.value}]


class FailingAudit(FakeAudit):
    async def write(self, event):
        raise RuntimeError("audit database unavailable")


class FailingCatalog:
    async def list_accessible(self, role):
        raise RuntimeError("catalog database unavailable")


class FakeRefreshingAuth:
    cookie_secure = False

    def authenticate(self, sealed_session):
        return AuthenticatedSession(IDENTITY, "refreshed-cookie")


class FakeContextFailure:
    async def ask(self, message, role):
        error = ValueError("summarization failed")
        error.audit_context = {
            "catalog_id": "finding-count",
            "sql_hash": RECORD.sql_hash,
            "source_commit": RECORD.source_commit,
            "parameter_names": ["severity"],
        }
        error.execution_result = {
            "estimated_cost": 10.0,
            "estimated_rows": 2,
            "row_count": 1,
            "duration_ms": 3.5,
        }
        raise error


IDENTITY = Identity("user_1", "analyst@example.com", "org_1", Role.analyst)


def authenticated_app(audit=None):
    app = create_app(FakeCatalog(), FakeChat(), audit_repository=audit)
    app.dependency_overrides[require_identity] = lambda: IDENTITY
    return app


def test_health_catalog_and_chat_api() -> None:
    client = TestClient(authenticated_app())
    assert client.get("/api/health").json()["status"] == "ok"

    catalog = client.get("/api/catalog")
    assert catalog.status_code == 200
    assert catalog.json()["queries"][0]["id"] == "finding-count"
    assert catalog.json()["role"] == "analyst"

    response = client.post(
        "/api/chat",
        json={"message": "How many findings?"},
    )
    assert response.status_code == 200
    assert response.json()["evidence"]["rows"][0]["count"] == 12
    assert client.get("/").status_code == 200
    assert client.get("/chat").status_code == 200


def test_protected_api_rejects_missing_auth_configuration() -> None:
    client = TestClient(
        create_app(
            FakeCatalog(),
            FakeChat(),
            settings=Settings(
                workos_api_key=None,
                workos_client_id=None,
                workos_cookie_password=None,
                _env_file=None,
            ),
        )
    )
    assert client.get("/api/catalog").status_code == 503
    assert client.post("/api/chat", json={"message": "findings"}).status_code == 503


def test_governance_headers_and_cross_origin_protection() -> None:
    client = TestClient(authenticated_app())
    supplied = "00000000-0000-0000-0000-000000000001"
    response = client.get("/api/health", headers={"X-Request-ID": supplied})
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-request-id"] != supplied
    second = client.get("/api/health", headers={"X-Request-ID": supplied})
    assert second.headers["x-request-id"] != response.headers["x-request-id"]
    denied = client.post(
        "/api/chat",
        headers={"Origin": "https://attacker.example"},
        json={"message": "findings"},
    )
    assert denied.status_code == 403
    same_host = client.post(
        "/api/chat",
        headers={"Origin": "http://testserver"},
        json={"message": "findings"},
    )
    assert same_host.status_code == 200


def test_chat_is_rate_limited_per_authenticated_user() -> None:
    app = create_app(
        FakeCatalog(),
        FakeChat(),
        settings=Settings(chat_rate_limit=1, chat_rate_window_seconds=60),
    )
    app.dependency_overrides[require_identity] = lambda: IDENTITY
    client = TestClient(app)
    assert client.post("/api/chat", json={"message": "findings"}).status_code == 200
    assert client.post("/api/chat", json={"message": "findings"}).status_code == 429


def test_successful_chat_writes_and_exposes_scoped_audit() -> None:
    audit = FakeAudit()
    client = TestClient(authenticated_app(audit))
    response = client.post("/api/chat", json={"message": "findings"})
    assert response.status_code == 200
    assert len(audit.events) == 1
    assert audit.events[0].identity == IDENTITY
    assert audit.events[0].outcome == "success"
    recent = client.get("/api/audit/recent")
    assert recent.json()["events"][0]["role"] == "analyst"


def test_refreshed_session_survives_error_response_with_execution_audit() -> None:
    audit = FakeAudit()
    app = create_app(
        FakeCatalog(),
        FakeContextFailure(),
        audit_repository=audit,
        auth_service=FakeRefreshingAuth(),
    )
    client = TestClient(app)
    client.cookies.set("wos_session", "expired")
    response = client.post(
        "/api/chat",
        json={"message": "findings"},
    )
    assert response.status_code == 422
    assert "wos_session=refreshed-cookie" in response.headers["set-cookie"]
    assert audit.events[0].catalog_id == "finding-count"
    assert audit.events[0].actual_rows == 1


def test_query_result_fails_closed_when_audit_write_fails() -> None:
    client = TestClient(authenticated_app(FailingAudit()))
    response = client.post("/api/chat", json={"message": "findings"})
    assert response.status_code == 503
    assert response.json()["detail"] == "Audit persistence is unavailable"


def test_refreshed_session_survives_uncaught_route_failure() -> None:
    app = create_app(
        FailingCatalog(),
        FakeChat(),
        auth_service=FakeRefreshingAuth(),
    )
    client = TestClient(app)
    client.cookies.set("wos_session", "expired")
    response = client.get("/api/catalog")
    assert response.status_code == 500
    assert "wos_session=refreshed-cookie" in response.headers["set-cookie"]


def test_authenticated_user_can_select_demo_role() -> None:
    app = create_app(
        FakeCatalog(),
        FakeChat(),
        auth_service=FakeRefreshingAuth(),
    )
    client = TestClient(app)
    client.cookies.set("wos_session", "session")
    profile = client.get("/api/me", headers={"X-Demo-Role": "admin"})
    assert profile.status_code == 200
    assert profile.json()["email"] == "analyst@example.com"
    assert profile.json()["role"] == "admin"
    assert client.get("/api/me", headers={"X-Demo-Role": "owner"}).status_code == 400
