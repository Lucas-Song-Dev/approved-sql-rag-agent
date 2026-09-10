from fastapi.testclient import TestClient

from app.domain import CatalogRecord, Sensitivity
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


def test_health_catalog_and_chat_api() -> None:
    client = TestClient(create_app(FakeCatalog(), FakeChat()))
    assert client.get("/api/health").json()["status"] == "ok"

    catalog = client.get("/api/catalog", headers={"X-Demo-Role": "viewer"})
    assert catalog.status_code == 200
    assert catalog.json()["queries"][0]["id"] == "finding-count"

    response = client.post(
        "/api/chat",
        headers={"X-Demo-Role": "viewer"},
        json={"message": "How many findings?"},
    )
    assert response.status_code == 200
    assert response.json()["evidence"]["rows"][0]["count"] == 12
    assert client.get("/").status_code == 200


def test_invalid_role_is_rejected() -> None:
    client = TestClient(create_app(FakeCatalog(), FakeChat()))
    assert client.get("/api/catalog", headers={"X-Demo-Role": "root"}).status_code == 400
