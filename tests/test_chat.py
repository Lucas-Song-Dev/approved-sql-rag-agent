import pytest

from app.chat import ChatService, DeterministicIntentSelector
from app.domain import CatalogRecord, Role, Sensitivity
from app.sql_validation import content_hash


def asset_query(role: Role) -> CatalogRecord:
    sql = "SELECT affected_asset FROM vulnerabilities LIMIT %(limit)s"
    return CatalogRecord(
        id=f"security.asset_open_findings_{role.value}.v1",
        name=f"Asset findings for {role.value}",
        description="Which assets have the most open findings?",
        sql_text=sql,
        sql_hash=content_hash(sql),
        parameters={"limit": {"type": "integer", "default": 25}},
        min_role=role,
        sensitivity=Sensitivity.low if role is Role.viewer else Sensitivity.high,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("available_roles", "expected_role"),
    [
        ([Role.viewer], Role.viewer),
        ([Role.viewer, Role.analyst], Role.analyst),
        ([Role.viewer, Role.analyst, Role.admin], Role.admin),
    ],
)
async def test_demo_question_uses_richest_accessible_asset_query(
    available_roles: list[Role], expected_role: Role
) -> None:
    selector = DeterministicIntentSelector()
    candidates = [asset_query(role) for role in available_roles]
    catalog_id, parameters, _ = await selector.select(
        "Which assets have the most open findings?", candidates
    )
    assert catalog_id == f"security.asset_open_findings_{expected_role.value}.v1"
    assert parameters == {"limit": 25}


def test_demo_detail_policy_limits_claude_to_richest_role_query() -> None:
    candidates = [asset_query(role) for role in Role]
    scoped = ChatService._apply_demo_detail_policy(
        "Which assets have the most open findings?", candidates
    )
    assert [record.min_role for record in scoped] == [Role.admin]
