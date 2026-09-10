from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any


class Role(StrEnum):
    viewer = "viewer"
    analyst = "analyst"
    admin = "admin"


class Sensitivity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"


class RoleLevel(IntEnum):
    viewer = 1
    analyst = 2
    admin = 3


ROLE_ACCESS = {
    Role.viewer: RoleLevel.viewer,
    Role.analyst: RoleLevel.analyst,
    Role.admin: RoleLevel.admin,
}


@dataclass
class CatalogRecord:
    id: str
    name: str
    description: str
    sql_text: str
    sql_hash: str
    parameters: dict[str, Any] = field(default_factory=dict)
    min_role: Role = Role.viewer
    sensitivity: Sensitivity = Sensitivity.low
    source_commit: str = ""
    source_path: str = ""
    source_url: str = ""
    score: float | None = None

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "min_role": self.min_role.value,
            "sensitivity": self.sensitivity.value,
            "source_commit": self.source_commit,
            "source_path": self.source_path,
            "source_url": self.source_url,
            "score": self.score,
        }
