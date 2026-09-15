import json
import re
from typing import Any, Protocol

from anthropic import AsyncAnthropic

from app.catalog import CatalogRepository
from app.domain import ROLE_ACCESS, CatalogRecord, Role
from app.executor import QueryExecutor


class IntentSelector(Protocol):
    async def select(
        self, prompt: str, candidates: list[CatalogRecord]
    ) -> tuple[str, dict[str, Any], str]: ...

    async def summarize(
        self, prompt: str, record: CatalogRecord, result: dict[str, Any]
    ) -> str: ...


class DeterministicIntentSelector:
    async def select(
        self, prompt: str, candidates: list[CatalogRecord]
    ) -> tuple[str, dict[str, Any], str]:
        if not candidates:
            raise LookupError("No accessible approved query matched the request")
        asset_matches = [
            item
            for item in candidates
            if "asset" in item.id and "asset" in prompt.lower() and "open" in prompt.lower()
        ]
        record = max(
            asset_matches or candidates[:1],
            key=lambda item: ROLE_ACCESS[item.min_role],
        )
        parameters: dict[str, Any] = {}
        for name, spec in record.parameters.items():
            match = re.search(rf"\b{name}\s*(?:=|is|:)?\s*([\w.-]+)", prompt, re.IGNORECASE)
            if match:
                parameters[name] = self._coerce(match.group(1), spec)
            elif name == "cve_id" and (
                match := re.search(r"CVE-\d{4}-\d{4,}", prompt, re.IGNORECASE)
            ):
                parameters[name] = match.group(0).upper()
            elif name == "severity" and (
                match := re.search(r"\b(critical|high|medium|low)\b", prompt, re.IGNORECASE)
            ):
                parameters[name] = match.group(1).lower()
            elif isinstance(spec, dict) and "default" in spec:
                parameters[name] = spec["default"]
            else:
                raise ValueError(f"Please provide parameter: {name}")
        return record.id, parameters, f"Selected approved query '{record.name}'."

    async def summarize(
        self, prompt: str, record: CatalogRecord, result: dict[str, Any]
    ) -> str:
        suffix = " Results were capped." if result["truncated"] else ""
        return f"{record.name} returned {result['row_count']} matching row(s).{suffix}"

    @staticmethod
    def _coerce(value: str, specification: Any) -> Any:
        expected = specification.get("type") if isinstance(specification, dict) else "string"
        if expected == "integer":
            return int(value)
        if expected == "number":
            return float(value)
        if expected == "boolean":
            return value.lower() in {"true", "yes", "1"}
        return value


class ClaudeIntentSelector:
    def __init__(self, api_key: str, model: str) -> None:
        self.client = AsyncAnthropic(api_key=api_key)
        self.model = model

    async def select(
        self, prompt: str, candidates: list[CatalogRecord]
    ) -> tuple[str, dict[str, Any], str]:
        catalog = [
            {
                "id": item.id,
                "name": item.name,
                "description": item.description,
                "parameters": item.parameters,
                "minimum_role": item.min_role.value,
                "sensitivity": item.sensitivity.value,
            }
            for item in candidates
        ]
        tool = {
            "name": "choose_approved_query",
            "description": "Choose one retrieved approved query and fill its parameters.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "catalog_id": {"type": "string"},
                    "parameters": {"type": "object"},
                    "reason": {"type": "string"},
                },
                "required": ["catalog_id", "parameters", "reason"],
                "additionalProperties": False,
            },
        }
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=500,
            system=(
                "Select only from the supplied approved-query catalog. "
                "Never request, generate, transform, or return SQL. When multiple queries "
                "match the same intent, choose the richest query whose minimum role is present "
                "in the supplied access-filtered catalog."
            ),
            messages=[
                {
                    "role": "user",
                    "content": f"Request: {prompt}\nRetrieved catalog: {json.dumps(catalog)}",
                }
            ],
            tools=[tool],
            tool_choice={"type": "tool", "name": "choose_approved_query"},
        )
        block = next(item for item in response.content if item.type == "tool_use")
        selected = block.input
        allowed_ids = {item.id for item in candidates}
        if selected["catalog_id"] not in allowed_ids:
            raise ValueError("Model selected a query outside the retrieved catalog")
        return selected["catalog_id"], selected["parameters"], selected["reason"]

    async def summarize(
        self, prompt: str, record: CatalogRecord, result: dict[str, Any]
    ) -> str:
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=700,
            system=(
                "Answer the user's security question concisely from the supplied database "
                "result only. State when no rows matched. Do not invent facts or expose SQL. "
                "Return plain text with short paragraphs and no Markdown formatting."
            ),
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Question: {prompt}\nApproved query: {record.name}\n"
                        f"Result: {json.dumps(result, default=str)}"
                    ),
                }
            ],
        )
        text = " ".join(block.text for block in response.content if block.type == "text").strip()
        if not text:
            raise ValueError("Claude returned no answer text")
        return text


class ChatService:
    def __init__(
        self,
        catalog: CatalogRepository,
        executor: QueryExecutor,
        selector: IntentSelector,
    ) -> None:
        self.catalog = catalog
        self.executor = executor
        self.selector = selector

    async def ask(self, prompt: str, role: Role) -> dict[str, Any]:
        candidates = await self.catalog.search(prompt, role)
        candidates = self._apply_demo_detail_policy(prompt, candidates)
        catalog_id, parameters, reason = await self.selector.select(prompt, candidates)
        record = next(item for item in candidates if item.id == catalog_id)
        audit_context = {
            "catalog_id": record.id,
            "sql_hash": record.sql_hash,
            "source_commit": record.source_commit,
            "parameter_names": sorted(parameters),
        }
        result: dict[str, Any] = {}
        try:
            result = await self.executor.execute(record, role, parameters)
            answer = await self.selector.summarize(prompt, record, result)
        except Exception as exc:
            exc.audit_context = audit_context
            exc.execution_result = result
            raise
        return {
            "answer": answer,
            "selection_reason": reason,
            "query": record.public(),
            "evidence": result,
            "_audit": audit_context,
        }

    @staticmethod
    def _apply_demo_detail_policy(
        prompt: str, candidates: list[CatalogRecord]
    ) -> list[CatalogRecord]:
        normalized = prompt.lower()
        if "asset" not in normalized or "open" not in normalized or "finding" not in normalized:
            return candidates
        asset_candidates = [item for item in candidates if "asset" in item.id]
        if not asset_candidates:
            return candidates
        richest_role = max(ROLE_ACCESS[item.min_role] for item in asset_candidates)
        return [
            item for item in asset_candidates if ROLE_ACCESS[item.min_role] == richest_role
        ]

