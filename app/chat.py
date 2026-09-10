import json
import re
from typing import Any, Protocol

from anthropic import AsyncAnthropic

from app.catalog import CatalogRepository
from app.domain import CatalogRecord, Role
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
        record = candidates[0]
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
                "Never request, generate, transform, or return SQL."
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
                "result only. State when no rows matched. Do not invent facts or expose SQL."
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
        catalog_id, parameters, reason = await self.selector.select(prompt, candidates)
        record = next(item for item in candidates if item.id == catalog_id)
        result = await self.executor.execute(record, role, parameters)
        return {
            "answer": await self.selector.summarize(prompt, record, result),
            "selection_reason": reason,
            "query": record.public(),
            "evidence": result,
        }

