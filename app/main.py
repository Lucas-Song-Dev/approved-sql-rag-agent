from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.catalog import CatalogRepository
from app.chat import ChatService, ClaudeIntentSelector, DeterministicIntentSelector
from app.config import Settings, get_settings
from app.database import PoolManager
from app.domain import Role
from app.embedder import FastEmbedder
from app.executor import QueryExecutor


class ChatRequest(BaseModel):
    message: str = Field(min_length=2, max_length=2000)


def current_role(x_demo_role: Annotated[str, Header()] = "viewer") -> Role:
    try:
        return Role(x_demo_role)
    except ValueError as exc:
        raise HTTPException(400, "X-Demo-Role must be viewer, analyst, or admin") from exc


def build_services(settings: Settings) -> tuple[CatalogRepository, ChatService, list[PoolManager]]:
    catalog_db = PoolManager(settings.vector_database_url)
    security_db = PoolManager(settings.security_database_url)
    embedder = FastEmbedder(settings.embedding_model, settings.embedding_dimensions)
    catalog = CatalogRepository(catalog_db, embedder)
    executor = QueryExecutor(security_db, settings.query_timeout_ms, settings.query_row_cap)
    selector = (
        ClaudeIntentSelector(settings.anthropic_api_key, settings.anthropic_model)
        if settings.anthropic_api_key
        else DeterministicIntentSelector()
    )
    return catalog, ChatService(catalog, executor, selector), [catalog_db, security_db]


def create_app(
    catalog: Any | None = None,
    chat_service: Any | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    managed: list[PoolManager] = []
    if catalog is None or chat_service is None:
        catalog, chat_service, managed = build_services(settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        for database in managed:
            await database.close()

    api = FastAPI(title="Approved SQL RAG Agent", version="0.1.0", lifespan=lifespan)
    api.state.catalog = catalog
    api.state.chat = chat_service

    @api.get("/api/health")
    async def health() -> dict[str, str]:
        agent = "claude" if settings.anthropic_api_key else "deterministic"
        return {"status": "ok", "agent": agent}

    @api.get("/api/catalog")
    async def list_catalog(
        request: Request, role: Annotated[Role, Depends(current_role)]
    ) -> dict[str, Any]:
        records = await request.app.state.catalog.list_accessible(role)
        return {"queries": [record.public() for record in records], "role": role.value}

    @api.post("/api/chat")
    async def chat(
        payload: ChatRequest,
        request: Request,
        role: Annotated[Role, Depends(current_role)],
    ) -> dict[str, Any]:
        try:
            return await request.app.state.chat.ask(payload.message, role)
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    static_dir = Path(__file__).parent / "static"
    api.mount("/static", StaticFiles(directory=static_dir), name="static")

    @api.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(static_dir / "index.html")

    return api


app = create_app()
