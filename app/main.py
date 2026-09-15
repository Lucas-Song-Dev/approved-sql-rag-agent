import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Cookie, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.audit import AuditEvent, AuditRepository
from app.auth import SESSION_COOKIE, WorkOSAuth, build_auth, require_identity
from app.catalog import CatalogRepository
from app.chat import ChatService, ClaudeIntentSelector, DeterministicIntentSelector
from app.config import Settings, get_settings
from app.database import PoolManager
from app.domain import Identity
from app.embedder import FastEmbedder
from app.executor import QueryBudgetExceeded, QueryExecutor
from app.observability import GovernanceMiddleware, RateLimiter


class ChatRequest(BaseModel):
    message: str = Field(min_length=2, max_length=2000)


def build_services(
    settings: Settings,
) -> tuple[CatalogRepository, ChatService, AuditRepository, list[PoolManager]]:
    catalog_db = PoolManager(settings.vector_database_url)
    security_db = PoolManager(settings.security_database_url)
    embedder = FastEmbedder(settings.embedding_model, settings.embedding_dimensions)
    catalog = CatalogRepository(catalog_db, embedder)
    executor = QueryExecutor(
        security_db,
        settings.query_timeout_ms,
        settings.query_row_cap,
        settings.query_max_plan_cost,
        settings.query_max_plan_rows,
    )
    selector = (
        ClaudeIntentSelector(settings.anthropic_api_key, settings.anthropic_model)
        if settings.anthropic_api_key
        else DeterministicIntentSelector()
    )
    return (
        catalog,
        ChatService(catalog, executor, selector),
        AuditRepository(catalog_db),
        [catalog_db, security_db],
    )


def create_app(
    catalog: Any | None = None,
    chat_service: Any | None = None,
    settings: Settings | None = None,
    audit_repository: Any | None = None,
    auth_service: WorkOSAuth | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    managed: list[PoolManager] = []
    if catalog is None or chat_service is None:
        catalog, chat_service, built_audit, managed = build_services(settings)
        audit_repository = audit_repository or built_audit
    auth_service = auth_service or build_auth(settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if audit_repository is not None and hasattr(audit_repository, "ensure_schema"):
            await audit_repository.ensure_schema()
        yield
        for database in managed:
            await database.close()

    api = FastAPI(title="Approved SQL RAG Agent", version="0.1.0", lifespan=lifespan)
    api.state.catalog = catalog
    api.state.chat = chat_service
    api.state.audit = audit_repository
    api.state.auth = auth_service
    api.state.rate_limiter = RateLimiter(
        settings.chat_rate_limit,
        settings.chat_rate_window_seconds,
    )
    api.add_middleware(GovernanceMiddleware, allowed_origin=settings.allowed_origin)

    @api.get("/api/health")
    async def health() -> dict[str, Any]:
        agent = "claude" if settings.anthropic_api_key else "deterministic"
        return {
            "status": "ok",
            "agent": agent,
            "authentication": "workos" if api.state.auth else "not_configured",
            "planner_budget": {
                "max_cost": settings.query_max_plan_cost,
                "max_rows": settings.query_max_plan_rows,
            },
        }

    @api.get("/auth/login", include_in_schema=False)
    def login(request: Request) -> RedirectResponse:
        if request.app.state.auth is None:
            raise HTTPException(503, "Authentication is not configured")
        return request.app.state.auth.login_response()

    @api.get("/auth/callback", include_in_schema=False)
    def callback(
        request: Request,
        code: Annotated[str, Query(min_length=1)],
        state: Annotated[str, Query(min_length=1)],
        state_cookie: Annotated[str | None, Cookie(alias="wos_auth_state")] = None,
    ) -> RedirectResponse:
        if request.app.state.auth is None:
            raise HTTPException(503, "Authentication is not configured")
        return request.app.state.auth.callback_response(code, state, state_cookie)

    @api.post("/auth/logout", include_in_schema=False)
    def logout(
        request: Request,
        sealed_session: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
    ) -> RedirectResponse:
        if request.app.state.auth is None:
            response = RedirectResponse("/", status_code=303)
            response.delete_cookie(SESSION_COOKIE)
            return response
        return request.app.state.auth.logout_response(sealed_session)

    @api.get("/api/me")
    async def me(identity: Annotated[Identity, Depends(require_identity)]) -> dict[str, Any]:
        return {
            "user_id": identity.user_id,
            "email": identity.email,
            "name": identity.display_name,
            "role": identity.role.value,
        }

    @api.get("/api/catalog")
    async def list_catalog(
        request: Request,
        identity: Annotated[Identity, Depends(require_identity)],
    ) -> dict[str, Any]:
        records = await request.app.state.catalog.list_accessible(identity.role)
        return {"queries": [record.public() for record in records], "role": identity.role.value}

    @api.get("/api/audit/recent")
    async def recent_audit(
        request: Request,
        identity: Annotated[Identity, Depends(require_identity)],
    ) -> dict[str, Any]:
        if request.app.state.audit is None:
            return {"events": []}
        return {"events": await request.app.state.audit.recent(identity)}

    @api.post("/api/chat")
    async def chat(
        payload: ChatRequest,
        request: Request,
        identity: Annotated[Identity, Depends(require_identity)],
    ) -> dict[str, Any]:
        try:
            request.app.state.rate_limiter.check(identity.user_id)
        except HTTPException:
            await _write_error_audit(request, identity, "denied", "rate_limit")
            raise
        try:
            result = await request.app.state.chat.ask(payload.message, identity.role)
            audit_context = result.pop("_audit", {})
            evidence = result.get("evidence", {})
            await _write_audit(
                request,
                AuditEvent(
                    request_id=request.state.request_id,
                    identity=identity,
                    outcome="success",
                    catalog_id=audit_context.get("catalog_id"),
                    sql_hash=audit_context.get("sql_hash"),
                    source_commit=audit_context.get("source_commit"),
                    parameter_names=audit_context.get("parameter_names", []),
                    estimated_cost=evidence.get("estimated_cost"),
                    estimated_rows=evidence.get("estimated_rows"),
                    actual_rows=evidence.get("row_count"),
                    duration_ms=evidence.get("duration_ms"),
                ),
            )
            return result
        except QueryBudgetExceeded as exc:
            await _write_audit(
                request,
                AuditEvent(
                    request_id=request.state.request_id,
                    identity=identity,
                    outcome="denied",
                    catalog_id=exc.catalog_id,
                    estimated_cost=exc.estimated_cost,
                    estimated_rows=exc.estimated_rows,
                    error_category="planner_budget",
                ),
            )
            raise HTTPException(422, "Approved query exceeded its execution budget") from exc
        except PermissionError as exc:
            await _write_error_audit(request, identity, "denied", "authorization")
            raise HTTPException(403, "Your role cannot run this approved query") from exc
        except LookupError as exc:
            await _write_error_audit(request, identity, "denied", "no_approved_query")
            raise HTTPException(404, "No accessible approved query matched") from exc
        except HTTPException:
            raise
        except ValueError as exc:
            await _write_exception_audit(request, identity, exc)
            raise HTTPException(422, "The approved query request could not be processed") from exc
        except Exception as exc:
            await _write_exception_audit(request, identity, exc)
            raise HTTPException(500, "The governed query service encountered an error") from exc

    static_dir = Path(__file__).parent / "static"
    api.mount("/static", StaticFiles(directory=static_dir), name="static")

    @api.get("/", include_in_schema=False)
    async def login_portal() -> FileResponse:
        return FileResponse(static_dir / "login.html")

    @api.get("/chat", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(static_dir / "index.html")

    return api


async def _write_error_audit(
    request: Request,
    identity: Identity,
    outcome: str,
    category: str,
) -> None:
    await _write_audit(
        request,
        AuditEvent(
            request_id=request.state.request_id,
            identity=identity,
            outcome=outcome,
            error_category=category,
        ),
    )


async def _write_exception_audit(
    request: Request,
    identity: Identity,
    exc: Exception,
) -> None:
    context = getattr(exc, "audit_context", {})
    result = getattr(exc, "execution_result", {})
    await _write_audit(
        request,
        AuditEvent(
            request_id=request.state.request_id,
            identity=identity,
            outcome="error",
            catalog_id=context.get("catalog_id"),
            sql_hash=context.get("sql_hash"),
            source_commit=context.get("source_commit"),
            parameter_names=context.get("parameter_names", []),
            estimated_cost=result.get("estimated_cost"),
            estimated_rows=result.get("estimated_rows"),
            actual_rows=result.get("row_count"),
            duration_ms=result.get("duration_ms"),
            error_category=type(exc).__name__,
        ),
    )


async def _write_audit(request: Request, event: AuditEvent) -> None:
    if request.app.state.audit is None:
        return
    try:
        await request.app.state.audit.write(event)
        logging.getLogger("sentinel").info(
            "query_governance",
            extra={
                "request_id": event.request_id,
                "user_id": event.identity.user_id,
                "catalog_id": event.catalog_id,
                "outcome": event.outcome,
            },
        )
    except Exception as exc:
        logging.getLogger("sentinel").exception(
            "audit_write_failed",
            extra={"request_id": event.request_id},
        )
        raise HTTPException(503, "Audit persistence is unavailable") from exc


app = create_app()
