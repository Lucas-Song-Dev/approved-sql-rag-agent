import json
import logging
import time
from collections import defaultdict, deque
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        for name in (
            "request_id",
            "method",
            "path",
            "status",
            "duration_ms",
            "user_id",
            "catalog_id",
            "outcome",
        ):
            value = getattr(record, name, None)
            if value is not None:
                data[name] = value
        return json.dumps(data, separators=(",", ":"), default=str)


def configure_logging() -> None:
    logger = logging.getLogger("sentinel")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


class GovernanceMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Any, allowed_origin: str) -> None:
        super().__init__(app)
        self.allowed_origin = allowed_origin.rstrip("/")
        configure_logging()
        self.logger = logging.getLogger("sentinel")

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        request_id = str(uuid4())
        request.state.request_id = request_id
        started = time.perf_counter()
        origin = request.headers.get("origin")
        if request.method not in {"GET", "HEAD", "OPTIONS"} and origin:
            if origin.rstrip("/") != self.allowed_origin:
                response = Response("Cross-origin request denied", status_code=403)
            else:
                response = await self._call_safely(request, call_next)
        else:
            response = await self._call_safely(request, call_next)
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        refreshed_session = getattr(request.state, "refreshed_session", None)
        auth = getattr(request.app.state, "auth", None)
        if refreshed_session and auth is not None:
            response.set_cookie(
                "wos_session",
                refreshed_session,
                secure=auth.cookie_secure,
                httponly=True,
                samesite="lax",
            )
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        identity = getattr(request.state, "identity", None)
        self.logger.info(
            "http_request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "user_id": getattr(identity, "user_id", None),
            },
        )
        return response

    async def _call_safely(self, request: Request, call_next: Any) -> Response:
        try:
            return await call_next(request)
        except Exception:
            self.logger.exception(
                "unhandled_request_error",
                extra={"request_id": request.state.request_id, "path": request.url.path},
            )
            return JSONResponse(
                {"detail": "The service encountered an unexpected error"},
                status_code=500,
            )


class RateLimiter:
    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> None:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        bucket = self.hits[key]
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= self.limit:
            raise HTTPException(429, "Chat request limit reached; try again shortly")
        bucket.append(now)
