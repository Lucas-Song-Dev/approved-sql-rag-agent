import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass, replace
from typing import Annotated

from fastapi import Header, HTTPException, Request
from fastapi.responses import RedirectResponse
from workos import WorkOSClient
from workos.session import seal_session_from_auth_response

from app.config import Settings
from app.domain import Identity, Role

SESSION_COOKIE = "wos_session"
STATE_COOKIE = "wos_auth_state"


def _identity_from_result(result: object) -> Identity:
    user = getattr(result, "user", None)
    organization_id = getattr(result, "organization_id", None)
    if user is None:
        raise HTTPException(403, "Authenticated user identity is incomplete")
    user_id = user.get("id") if isinstance(user, dict) else getattr(user, "id", None)
    email = user.get("email") if isinstance(user, dict) else getattr(user, "email", None)
    if not user_id or not email:
        raise HTTPException(403, "Authenticated user identity is incomplete")
    first_name = (
        user.get("first_name") if isinstance(user, dict) else getattr(user, "first_name", None)
    )
    last_name = (
        user.get("last_name") if isinstance(user, dict) else getattr(user, "last_name", None)
    )
    display_name = " ".join(part for part in (first_name, last_name) if part).strip()
    return Identity(
        user_id=str(user_id),
        email=str(email),
        organization_id=str(organization_id or "demo"),
        role=Role.viewer,
        permissions=tuple(getattr(result, "permissions", None) or ()),
        display_name=display_name or str(email).split("@", 1)[0],
    )


@dataclass
class AuthenticatedSession:
    identity: Identity
    refreshed_session: str | None = None


class WorkOSAuth:
    def __init__(self, settings: Settings, client: WorkOSClient | None = None) -> None:
        if not (
            settings.workos_api_key
            and settings.workos_client_id
            and settings.workos_cookie_password
        ):
            raise ValueError("WorkOS authentication is not configured")
        try:
            decoded_password = base64.urlsafe_b64decode(settings.workos_cookie_password)
        except ValueError as exc:
            raise ValueError("WORKOS_COOKIE_PASSWORD must be URL-safe base64") from exc
        if len(decoded_password) != 32:
            raise ValueError("WORKOS_COOKIE_PASSWORD must encode exactly 32 random bytes")
        self.client = client or WorkOSClient(
            api_key=settings.workos_api_key,
            client_id=settings.workos_client_id,
        )
        self.cookie_password = settings.workos_cookie_password
        self.redirect_uri = settings.workos_redirect_uri
        self.cookie_secure = settings.cookie_secure

    def login_response(self) -> RedirectResponse:
        state = secrets.token_urlsafe(32)
        url = self.client.user_management.get_authorization_url(
            provider="authkit",
            redirect_uri=self.redirect_uri,
            state=state,
        )
        response = RedirectResponse(url=url, status_code=303)
        response.set_cookie(
            STATE_COOKIE,
            self._state_digest(state),
            max_age=600,
            secure=self.cookie_secure,
            httponly=True,
            samesite="lax",
        )
        return response

    def callback_response(
        self,
        code: str,
        state: str,
        state_cookie: str | None,
    ) -> RedirectResponse:
        if not state_cookie or not hmac.compare_digest(state_cookie, self._state_digest(state)):
            raise HTTPException(400, "Invalid authentication state")
        try:
            result = self.client.user_management.authenticate_with_code(
                code=code,
            )
            user_data = result.user.to_dict()
            impersonator = (
                result.impersonator.to_dict() if getattr(result, "impersonator", None) else None
            )
            sealed_session = seal_session_from_auth_response(
                access_token=result.access_token,
                refresh_token=result.refresh_token,
                user=user_data,
                impersonator=impersonator,
                cookie_password=self.cookie_password,
            )
            self.authenticate(sealed_session)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(401, "Authentication failed") from exc
        response = RedirectResponse(url="/chat", status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            sealed_session,
            secure=self.cookie_secure,
            httponly=True,
            samesite="lax",
        )
        response.delete_cookie(STATE_COOKIE)
        return response

    def authenticate(self, sealed_session: str | None) -> AuthenticatedSession:
        if not sealed_session:
            raise HTTPException(401, "Authentication required")
        try:
            session = self.client.user_management.load_sealed_session(
                session_data=sealed_session,
                cookie_password=self.cookie_password,
            )
            result = session.authenticate()
            if result.authenticated:
                return AuthenticatedSession(_identity_from_result(result))
            refreshed = session.refresh()
            if not refreshed.authenticated:
                raise HTTPException(401, "Session expired")
            return AuthenticatedSession(
                _identity_from_result(refreshed),
                refreshed_session=refreshed.sealed_session,
            )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(401, "Invalid session") from exc

    def logout_response(self, sealed_session: str | None) -> RedirectResponse:
        redirect_url = "/"
        if sealed_session:
            try:
                session = self.client.user_management.load_sealed_session(
                    session_data=sealed_session,
                    cookie_password=self.cookie_password,
                )
                redirect_url = session.get_logout_url()
            except Exception:
                pass
        response = RedirectResponse(url=redirect_url, status_code=303)
        response.delete_cookie(SESSION_COOKIE)
        return response

    def _state_digest(self, state: str) -> str:
        return hmac.new(
            self.cookie_password.encode(),
            state.encode(),
            hashlib.sha256,
        ).hexdigest()


def build_auth(settings: Settings) -> WorkOSAuth | None:
    if not (
        settings.workos_api_key
        and settings.workos_client_id
        and settings.workos_cookie_password
    ):
        return None
    return WorkOSAuth(settings)


def require_identity(
    request: Request,
    x_demo_role: Annotated[str | None, Header()] = None,
) -> Identity:
    auth: WorkOSAuth | None = request.app.state.auth
    if auth is None:
        raise HTTPException(503, "Authentication is not configured")
    session = auth.authenticate(request.cookies.get(SESSION_COOKIE))
    if session.refreshed_session:
        request.state.refreshed_session = session.refreshed_session
    identity = session.identity
    if x_demo_role:
        try:
            identity = replace(identity, role=Role(x_demo_role))
        except ValueError as exc:
            raise HTTPException(400, "X-Demo-Role must be viewer, analyst, or admin") from exc
    request.state.identity = identity
    return identity
