from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

from app.auth import WorkOSAuth
from app.config import Settings
from app.domain import Role


class FakeUser:
    id = "user_1"
    email = "analyst@example.com"
    first_name = "Avery"
    last_name = "Chen"

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
        }


def result(role: str = "analyst", authenticated: bool = True):
    return SimpleNamespace(
        authenticated=authenticated,
        user=FakeUser(),
        organization_id="org_1",
        role=role,
        permissions=["queries:read"],
        sealed_session="sealed-refreshed",
        access_token="access-token",
        refresh_token="refresh-token",
        impersonator=None,
    )


class FakeSession:
    def __init__(self, auth_result=None, refresh_result=None) -> None:
        self.auth_result = auth_result or result()
        self.refresh_result = refresh_result or result()

    def authenticate(self):
        return self.auth_result

    def refresh(self):
        return self.refresh_result

    def get_logout_url(self):
        return "https://auth.example/logout"


class FakeUserManagement:
    def __init__(self) -> None:
        self.state = ""
        self.kwargs: dict[str, object] = {}
        self.session = FakeSession()
        self.cookie_password = ""

    def get_authorization_url(self, **kwargs):
        self.kwargs = kwargs
        self.state = kwargs["state"]
        return f"https://auth.example/authorize?state={self.state}"

    def authenticate_with_code(self, **kwargs):
        assert kwargs == {"code": "code"}
        return result()

    def load_sealed_session(self, **kwargs):
        assert kwargs["cookie_password"] == self.cookie_password
        assert kwargs["session_data"]
        return self.session


class FakeClient:
    def __init__(self) -> None:
        self.user_management = FakeUserManagement()


def auth() -> tuple[WorkOSAuth, FakeClient]:
    client = FakeClient()
    cookie_password = Fernet.generate_key().decode()
    settings = Settings(
        workos_api_key="sk_test",
        workos_client_id="client_test",
        workos_cookie_password=cookie_password,
    )
    service = WorkOSAuth(settings, client=client)
    client.user_management.cookie_password = cookie_password
    return service, client


def test_login_callback_and_profile_mapping() -> None:
    service, client = auth()
    login = service.login_response()
    assert login.status_code == 303
    assert "organization_id" not in client.user_management.kwargs
    assert "httponly" in login.headers["set-cookie"].lower()
    state = client.user_management.state
    callback = service.callback_response("code", state, service._state_digest(state))
    assert "wos_session=" in callback.headers["set-cookie"]
    assert callback.headers["location"] == "/chat"
    session = service.authenticate("sealed")
    assert session.identity.role is Role.viewer
    assert session.identity.display_name == "Avery Chen"
    assert session.identity.organization_id == "org_1"


def test_invalid_oauth_state_is_rejected() -> None:
    service, _ = auth()
    with pytest.raises(HTTPException, match="state"):
        service.callback_response("code", "state", "wrong")


def test_expired_session_is_refreshed() -> None:
    service, client = auth()
    client.user_management.session = FakeSession(
        auth_result=SimpleNamespace(authenticated=False),
        refresh_result=result("viewer"),
    )
    session = service.authenticate("sealed")
    assert session.identity.role is Role.viewer
    assert session.refreshed_session == "sealed-refreshed"


def test_missing_organization_membership_uses_demo_scope() -> None:
    service, client = auth()
    client.user_management.session = FakeSession(
        auth_result=SimpleNamespace(
            authenticated=True,
            user=FakeUser(),
            organization_id=None,
            role="analyst",
            permissions=[],
        )
    )
    session = service.authenticate("sealed")
    assert session.identity.organization_id == "demo"
    assert session.identity.role is Role.viewer
