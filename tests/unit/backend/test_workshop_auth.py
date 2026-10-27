# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import base64
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, Request, Response, WebSocket
from fastapi.testclient import TestClient

from pyrit.backend.authentication_policy import AuthenticationConfigurationError, resolve_authentication_policy
from pyrit.backend.middleware.auth import has_admin_access
from pyrit.backend.middleware.workshop_auth import WorkshopAuthMiddleware
from pyrit.backend.routes.health import health_check_async

SETTINGS = {
    "PYRIT_AUTH_MODE": "workshop",
    "PYRIT_WORKSHOP_USERNAME": "team-1",
    "PYRIT_WORKSHOP_PASSWORD": "test-token-not-a-real-secret",
    "PYRIT_WORKSHOP_ORIGIN": "https://team.example",
}
HEADERS = {
    "Authorization": "Basic " + base64.b64encode(b"team-1:test-token-not-a-real-secret").decode(),
    "Origin": "https://team.example",
}


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.state.authentication_policy = resolve_authentication_policy(environment=SETTINGS)
    app.add_middleware(WorkshopAuthMiddleware)

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def echo_async(request: Request, path: str) -> dict[str, bool | str]:
        return {"path": path, "admin": has_admin_access(request)}

    @app.websocket("/ws")
    async def socket_async(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_text("ok")
        await websocket.close()

    return TestClient(app)


@pytest.mark.parametrize(
    "path", ["/", "/api/targets", "/api/media", "/api/auth/config", "/assets/app.js", "/api/version"]
)
def test_workshop_protects_all_surfaces(client: TestClient, path: str) -> None:
    response = client.get(path)
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Basic ")
    assert client.get(path, headers=HEADERS).status_code == 200


def test_workshop_health_is_public_and_teams_are_not_admins(client: TestClient) -> None:
    assert client.get("/api/health").status_code == 200
    assert client.post("/api/health").status_code == 401
    assert client.get("/api/auth/access", headers=HEADERS).json()["admin"] is False


@pytest.mark.parametrize("authorization", ["Bearer secret", "Basic !!!", "Basic dGVhbS0xOndyb25n", ""])
def test_workshop_bad_credentials(client: TestClient, authorization: str) -> None:
    assert client.get("/", headers={"Authorization": authorization}).status_code == 401


def test_workshop_csrf_and_rate_limit(client: TestClient) -> None:
    assert client.post("/api/targets", headers=HEADERS).status_code == 200
    assert client.post("/api/targets", headers={**HEADERS, "Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/targets", headers={"Authorization": HEADERS["Authorization"]}).status_code == 403
    for _ in range(60):
        assert client.get("/").status_code == 401
    assert client.get("/").status_code == 429
    assert client.get("/", headers=HEADERS).status_code == 200


def test_workshop_websocket_requires_credentials_and_origin(client: TestClient) -> None:
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws"):
            pass
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws", headers={**HEADERS, "Origin": "https://evil.example"}):
            pass
    with client.websocket_connect("/ws", headers=HEADERS) as socket:
        assert socket.receive_text() == "ok"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("PYRIT_WORKSHOP_PASSWORD", ""),
        ("PYRIT_WORKSHOP_USERNAME", ""),
        ("PYRIT_WORKSHOP_ORIGIN", "http://team.example"),
        ("PYRIT_WORKSHOP_ORIGIN", "https://team.example/path"),
        ("PYRIT_ALLOW_UNAUTHENTICATED_ADMIN", "true"),
        ("ENTRA_CLIENT_ID", "unexpected"),
    ],
)
def test_workshop_configuration_fails_closed(key: str, value: str) -> None:
    with pytest.raises(AuthenticationConfigurationError):
        resolve_authentication_policy(environment={**SETTINGS, key: value})


def test_workshop_policy_does_not_disclose_password() -> None:
    policy = resolve_authentication_policy(environment=SETTINGS)
    assert SETTINGS["PYRIT_WORKSHOP_PASSWORD"] not in repr(policy)
    assert policy.enabled is False


@pytest.mark.parametrize(("state", "expected"), [("ready", 200), ("failed", 503), ("initializing", 503)])
async def test_workshop_readiness_status(state: str, expected: int) -> None:
    request = MagicMock(spec=Request)
    request.app = SimpleNamespace(
        state=SimpleNamespace(runtime_lifecycle=SimpleNamespace(reported_state=state, generation="test"))
    )
    request.query_params = {"ready": "true"}
    response = Response()
    result = await health_check_async(request=request, response=response)
    assert response.status_code == expected
    assert result["ready"] is (state == "ready")
