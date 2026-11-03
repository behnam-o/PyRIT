# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import base64
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, Request, Response, WebSocket
from fastapi.testclient import TestClient
from httpx2 import Response as HTTPResponse

from pyrit.backend.authentication_policy import AuthenticationConfigurationError, resolve_authentication_policy
from pyrit.backend.middleware.auth import has_admin_access
from pyrit.backend.middleware.workshop_auth import WorkshopAuthMiddleware
from pyrit.backend.routes.health import health_check_async

SETTINGS = {
    "PYRIT_AUTH_MODE": "workshop",
    "PYRIT_WORKSHOP_USERNAME": "team-1",
    "PYRIT_WORKSHOP_PASSWORD": "test-token-not-a-real-secret",
    "PYRIT_WORKSHOP_ORIGIN": "https://team.example",
    "PYRIT_WORKSHOP_LOGIN_ORIGIN": "https://ctf.example",
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

    return TestClient(app, base_url=SETTINGS["PYRIT_WORKSHOP_ORIGIN"])


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


def login(client: TestClient, *, token: str = SETTINGS["PYRIT_WORKSHOP_PASSWORD"]) -> HTTPResponse:
    return client.post(
        "/workshop/login",
        data={"token": token},
        headers={"Origin": SETTINGS["PYRIT_WORKSHOP_LOGIN_ORIGIN"]},
        follow_redirects=False,
    )


def test_post_login_sets_secure_host_cookie_without_exposing_token(client: TestClient) -> None:
    response = login(client)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert "www-authenticate" not in response.headers
    cookie = response.headers["set-cookie"]
    for value in ("__Host-pyrit-workshop=", "HttpOnly", "Secure", "SameSite=lax", "Path=/", "Max-Age=28800"):
        assert value in cookie
    assert "Domain=" not in cookie
    assert SETTINGS["PYRIT_WORKSHOP_PASSWORD"] not in cookie + response.text
    assert response.headers["cache-control"] == "no-store"
    for path in ("/", "/api/targets", "/api/media", "/api/auth/config", "/assets/app.js"):
        assert client.get(path).status_code == 200
    assert client.get("/api/auth/access").json()["admin"] is False


def test_cookie_login_keeps_csrf_and_websocket_origin_checks(client: TestClient) -> None:
    from starlette.websockets import WebSocketDisconnect

    assert login(client).status_code == 303
    assert client.post("/api/targets", headers={"Origin": SETTINGS["PYRIT_WORKSHOP_ORIGIN"]}).status_code == 200
    assert client.post("/api/targets", headers={"Origin": SETTINGS["PYRIT_WORKSHOP_LOGIN_ORIGIN"]}).status_code == 403
    assert client.post("/api/targets").status_code == 403
    cookie = f"{WorkshopAuthMiddleware.COOKIE_NAME}={client.cookies.get(WorkshopAuthMiddleware.COOKIE_NAME)}"
    with client.websocket_connect(
        "/ws", headers={"Origin": SETTINGS["PYRIT_WORKSHOP_ORIGIN"], "Cookie": cookie}
    ) as socket:
        assert socket.receive_text() == "ok"
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            "/ws", headers={"Origin": SETTINGS["PYRIT_WORKSHOP_LOGIN_ORIGIN"], "Cookie": cookie}
        ):
            pass


@pytest.mark.parametrize("origin", [None, "null", "https://evil.example", "https://team.example"])
def test_handoff_rejects_untrusted_or_missing_origin(client: TestClient, origin: str | None) -> None:
    response = client.post(
        "/workshop/login",
        data={"token": SETTINGS["PYRIT_WORKSHOP_PASSWORD"]},
        headers={"Origin": origin} if origin else {},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert "set-cookie" not in response.headers


def test_handoff_rejects_wrong_method_content_type_and_oversized_body(client: TestClient) -> None:
    headers = {"Origin": SETTINGS["PYRIT_WORKSHOP_LOGIN_ORIGIN"]}
    assert client.get("/workshop/login").status_code == 405
    assert client.post("/workshop/login", json={"token": "example"}, headers=headers).status_code == 415
    assert (
        client.post(
            "/workshop/login",
            content=b"x" * 2049,
            headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
        ).status_code
        == 413
    )
    assert (
        client.post(
            "/workshop/login",
            content="token=first&token=second",
            headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
        ).status_code
        == 401
    )


def test_handoff_is_opt_in_and_rate_limits_invalid_tokens(client: TestClient) -> None:
    for _ in range(60):
        assert login(client, token="wrong-test-token-for-team").status_code == 401
    assert login(client).status_code == 429
    assert client.get("/", headers=HEADERS).status_code == 200
    client.app.state.authentication_policy = resolve_authentication_policy(
        environment={**SETTINGS, "PYRIT_WORKSHOP_LOGIN_ORIGIN": ""}
    )
    assert login(client).status_code == 403


def test_session_rejects_tampering_expiry_and_password_rotation(client: TestClient) -> None:
    assert login(client).status_code == 303
    original = client.cookies.get(WorkshopAuthMiddleware.COOKIE_NAME)
    client.cookies.clear()
    altered = original[:-1] + ("0" if original[-1] != "0" else "1")
    assert client.get("/", headers={"Cookie": f"{WorkshopAuthMiddleware.COOKIE_NAME}={altered}"}).status_code == 401
    headers = {"Cookie": f"{WorkshopAuthMiddleware.COOKIE_NAME}={original}"}
    issued = int(original.split(".", 1)[0])
    with patch("pyrit.backend.middleware.workshop_auth.time", return_value=issued + 28800):
        assert client.get("/", headers=headers).status_code == 401
    with patch("pyrit.backend.middleware.workshop_auth.time", return_value=issued - 1):
        assert client.get("/", headers=headers).status_code == 401
    client.app.state.authentication_policy = resolve_authentication_policy(
        environment={**SETTINGS, "PYRIT_WORKSHOP_PASSWORD": "rotated-test-token-not-real"}
    )
    assert client.get("/", headers=headers).status_code == 401


def test_session_cookie_is_not_valid_in_another_middleware_instance(client: TestClient) -> None:
    assert login(client).status_code == 303
    other_app = FastAPI()
    other_app.state.authentication_policy = resolve_authentication_policy(environment=SETTINGS)
    other_app.add_middleware(WorkshopAuthMiddleware)
    cookie = client.cookies.get(WorkshopAuthMiddleware.COOKIE_NAME)
    with TestClient(other_app, base_url=SETTINGS["PYRIT_WORKSHOP_ORIGIN"]) as other:
        response = other.get(
            "/",
            headers={
                "Cookie": f"{WorkshopAuthMiddleware.COOKIE_NAME}={cookie}",
            },
        )
    assert response.status_code == 401


def test_session_logout_requires_same_origin_post_and_clears_cookie(client: TestClient) -> None:
    assert login(client).status_code == 303
    assert client.get("/workshop/logout").status_code == 405
    assert client.post("/workshop/logout", headers={"Origin": "https://evil.example"}).status_code == 403
    response = client.post("/workshop/logout", headers={"Origin": SETTINGS["PYRIT_WORKSHOP_ORIGIN"]})
    assert response.status_code == 200
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert client.get("/").status_code == 401


@pytest.mark.parametrize("origin", ["http://ctf.example", "https://ctf.example/path", "https://user:pass@ctf.example"])
def test_login_origin_configuration_rejects_invalid_values(origin: str) -> None:
    with pytest.raises(AuthenticationConfigurationError):
        resolve_authentication_policy(environment={**SETTINGS, "PYRIT_WORKSHOP_LOGIN_ORIGIN": origin})
