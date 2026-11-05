# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Whole-application Basic and browser-session authentication for team workshops."""

import base64
import binascii
import logging
import re
from collections import deque
from hashlib import sha256
from hmac import compare_digest, digest
from http.cookies import CookieError, SimpleCookie
from secrets import token_bytes, token_urlsafe
from time import monotonic, time
from typing import ClassVar
from urllib.parse import parse_qs, urlencode

from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from pyrit.backend.authentication_policy import AuthenticationPolicy
from pyrit.backend.middleware.auth import AuthenticatedUser

logger = logging.getLogger(__name__)


class WorkshopAuthMiddleware:
    """Protect the GUI, APIs, media and WebSockets without buffering responses."""

    COOKIE_NAME: ClassVar[str] = "__Host-pyrit-workshop"
    SESSION_SECONDS: ClassVar[int] = 8 * 60 * 60
    LOGIN_PATH: ClassVar[str] = "/workshop/login"
    LOGOUT_PATH: ClassVar[str] = "/workshop/logout"

    def __init__(self, app: ASGIApp) -> None:
        """Wrap all transports with the process-start workshop policy."""
        self.app = app
        self._failures: deque[float] = deque(maxlen=60)
        self._session_key = token_bytes(32)

    def _session_signature(self, *, payload: str, policy: AuthenticationPolicy) -> str:
        message = f"{policy.workshop_username}\n{policy.workshop_origin}\n{payload}".encode()
        return digest(self._session_key, policy.workshop_password_hash + message, "sha256").hex()

    def _session_cookie(self, policy: AuthenticationPolicy) -> str:
        payload = f"{int(time())}.{token_urlsafe(16)}"
        return f"{payload}.{self._session_signature(payload=payload, policy=policy)}"

    def _cookie_authenticated(self, *, headers: Headers, policy: AuthenticationPolicy) -> bool:
        cookies = headers.getlist("cookie")
        if len(cookies) != 1 or len(cookies[0]) > 8192:
            return False
        parsed = SimpleCookie()
        try:
            parsed.load(cookies[0])
        except CookieError:
            return False
        cookie = parsed.get(self.COOKIE_NAME)
        if cookie is None or not re.fullmatch(r"[0-9]{1,12}\.[A-Za-z0-9_-]{22}\.[a-f0-9]{64}", cookie.value):
            return False
        payload, signature = cookie.value.rsplit(".", 1)
        issued = int(payload.split(".", 1)[0])
        valid_signature = compare_digest(signature, self._session_signature(payload=payload, policy=policy))
        return valid_signature and 0 <= time() - issued < self.SESSION_SECONDS

    def _login_limited(self) -> bool:
        now = monotonic()
        while self._failures and self._failures[0] <= now - 60:
            self._failures.popleft()
        return len(self._failures) >= 60

    async def _login_async(self, *, scope: Scope, receive: Receive, policy: AuthenticationPolicy) -> Response:
        if scope["method"] != "POST":
            return JSONResponse({"detail": "Use POST to sign in."}, status_code=405, headers={"Allow": "POST"})
        headers = Headers(scope=scope)
        if not policy.workshop_login_origin or headers.getlist("origin") != [policy.workshop_login_origin]:
            logger.warning("Workshop login rejected an untrusted origin.")
            return JSONResponse({"detail": "Sign in from the configured CTF platform."}, status_code=403)
        if self._login_limited():
            return JSONResponse({"detail": "Too many login failures."}, status_code=429, headers={"Retry-After": "60"})
        if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/x-www-form-urlencoded":
            return JSONResponse({"detail": "Submit a form token."}, status_code=415)
        body = bytearray()
        async for chunk in Request(scope, receive=receive).stream():
            if len(body) + len(chunk) > 65536:
                return JSONResponse({"detail": "Login form is too large."}, status_code=413)
            body.extend(chunk)
        try:
            fields = parse_qs(body.decode("ascii"), keep_blank_values=True, strict_parsing=True, max_num_fields=5)
        except (UnicodeDecodeError, ValueError):
            fields = {}
        tokens = fields.get("token", [])
        token = tokens[0] if "token" in fields and len(tokens) == 1 else ""
        if (
            not token.isascii()
            or not 16 <= len(token) <= 128
            or not compare_digest(sha256(token.encode()).digest(), policy.workshop_password_hash)
        ):
            self._failures.append(monotonic())
            logger.warning("Workshop login rejected invalid credentials.")
            return JSONResponse({"detail": "Invalid team token. Return to the CTF and sign in again."}, status_code=401)
        allowed = {"token", "objective", "target", "scorer"}
        if set(fields) - allowed or any(len(values) != 1 for values in fields.values()):
            return JSONResponse({"detail": "Invalid new attack fields."}, status_code=400)
        prefill = {name: values[0] for name, values in fields.items() if name != "token"}
        for name, value in prefill.items():
            if len(value) > (10000 if name == "objective" else 128) or (
                name != "objective" and not re.fullmatch(r"[A-Za-z0-9_.-]+", value)
            ):
                return JSONResponse({"detail": "Invalid new attack field."}, status_code=400)
        destination = "/attack/chat?" + urlencode(prefill) if prefill else "/"
        response = RedirectResponse(destination, status_code=303)
        response.set_cookie(
            self.COOKIE_NAME,
            self._session_cookie(policy),
            max_age=self.SESSION_SECONDS,
            path="/",
            secure=True,
            httponly=True,
            samesite="lax",
        )
        return response

    @staticmethod
    def _authenticated(*, headers: Headers, policy: AuthenticationPolicy) -> bool:
        authorization = headers.getlist("authorization")
        if len(authorization) != 1 or len(authorization[0]) > 1024:
            return False
        scheme, _, encoded = authorization[0].partition(" ")
        if scheme.casefold() != "basic":
            return False
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("ascii")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return False
        username, separator, password = decoded.partition(":")
        if not separator:
            return False
        correct_user = compare_digest(username.encode(), policy.workshop_username.encode())
        correct_password = compare_digest(sha256(password.encode()).digest(), policy.workshop_password_hash)
        return correct_user & correct_password

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Require team credentials before admitting application traffic."""
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        policy: AuthenticationPolicy = scope["app"].state.authentication_policy
        if policy.mode != "workshop":
            await self.app(scope, receive, send)
            return
        if scope["type"] == "http" and scope["method"] == "GET" and scope["path"] == "/api/health":
            await self.app(scope, receive, send)
            return
        if scope["type"] == "http" and scope["path"] == self.LOGIN_PATH:
            response = await self._login_async(scope=scope, receive=receive, policy=policy)
            response.headers["Cache-Control"] = "no-store"
            await response(scope, receive, send)
            return
        headers = Headers(scope=scope)
        if not self._authenticated(headers=headers, policy=policy) and not self._cookie_authenticated(
            headers=headers, policy=policy
        ):
            now = monotonic()
            while self._failures and self._failures[0] <= now - 60:
                self._failures.popleft()
            limited = len(self._failures) >= 60
            self._failures.append(now)
            logger.warning("Workshop authentication rejected a request.")
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            else:
                await JSONResponse(
                    {"detail": "Too many login failures." if limited else "Team credentials required."},
                    status_code=429 if limited else 401,
                    headers={
                        "WWW-Authenticate": 'Basic realm="CoPyRIT workshop", charset="UTF-8"',
                        "Cache-Control": "no-store",
                        **({"Retry-After": "60"} if limited else {}),
                    },
                )(scope, receive, send)
            return
        # Browsers attach Basic credentials and cookies automatically; require same-origin mutations.
        if (scope["type"] == "websocket" or scope["method"] not in {"GET", "HEAD", "OPTIONS"}) and headers.get(
            "origin"
        ) != policy.workshop_origin:
            logger.warning("Workshop authentication rejected a cross-origin request.")
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            else:
                await JSONResponse({"detail": "Same-origin request required."}, status_code=403)(scope, receive, send)
            return
        if scope["type"] == "http" and scope["path"] == self.LOGOUT_PATH:
            if scope["method"] != "POST":
                await JSONResponse({"detail": "Use POST to sign out."}, status_code=405, headers={"Allow": "POST"})(
                    scope, receive, send
                )
                return
            response = JSONResponse(
                {"detail": "Workshop browser session cleared."}, headers={"Cache-Control": "no-store"}
            )
            response.delete_cookie(self.COOKIE_NAME, path="/", secure=True, httponly=True, samesite="lax")
            await response(scope, receive, send)
            return
        scope.setdefault("state", {})["user"] = AuthenticatedUser(
            oid=policy.workshop_username, name=policy.workshop_username, email="", groups=[], is_admin=False
        )
        await self.app(scope, receive, send)
