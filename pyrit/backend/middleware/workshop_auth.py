# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Whole-application HTTP Basic authentication for disposable team workshops."""

import base64
import binascii
import logging
from collections import deque
from hashlib import sha256
from hmac import compare_digest
from time import monotonic

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from pyrit.backend.authentication_policy import AuthenticationPolicy
from pyrit.backend.middleware.auth import AuthenticatedUser

logger = logging.getLogger(__name__)


class WorkshopAuthMiddleware:
    """Protect the GUI, APIs, media and WebSockets without buffering responses."""

    def __init__(self, app: ASGIApp) -> None:
        """Wrap all transports with the process-start workshop policy."""
        self.app = app
        self._failures: deque[float] = deque(maxlen=60)

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
        headers = Headers(scope=scope)
        if not self._authenticated(headers=headers, policy=policy):
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
        # Browsers attach Basic credentials automatically; protect state-changing requests from CSRF.
        if (scope["type"] == "websocket" or scope["method"] not in {"GET", "HEAD", "OPTIONS"}) and headers.get(
            "origin"
        ) != policy.workshop_origin:
            logger.warning("Workshop authentication rejected a cross-origin request.")
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            else:
                await JSONResponse({"detail": "Same-origin request required."}, status_code=403)(scope, receive, send)
            return
        scope.setdefault("state", {})["user"] = AuthenticatedUser(
            oid=policy.workshop_username, name=policy.workshop_username, email="", groups=[], is_admin=False
        )
        await self.app(scope, receive, send)
