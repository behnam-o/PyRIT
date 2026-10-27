# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Immutable incoming-request authentication policy."""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Literal
from urllib.parse import urlsplit

from pyrit.common.authentication import (
    AUTH_MODE_ENVIRONMENT_VARIABLE,
    REQUIRED_ENTRA_ENVIRONMENT_VARIABLES,
)

AuthenticationMode = Literal["local", "entra", "workshop"]

_ENTRA_VARIABLES = (*REQUIRED_ENTRA_ENVIRONMENT_VARIABLES, "ENTRA_ADMIN_GROUP_ID")
_UNAUTHENTICATED_ADMIN_VARIABLE = "PYRIT_ALLOW_UNAUTHENTICATED_ADMIN"


class AuthenticationConfigurationError(ValueError):
    """Authentication settings cannot produce a safe startup policy."""


@dataclass(frozen=True)
class AuthenticationPolicy:
    """Validated process-start policy for incoming GUI requests."""

    mode: AuthenticationMode
    tenant_id: str = ""
    client_id: str = ""
    allowed_group_ids: tuple[str, ...] = ()
    admin_group_id: str = ""
    allow_unauthenticated_admin: bool = False
    workshop_username: str = ""
    workshop_password_hash: bytes = field(default=b"", repr=False)
    workshop_origin: str = ""

    @property
    def enabled(self) -> bool:
        """Whether Microsoft Entra authentication protects ordinary API requests."""
        return self.mode == "entra"

    @property
    def allowed_group_ids_csv(self) -> str:
        """Normalized group IDs for the frontend bootstrap contract."""
        return ",".join(self.allowed_group_ids)


def _parse_boolean_setting(*, environment: Mapping[str, str], name: str) -> bool:
    raw_value = environment.get(name, "").strip().casefold()
    if not raw_value:
        return False
    if raw_value == "true":
        return True
    if raw_value == "false":
        return False
    raise AuthenticationConfigurationError(f"{name} must be 'true' or 'false' when set.")


def _parse_allowed_group_ids(value: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(group_id.strip() for group_id in value.split(",") if group_id.strip()))


def resolve_authentication_policy(*, environment: Mapping[str, str] | None = None) -> AuthenticationPolicy:
    """
    Resolve and validate the process-start authentication policy.

    Args:
        environment: Process environment to validate. Defaults to ``os.environ``.

    Returns:
        AuthenticationPolicy: Immutable validated authentication policy.

    Raises:
        AuthenticationConfigurationError: If settings are missing, incomplete,
            contradictory, or unsupported.
    """
    environment = os.environ if environment is None else environment
    mode_raw = environment.get(AUTH_MODE_ENVIRONMENT_VARIABLE, "").strip().casefold()
    if mode_raw and mode_raw not in {"local", "entra", "workshop"}:
        raise AuthenticationConfigurationError(
            f"{AUTH_MODE_ENVIRONMENT_VARIABLE} must be 'local', 'entra', or 'workshop'; received {mode_raw!r}."
        )

    tenant_id = environment.get("ENTRA_TENANT_ID", "").strip()
    client_id = environment.get("ENTRA_CLIENT_ID", "").strip()
    allowed_group_ids = _parse_allowed_group_ids(environment.get("ENTRA_ALLOWED_GROUP_IDS", ""))
    admin_group_id = environment.get("ENTRA_ADMIN_GROUP_ID", "").strip()
    allow_unauthenticated_admin = _parse_boolean_setting(
        environment=environment,
        name=_UNAUTHENTICATED_ADMIN_VARIABLE,
    )

    if mode_raw == "workshop":
        if any(name in environment for name in _ENTRA_VARIABLES) or allow_unauthenticated_admin:
            raise AuthenticationConfigurationError("Workshop authentication cannot enable Entra or anonymous admin.")
        username = environment.get("PYRIT_WORKSHOP_USERNAME", "")
        password = environment.get("PYRIT_WORKSHOP_PASSWORD", "")
        origin = environment.get("PYRIT_WORKSHOP_ORIGIN", "")
        if not username or not username.isascii() or not username.replace("-", "").isalnum():
            raise AuthenticationConfigurationError(
                "PYRIT_WORKSHOP_USERNAME must contain ASCII letters, digits or hyphens."
            )
        if not 16 <= len(password) <= 128 or not password.isascii() or any(c.isspace() for c in password):
            raise AuthenticationConfigurationError(
                "PYRIT_WORKSHOP_PASSWORD must contain 16-128 non-whitespace ASCII characters."
            )
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise AuthenticationConfigurationError("PYRIT_WORKSHOP_ORIGIN must be an HTTPS origin without a path.")
        return AuthenticationPolicy(
            mode="workshop",
            workshop_username=username,
            workshop_password_hash=sha256(password.encode()).digest(),
            workshop_origin=origin,
        )

    if mode_raw == "local":
        configured_entra_variables = [name for name in _ENTRA_VARIABLES if name in environment]
        if configured_entra_variables:
            joined_names = ", ".join(configured_entra_variables)
            raise AuthenticationConfigurationError(
                f"{AUTH_MODE_ENVIRONMENT_VARIABLE}=local cannot be combined with Entra settings: {joined_names}."
            )
        return AuthenticationPolicy(
            mode="local",
            allow_unauthenticated_admin=allow_unauthenticated_admin,
        )

    required_values = {
        "ENTRA_TENANT_ID": tenant_id,
        "ENTRA_CLIENT_ID": client_id,
        "ENTRA_ALLOWED_GROUP_IDS": allowed_group_ids,
    }
    missing_settings = [name for name, value in required_values.items() if not value]
    if missing_settings:
        if not mode_raw and not any(name in environment for name in REQUIRED_ENTRA_ENVIRONMENT_VARIABLES):
            raise AuthenticationConfigurationError(
                "Authentication configuration is absent. For loopback-only local development, "
                f"set {AUTH_MODE_ENVIRONMENT_VARIABLE}=local. For a shared deployment, set "
                f"{AUTH_MODE_ENVIRONMENT_VARIABLE}=entra and configure "
                f"{', '.join(REQUIRED_ENTRA_ENVIRONMENT_VARIABLES)}."
            )
        raise AuthenticationConfigurationError(
            f"Incomplete Entra ID configuration: {', '.join(missing_settings)} must be set."
        )
    if allow_unauthenticated_admin:
        raise AuthenticationConfigurationError(
            f"{_UNAUTHENTICATED_ADMIN_VARIABLE}=true is not allowed when Entra authentication is enabled."
        )

    return AuthenticationPolicy(
        mode="entra",
        tenant_id=tenant_id,
        client_id=client_id,
        allowed_group_ids=allowed_group_ids,
        admin_group_id=admin_group_id,
    )
