# Disposable workshop authentication

`pyrit_backend --auth-mode workshop` is an opt-in mode for short, isolated
team deployments behind HTTPS ingress. It uses the browser's native HTTP Basic
login prompt, not Microsoft Entra or a persistent multi-user identity system.
Existing `local` and `entra` modes are unchanged.

Set these process variables before startup:

- `PYRIT_WORKSHOP_USERNAME`: the team's ASCII username, e.g. `team-1`.
- `PYRIT_WORKSHOP_PASSWORD`: a randomly generated 16-128 character ASCII secret.
- `PYRIT_WORKSHOP_ORIGIN`: the exact public HTTPS origin, without a trailing slash.

Missing/invalid settings, Entra settings, or anonymous-admin access fail startup.
Credentials protect the whole GUI, APIs, media, and WebSockets. GET `/api/health`
is the only public HTTP route; add `?ready=true` for a deployment readiness probe
that responds with 503 when runtime initialization has not succeeded.

Authenticated team members share one non-administrator identity and one database.
They cannot use configuration-administrator endpoints. The middleware compares
credentials in constant time, rate-limits failed logins, and requires the configured
Origin for mutations and WebSocket connections. HTTP Basic credentials are sent
on every request: expose the deployment only through HTTPS and never log the
Authorization header. No credentials should be embedded in the frontend image.

Basic authentication does not provide a reliable application logout or session
expiry. Close the browser session or use separate private sessions when changing
teams. Rotate passwords and shut down deployments after the workshop. Restart
the backend to pick up changed credentials.

This mode does not change model-provider authentication. A separate
`WORKSHOP_TOKEN` can identify the team to a CTF server; reusing it as the login
password deliberately gives its holder both permissions.
