# Disposable workshop authentication

`pyrit_backend --auth-mode workshop` is an opt-in mode for short, isolated
team deployments behind HTTPS ingress. It supports the browser's native HTTP Basic
login prompt and a trusted CTF POST handoff, not a persistent multi-user identity system.
Existing `local` and `entra` modes are unchanged.

Set these process variables before startup:

- `PYRIT_WORKSHOP_USERNAME`: the team's ASCII username, e.g. `team-1`.
- `PYRIT_WORKSHOP_PASSWORD`: a randomly generated 16-128 character ASCII secret.
- `PYRIT_WORKSHOP_ORIGIN`: the exact public HTTPS origin, without a trailing slash.
- `PYRIT_WORKSHOP_LOGIN_ORIGIN`: optional exact HTTPS origin of the CTF platform.
  Without it, POST handoff is disabled; Basic authentication still works.

Missing/invalid settings, Entra settings, or anonymous-admin access fail startup.
Credentials protect the whole GUI, APIs, media, and WebSockets. GET `/api/health`
is the only anonymous data route; add `?ready=true` for a deployment readiness probe
that responds with 503 when runtime initialization has not succeeded.

Authenticated team members share one non-administrator identity and one database.
They cannot use configuration-administrator endpoints. The middleware compares
credentials in constant time, rate-limits failed logins, and requires the configured
Origin for mutations and WebSocket connections. HTTP Basic credentials are sent
on every request: expose the deployment only through HTTPS and never log the
Authorization header. No credentials should be embedded in the frontend image.

The CTF submits a normal form POST to `/workshop/login` with a single `token`
field. The endpoint accepts only the configured CTF Origin, bounds the form to
2048 bytes, and rate-limits failed logins. It never takes credentials or redirect
destinations from a URL. Success sets a signed `__Host-pyrit-workshop` cookie
(`Secure`, `HttpOnly`, `SameSite=Lax`, path `/`, no Domain) and redirects to `/`.
Ordinary mutation and WebSocket origin checks remain restricted to CoPyRIT's own
origin; the CTF origin is allowed only on this login endpoint.

The cookie expires after eight hours. Signing keys are random per process, so
restarts/deployments invalidate browser sessions; click Open CoPyRIT in the CTF
again. Cookies cannot grant admin access, be shared across team deployments, or
survive a password change. Cookie-only clients can POST `/workshop/logout` from
CoPyRIT's own origin to clear their browser session. Logging out of the CTF does
not automatically log out CoPyRIT. No cross-domain session sharing is attempted.

Basic authentication remains a fallback and has no reliable browser logout.
Close the browser session or use separate private sessions when changing teams.
Rotate passwords and shut down deployments after the workshop. Restart the
backend to pick up changed credentials.

This mode does not change model-provider authentication. A separate
`WORKSHOP_TOKEN` can identify the team to a CTF server; reusing it as the login
password deliberately gives its holder both permissions.
