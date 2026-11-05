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

The CTF submits a normal form POST to `/workshop/login` with a `token` field and
optional `objective`, `target`, and `scorer` fields. The endpoint accepts only the
configured CTF Origin, bounds the form to 64 KiB, and rate-limits failed logins.
Objectives are limited to 10,000 characters; registry names to 128 characters.
It never takes credentials or arbitrary redirect
destinations from a URL. Success sets a signed `__Host-pyrit-workshop` cookie
(`Secure`, `HttpOnly`, `SameSite=Lax`, path `/`, no Domain) and redirects to `/`,
or to `/attack/chat` with encoded prefill query parameters when supplied.
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

## New-attack links

The unsaved attack page `/attack/chat` accepts optional `objective`, `target`, and
`scorer` query parameters. Target/scorer values are registered names. The page
waits for registry loading, resolves names to current identities, and reports
unknown or ineligible values explicitly. Prefill is applied once per navigation:
subsequent user edits are retained, and existing attack URLs are not modified.
No attack is created, prompt sent, or default preference changed just by opening
a link. Omitting parameters preserves normal new-attack defaults. Objectives in
URLs can appear in browser history, so never put credentials or sensitive material
in these links.
