# Threat Model: bwh-auth

_Last reviewed: 2026-05-07 (package version 0.1.4). Re-review after changes to form components, WebAuthn helpers, or the endpoint-config surface._

## Scope

`bwh-auth` provides shared headless React auth UI components and browser WebAuthn helpers for BWH applications.

Covered package capabilities:

- Login form behavior, including explicit passkey login and WebAuthn conditional UI.
- Signup form behavior, including custom fields and passwordless signup support hooks.
- Password reset request and reset password forms.
- Password change form.
- Email 2FA form.
- Passkey management UI and browser helpers for passkey registration and authentication.
- Type-safe component injection for app-owned UI controls.

Out of scope:

- App-owned Blade templates, page wrappers, Vite entrypoints, routing, and layout.
- Server-side validation, authorization, database writes, and mail delivery.
- Visual styling and accessibility details of injected app components.
- Browser, OS, password manager, and passkey provider security.

## Security objectives

- Send auth requests only to the intended app/package endpoints.
- Preserve browser WebAuthn security properties by passing challenges and credential responses without weakening them.
- Avoid owning secrets in the UI package.
- Avoid silently bypassing server-side auth validation.
- Make insecure consumer integration choices visible and documentable.

## Primary assets

- CSRF token read from app-provided endpoint config or the page meta tag.
- User-entered email, password, password confirmation, invite code, 2FA code, and custom signup fields.
- WebAuthn credential creation and assertion responses.
- Auth redirect URL returned by the server.
- Server validation errors and auth failure messages.
- Component injection surface supplied by consuming apps.

## Trust boundaries

- Browser UI to Laravel backend over HTTPS.
- App-owned page wrapper to shared React component.
- Shared React component to injected UI controls.
- Browser WebAuthn APIs to platform authenticator.
- Package tarball from GitHub release to consuming app build system.

## Entry points

React components and helpers:

- `LoginForm`
- `SignupForm`
- `PasswordResetRequestForm`
- `ResetPasswordForm`
- `ChangePasswordForm`
- `TwoFactorForm`
- `PasskeyLoginButton`
- `PasskeySection`
- `authenticateWithPasskey()`
- `registerPasskey()`
- `isConditionalMediationAvailable()`
- `getCsrfToken()`

Default backend endpoints used by components:

- `POST /login` — **app-owned** (not provided by `bherila/auth-laravel`)
- `POST /register` — **app-owned**
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`
- `POST /api/change-password`
- `POST /api/auth/two-factor/verify`
- `POST /api/auth/two-factor/resend`
- `GET /api/passkeys`
- `POST /api/passkeys/register/options`
- `POST /api/passkeys/register`
- `DELETE /api/passkeys/{id}`
- `POST /api/passkeys/auth/options`
- `POST /api/passkeys/auth`

The `/api/auth/two-factor/report/{token}` endpoint exposed by `bherila/auth-laravel` is **not** wrapped by this package — it is followed via a link in the 2FA email and rendered by an app-owned page, so its threat surface is covered by the Laravel threat model only.

## Key assumptions

- Consuming apps render these components only in trusted first-party pages.
- Consuming apps use HTTPS in production.
- Backend endpoints perform all authoritative validation and authorization.
- CSRF tokens are present in a trusted meta tag or explicitly provided through `endpoints.csrfToken`.
- Consumers do not pass attacker-controlled endpoint URLs.
- Consumers inject trustworthy UI components.
- Redirect URLs returned by the server are trusted or server-validated.

## Threats and mitigations

| Threat | Risk | Package controls | Consumer requirements |
| --- | --- | --- | --- |
| Endpoint injection | Attacker causes auth data or WebAuthn responses to be posted to an untrusted URL. | Endpoints default to same-origin package routes. The package does **not** validate consumer-supplied endpoint URLs against the current origin. | Do not build `endpoints` from untrusted input; prefer relative same-origin paths. Consider adding a same-origin assertion in app code that wires endpoints. |
| CSRF token missing or stale | Auth request fails or consumer disables CSRF to make it work. | `getCsrfToken()` reads explicit config first and then `meta[name="csrf-token"]`. | Include CSRF meta tag in app pages or pass `csrfToken` explicitly; keep server CSRF enabled. |
| XSS steals typed credentials | Malicious script reads form fields or CSRF token. | Package does not use `dangerouslySetInnerHTML`; values are bound through React state, not the DOM. | Enforce CSP (no `unsafe-inline`/`unsafe-eval`), avoid unsafe scripts, sanitize app content, audit injected components. |
| Malicious injected components | App-provided Button/Input/Label components exfiltrate auth data or break semantics. | **None at runtime.** Component injection is typed at compile time, but TypeScript types are erased — there is no runtime check that an injected component is trustworthy. The boundary is entirely a consumer responsibility. | Inject only reviewed first-party components; keep the shared injection helpers in trusted code; never accept injected components from runtime config or feature flags. |
| Open redirect after auth | Server returns attacker-controlled redirect and UI follows it. | UI follows server `redirect` value. The package does not currently restrict redirect targets to relative URLs as a UI-side defense in depth. | Server must validate redirect targets; prefer relative redirects. Consider tightening the UI to refuse non-relative redirects unless an allowlist is configured. |
| Passkey prompt confusion | Conditional UI or explicit button triggers a passkey prompt in unexpected contexts (iframes, popovers, hidden flows). | Helper functions (`authenticateWithPasskey`, `registerPasskey`) do not auto-trigger — they require explicit calls. **Note:** `LoginForm` *does* automatically start a conditional-mediation request on mount when the browser supports it, which surfaces a passkey hint in the email field's autofill UI. The form gates this on `isConditionalMediationAvailable()` and uses `AbortSignal` to cancel on unmount. | Mount `LoginForm` only on intended login pages; never embed it in iframeable or third-party-host contexts. Provide an `AbortController` or unmount path so the conditional request does not outlive the page. |
| WebAuthn ceremony tampering | UI incorrectly encodes/decodes challenge or credential bytes. | Helpers base64url-decode challenges/IDs and base64url-encode credential responses without re-encoding through any lossy intermediate. | Keep helpers updated with the backend package and test after every `web-auth/webauthn-lib` upgrade. |
| Passwordless signup partial completion | User account is created, then passkey registration is canceled. | Helper exposes errors and abort detection so apps can show recovery/continue paths. | App should explain that the account exists, provide dashboard/settings recovery, and support email password reset. |
| User enumeration through UI messages | UI reveals account existence based on backend response. | Components display server messages/errors verbatim and do not add account-existence hints of their own. | Backend should return generic forgot-password responses; UI copy should not reveal account existence; review error string changes during code review. |
| Brute force via repeated UI submissions | Attacker automates login/reset/2FA flows. | Components disable submit buttons while loading; this is a UX guard, not a security control. | Backend must rate-limit; do not rely on UI disabling. |
| Wrong autocomplete attributes confuse password managers | Password manager saves the wrong value or users disable the manager and reuse weak passwords. | Inputs set `autocomplete` hints (`current-password`, `new-password`, `email`, `one-time-code`) appropriate to each form. | Do not override `autocomplete` from app-side props; verify after refactors that the hints still reach the rendered `<input>`. |
| Token leakage via Referer | Reset/2FA links open pages that load third-party resources, leaking tokens through `Referer`. | None in this package — pages are app-owned. | Set `Referrer-Policy: no-referrer` (or stricter) on reset/2FA pages; avoid third-party scripts and resources on those pages. |
| Frontend telemetry captures secrets | Sentry/PostHog/LogRocket-style tools record password fields, 2FA codes, WebAuthn responses, or CSRF tokens. | Components do not call any logger; they only render. The package is silent on telemetry redaction. | Configure session-replay tools to mask all inputs by default and explicitly verify masking on auth pages; never log form state from app wrappers. |
| Dependency/package compromise | Consumer installs a malicious package artifact. | Package is published to npm through GitHub OIDC trusted publishing with provenance, after a verified signed release tag. | Pin an npm version or reviewed range; commit `pnpm-lock.yaml` with integrity hashes; review release commits and provenance; restrict who can create release tags. |

## Security checklist for consuming apps

- Pin `bwh-auth` to a reviewed npm version or range and commit the lockfile.
- Use same-origin relative endpoint URLs unless there is a documented reason not to.
- Provide `csrfToken` explicitly or include a trusted Laravel CSRF meta tag.
- Keep backend CSRF, auth middleware, validation, and rate limiting enabled.
- Validate all server-returned redirect URLs.
- Use app-owned wrappers for Blade pages and Vite entrypoints.
- Inject only trusted first-party UI components.
- Test passkey registration and login in supported browsers after package updates.
- Test passwordless signup cancellation and recovery copy.
- Test forgot/reset password for users with and without passwords.
- Verify CSP and dependency scanning in consuming apps.
- Avoid logging passwords, 2FA codes, WebAuthn responses, or reset tokens in frontend telemetry.

## Residual risks

- Browser XSS can compromise most browser-based auth flows, including passwords and recovery flows.
- Passkey UX depends on browser, OS, and password manager behavior outside this package.
- The UI cannot enforce server-side policy; it only submits requests and displays responses.
- Passwordless signup creates an account before passkey enrollment completes, so consumers need a clear recovery path.

## Incident response notes

- If a UI package release is compromised, pin consumers to the last known-good tarball and rebuild assets.
- If endpoint configuration leaks credentials to an unintended host, rotate affected credentials and review logs.
- If XSS is found on a page using these components, assume typed credentials and CSRF tokens may have been exposed.
- If passkey enrollment fails broadly after a release, verify frontend/base64url helpers and backend WebAuthn dependency compatibility together.
