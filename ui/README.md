# bwh-auth

Shared React auth components for BWH applications.

This package owns auth-specific UI and browser helpers. Generic primitives come from `bwh-ui`.

## Components

- `LoginForm`
- `SignupForm`
- `PasswordResetRequestForm`
- `ResetPasswordForm`
- `PasskeyLoginButton`
- `PasskeySection`

## Endpoint Defaults

Passkey components default to the Laravel package routes:

- `GET /api/passkeys`
- `POST /api/passkeys/register/options`
- `POST /api/passkeys/register`
- `DELETE /api/passkeys/:id`
- `POST /api/passkeys/auth/options`
- `POST /api/passkeys/auth`
