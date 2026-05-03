# bherila/auth-laravel

Shared Laravel auth package for BWH applications.

Includes:

- WebAuthn/passkey registration and login
- email-code 2FA challenge service, API routes, and mailables
- password reset request/reset API routes and mailables
- passkey and 2FA database tables
- policy and audit contracts for app-specific behavior

## Install

```sh
composer require bherila/auth-laravel
php artisan vendor:publish --tag=bherila-auth-config
php artisan vendor:publish --tag=bherila-auth-migrations
php artisan migrate
```

Publish mail views only if the consuming app wants to customize the package email templates:

```sh
php artisan vendor:publish --tag=bherila-auth-views
```

If installing from GitHub before Packagist publication, add the repository to the consuming app:

```json
{
  "repositories": [
    {
      "type": "vcs",
      "url": "https://github.com/bherila/auth"
    }
  ]
}
```

Then run `composer require bherila/auth-laravel:*`. Composer reads the repository-root `composer.json`, which autoloads the Laravel package from `laravel/src`.

## Configuration

Published config lives at `config/bherila-auth.php`. Important settings:

- `routes.prefix`: defaults to `api`, so package endpoints are under `/api/...`.
- `routes.middleware`: defaults to `['web']` so session auth and CSRF work in Laravel/Vite apps.
- `password_resets.reset_url`: reset-page URL generated into password reset emails. Defaults to `{APP_URL}/reset-password/{token}?email={email}`.
- `password_resets.redirect_after_reset`: JSON redirect returned after a successful reset.
- `two_factor.expires_minutes`: 2FA code expiry. Defaults to 15 minutes.
- `two_factor.allow_test_code`: allows the configured test code outside production.
- `migrations.drop_tables_on_rollback`: defaults to `false` so package rollbacks do not drop existing app auth tables.

The package migration uses `Schema::hasTable()` before creating its tables. This lets existing apps such as bwh-php keep an already-created passkey table without migration failure. It does not alter existing tables, so apps with older or different schemas should either point the package config at compatible tables or add an app-local migration for schema reconciliation. Rollback table drops are disabled by default to avoid deleting pre-existing auth data.

## API routes

With the default prefix, the package registers:

- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`
- `POST /api/auth/two-factor/verify`
- `POST /api/auth/two-factor/resend`
- `GET /api/auth/two-factor/confirm/{token}`
- `GET|POST /api/auth/two-factor/report/{token}`
- `GET /api/passkeys`
- `POST /api/passkeys/register/options`
- `POST /api/passkeys/register`
- `DELETE /api/passkeys/{id}`
- `POST /api/passkeys/auth/options`
- `POST /api/passkeys/auth`

## Password reset integration

The package owns the JSON API endpoints and mailables. The consuming app owns the pages.

Create pages such as `/forgot-password` and `/reset-password/{token}` and mount the shared `bwh-auth` UI components from `auth/ui`:

```tsx
import { PasswordResetRequestForm, ResetPasswordForm } from 'bwh-auth';
import { getAuthComponents } from '@/lib/auth-components';

export function ForgotPasswordPage() {
  return <PasswordResetRequestForm components={getAuthComponents()} />;
}

export function ResetPasswordPage({ token, email }: { token: string; email: string }) {
  return <ResetPasswordForm components={getAuthComponents()} token={token} email={email} />;
}
```

The reset email uses `password_resets.reset_url`. Set `BHERILA_AUTH_PASSWORD_RESET_URL` when the app uses a different route shape.

## Email 2FA integration

The package intentionally does not own password credential login because each app has different user approval, lockout, and onboarding rules. After the consuming app verifies email/password and decides the user may proceed, start a package 2FA challenge instead of logging in immediately:

```php
use BWH\Auth\Services\TwoFactorService;

$attempt = app(TwoFactorService::class)->startChallenge(
    $user,
    $request,
    $request->boolean('remember'),
);

return response()->json([
    'success' => true,
    'requires_2fa' => true,
    'attempt_token' => $attempt->token,
    'message' => 'A verification code has been sent to your email address.',
]);
```

The consuming app also owns the 2FA page wrapper, for example `/login/two-factor/{token}`:

```tsx
import { TwoFactorForm } from 'bwh-auth';
import { getAuthComponents } from '@/lib/auth-components';

export function TwoFactorPage({ token }: { token: string }) {
  return <TwoFactorForm components={getAuthComponents()} attemptToken={token} />;
}
```

`TwoFactorForm` posts to `/api/auth/two-factor/verify`, can resend via `/api/auth/two-factor/resend`, and can report suspicious attempts via `POST /api/auth/two-factor/report/{token}`. The same report route also accepts `GET` so the email report link works.

## Mailables

Included mailables:

- `BWH\Auth\Mail\TwoFactorLoginMail`
- `BWH\Auth\Mail\PasswordResetMail`
- `BWH\Auth\Mail\PasswordResetNoticeMail`

Views are loaded from the `bherila-auth::emails.*` namespace and can be overridden by publishing Laravel views if needed.

## App Integration

Bind `BWH\Auth\Contracts\AuthUserPolicy` when an app needs custom login gates or redirects.

Bind `BWH\Auth\Contracts\AuthAuditLogger` when an app wants package auth events mirrored into its own audit tables.
