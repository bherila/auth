# bherila/auth-laravel

Shared Laravel auth package for BWH applications.

Includes:

- WebAuthn/passkey registration and login
- email-code 2FA challenge service, API routes, and mailables
- password reset request/reset/change API routes and mailables
- passkey and 2FA database tables
- policy and audit contracts for app-specific behavior

## Install

```sh
composer require bherila/auth-laravel
php artisan vendor:publish --tag=bherila-auth-config
php artisan vendor:publish --tag=bherila-auth-migrations
php artisan migrate
```

Routes are auto-registered by `BWH\\Auth\\AuthServiceProvider`; consuming apps should not copy or publish package route files. Publishable assets are limited to config, migrations, and optional mail views.

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

Then run `composer require bherila/auth-laravel:dev-main`. Composer reads the repository-root `composer.json`, which autoloads the Laravel package from `laravel/src`.

## Configuration

Published config lives at `config/bherila-auth.php`. Important settings:

- `routes.prefix`: defaults to `api`, so package endpoints are under `/api/...`.
- `routes.middleware`: defaults to `['web']` so session auth and CSRF work in Laravel/Vite apps.
- `routes.passkeys`, `routes.password_resets`, `routes.change_password`, and `routes.two_factor`: enable or disable route families independently when an app owns one part of the auth surface locally.
- `password_resets.reset_url`: reset-page URL generated into password reset emails. Defaults to `{APP_URL}/reset-password/{token}?email={email}`.
- `password_resets.verify_email_on_reset`: optionally marks verified-email users verified after a successful reset.
- `password_resets.redirect_after_reset`: JSON redirect returned after a successful reset.
- `BHERILA_AUTH_PASSWORD_RESET_MAIL_SUBJECT`: optional reset-link mailable subject override.
- `BHERILA_AUTH_PASSWORD_NOTICE_MAIL_SUBJECT`: optional password reset/change notice subject override.
- `two_factor.expires_minutes`: 2FA code expiry. Defaults to 15 minutes.
- `two_factor.allow_test_code`: allows the configured test code outside production.
- `BHERILA_AUTH_TWO_FACTOR_MAIL_SUBJECT`: optional email 2FA subject override.
- `passkeys.user_verification`: WebAuthn user verification requirement. Defaults to `preferred`; set to `required` for passkeys used as a stronger security factor.
- `passkeys.resident_key`: WebAuthn resident key requirement. Defaults to `preferred`.
- `users.force_change_password_attribute`: optional boolean column to clear after password reset/change, such as `force_change_pw`.
- `migrations.drop_tables_on_rollback`: defaults to `false` so package rollbacks do not drop existing app auth tables.

The package migration uses `Schema::hasTable()` before creating its tables. This lets existing apps such as bwh-php keep an already-created passkey table without migration failure. It does not alter existing tables, so apps with older or different schemas should either point the package config at compatible tables or add an app-local migration for schema reconciliation. Rollback table drops are disabled by default to avoid deleting pre-existing auth data.

## API routes

With the default prefix, the package registers:

- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`
- `POST /api/change-password`
- `POST /api/auth/two-factor/verify`
- `POST /api/auth/two-factor/resend`
- `GET /api/auth/two-factor/confirm/{token}`
- `POST /api/auth/two-factor/confirm/{token}`
- `GET /api/auth/two-factor/report/{token}`
- `POST /api/auth/two-factor/report/{token}`
- `GET /api/passkeys`
- `POST /api/passkeys/register/options`
- `POST /api/passkeys/register`
- `DELETE /api/passkeys/{id}`
- `POST /api/passkeys/auth/options`
- `POST /api/passkeys/auth`

## Ownership boundary

This package owns Laravel services, API routes, database migrations, controllers, and auth mailables. It intentionally does not ship application page Blade wrappers or Vite entrypoints. Each consuming app should create its own Blade pages and Vite entrypoints, then mount the shared `bwh-auth` React components where useful.

The package does include Markdown Blade templates for its mailables under `bherila-auth::emails.*`. Those are email templates, not page wrappers, and can be published/overridden with `php artisan vendor:publish --tag=bherila-auth-views`.

## Password reset integration

The package owns the JSON API endpoints and mailables. The consuming app owns the pages, including Blade wrappers and Vite entrypoints.

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

## Authenticated password change

The package registers `POST /api/change-password` behind `auth` middleware. It expects `current_password`, `password`, and `password_confirmation`, updates the authenticated user's password, sends `PasswordResetNoticeMail`, and returns JSON suitable for `bwh-auth`'s `ChangePasswordForm`.

The consuming app owns where this appears, such as an account settings page or dialog.

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

The consuming app also owns the 2FA page wrapper and Vite entrypoint, for example `/login/two-factor/{token}`:

```tsx
import { TwoFactorForm } from 'bwh-auth';
import { getAuthComponents } from '@/lib/auth-components';

export function TwoFactorPage({ token }: { token: string }) {
  return <TwoFactorForm components={getAuthComponents()} attemptToken={token} />;
}
```

`TwoFactorForm` posts to `/api/auth/two-factor/verify`, can resend via `/api/auth/two-factor/resend`, and can report suspicious attempts via `POST /api/auth/two-factor/report/{token}`.

Email confirmation and report links are side-effect-free `GET` pages. The user must submit a CSRF-protected `POST` to complete login or report suspicious activity, which prevents common email security scanners from consuming one-shot login links.

## Mailables

Included mailables for password reset, password reset/change notices, and email 2FA:

- `BWH\Auth\Mail\TwoFactorLoginMail`
- `BWH\Auth\Mail\PasswordResetMail`
- `BWH\Auth\Mail\PasswordResetNoticeMail`

Views are loaded from the `bherila-auth::emails.*` namespace and can be overridden by publishing Laravel views if needed.

## App Integration

Bind `BWH\Auth\Contracts\AuthUserPolicy` when an app needs custom login gates or redirects.

Bind `BWH\Auth\Contracts\AuthAuditLogger` when an app wants package auth events mirrored into its own audit tables.
