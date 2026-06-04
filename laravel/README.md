# bherila/auth-laravel

Shared Laravel auth package for BWH applications.

Includes:

- WebAuthn/passkey registration and login
- email-code 2FA challenge service, API routes, and mailables
- password reset request/reset/change API routes and mailables
- passkey and 2FA database tables
- login audit logging: an owned `auth_audit_log` table, a default database logger, binary IP storage, optional read endpoints, and opt-in retention (see "Login audit logging")
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

When `audit.routes_enabled` is true (off by default), it also registers `GET /api/auth/audit-log`, `POST /api/auth/audit-log/{id}/suspicious`, and `GET /api/auth/audit-log/all`. See "Login audit logging".

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

Bind `BWH\Auth\Contracts\AuthAuditLogger` only when an app wants to override the built-in audit behavior (for example, to mirror events into its own broader audit table). Most apps should instead use the database driver described below.

## Login audit logging

The package can own a single append-only audit log for authentication events, so consuming apps no longer hand-roll their own login-audit table and writer.

### Enable it

```sh
php artisan vendor:publish --tag=bherila-auth-config
php artisan vendor:publish --tag=bherila-auth-migrations
php artisan migrate
```

Then set the driver in `.env`:

```
BHERILA_AUTH_AUDIT_DRIVER=database
```

The driver defaults to `null` (a no-op `NullAuthAuditLogger`), so an app that has not published/run the migration is unaffected and never hits a missing table. Setting it to `database` binds `DatabaseAuthAuditLogger`, which writes one row per event into the `bherila-auth.audit.table` table (default `auth_audit_log`).

### What gets recorded

The package's own controllers/services already report passkey, 2FA, and password reset/change events. For **primary password login and logout**, the package does not own the login controller, so the app calls the contract from its own login flow. Use the `LogsAuthEvents` trait:

```php
use BWH\Auth\Concerns\LogsAuthEvents;

class LoginController
{
    use LogsAuthEvents;

    public function login(Request $request)
    {
        // ... resolve $user, attempt credentials ...
        if (! $ok) {
            $this->auditLoginFailed($request, $user, $request->input('email'), 'Invalid credentials');
            // ...
        }

        $this->auditLoginSucceeded($request, $user); // method defaults to 'password'
    }

    public function logout(Request $request)
    {
        $this->auditLoggedOut($request, $request->user());
        // ...
    }
}
```

`auth_method` is a free-form string (e.g. `password`, `passkey`, `two_factor`, `dev`). Failed logins for unknown emails are recorded with a null `user_id` and the attempted `email`.

### Schema

`auth_audit_log` columns: `id`, `user_id` (nullable), `acting_user_id` (nullable), `email`, `event`, `auth_method`, `succeeded`, `reason`, `ip_address` (`varbinary(16)` on MySQL / `blob` on SQLite, via `BWH\Auth\Casts\BinaryIpAddressCast`), `user_agent`, `session_id`, `is_suspicious`, `metadata` (json), timestamps. Event-name constants live on `BWH\Auth\Models\AuthAuditLog` (`EVENT_LOGIN_SUCCEEDED`, etc.). The client IP is resolved via `BWH\Auth\Support\ClientIp`, which uses Laravel's `Request::ip()` — so it only honours `X-Forwarded-*` headers from configured trusted proxies. **Apps behind Cloudflare or a load balancer must configure Laravel's TrustProxies** (in `bootstrap/app.php`) so the real client IP is recorded; otherwise forwarded headers are ignored to prevent audit-log IP spoofing.

### Read endpoints (optional)

Set `BHERILA_AUTH_AUDIT_ROUTES=true` to register read endpoints (the package ships no UI; render your own and call these or query `AuthAuditLog`):

- `GET /api/auth/audit-log` — the authenticated user's own history (paginated)
- `POST /api/auth/audit-log/{id}/suspicious` — flag/unflag one of the user's own entries
- `GET /api/auth/audit-log/all` — cross-user admin list, gated by the `bherila-auth.audit.admin_ability` Gate ability (route returns 403 unless that ability is configured and allowed)

### Retention

Retention is **off by default** (`bherila-auth.audit.retention_days = null`), so nothing is ever pruned. To enable pruning, set `BHERILA_AUTH_AUDIT_RETENTION_DAYS` and schedule Laravel's prune command:

```php
// bootstrap/app.php or a scheduler
Schedule::command('model:prune', ['--model' => [\BWH\Auth\Models\AuthAuditLog::class]])->daily();
```

> **Since 0.2.0.** The audit-log table, default database logger, `BinaryIpAddressCast`, `ClientIp`, the `LogsAuthEvents` trait, read endpoints, retention, and the `loginSucceeded`/`loginFailed`/`loggedOut` contract methods were added in 0.2.0. The contract gained methods; implementations should extend `BWH\Auth\Services\AbstractAuthAuditLogger` (which provides no-op defaults) rather than implementing the interface directly.
