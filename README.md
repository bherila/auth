# bherila/auth-laravel

Shared Laravel auth package for BWH applications.

The companion React component package is
[`bwh-auth`](https://github.com/bherila/auth-react).

Includes:

- OAuth 2.0 authorization-code client mechanics with PKCE and validated identity responses
- opt-in Passport authorization-server helpers for metadata, dynamic public-client registration,
  S256 PKCE, RFC 8707 resource binding, and a shared consent experience
- WebAuthn/passkey registration and login
- email-code 2FA challenge service, API routes, and mailables
- password reset request/reset/change API routes and mailables
- passkey and 2FA database tables
- login audit logging: an owned `auth_audit_log` table, a default database logger, binary IP storage, optional read endpoints, and opt-in retention (see "Login audit logging")
- policy and audit contracts for app-specific behavior

## Upgrading to v0.5.0 (breaking)

This release adds a required method to the `AuthUserPolicy` contract:

```php
public function canLogin(Authenticatable $user, Request $request): bool;
```

It is the single gate for account-state checks (active, approved, not disabled)
and is now enforced by the new `RequireActiveUser` middleware on the package's
audit routes, so a role-only admin gate can no longer let a pending or disabled
account through.

Because the contract gained a required method, this is a **breaking change** and
must be released as **v0.5.0** (not a 0.4.x patch) so consumers opt in. Consuming
apps that **implement `AuthUserPolicy` directly** must add `canLogin()` when they
upgrade — typically delegating to their model:

```php
public function canLogin(Authenticatable $user, Request $request): bool
{
    return $user instanceof User && $user->canLogin() && $user->hasVerifiedEmail();
}
```

Apps that extend `DefaultAuthUserPolicy` inherit a working `canLogin()` (it
duck-types `$user->canLogin()`, falls back to `is_disabled`, defaults to `true`)
and need no change.

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

Consumers install from Packagist and should not add a GitHub VCS repository entry.
For unreleased local package development only, use a Composer path repository:

```json
{
  "repositories": [
    {
      "type": "path",
      "url": "../auth-laravel",
      "options": { "symlink": true }
    }
  ]
}
```

Then run `composer require bherila/auth-laravel:@dev`. Composer reads the
repository-root `composer.json` and autoloads the package from `src`. Remove the
path override before validating a published release.

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
- `throttle.enabled`: enables audit-log-backed password-login lockout. Defaults to `false`.
- `throttle.max_attempts`: failed attempts allowed for the same key before lockout. Defaults to `5`.
- `throttle.decay_minutes`: lockout/window length. Defaults to `15`.
- `throttle.key`: how failed attempts are grouped — `email` (per account, across all IPs), `ip` (per source, across all accounts), or `email_ip` (per account+source pair). Defaults to `email_ip`; any unrecognized value falls back to `email_ip`.
- `users.force_change_password_attribute`: optional boolean column to clear after password reset/change, such as `force_change_pw`.
- `migrations.drop_tables_on_rollback`: defaults to `false` so package rollbacks do not drop existing app auth tables.

Enabling `throttle.enabled` only changes the package service behavior. Apps that use their own password-login controller must still call `ThrottlesLoginAttempts` or the `LoginThrottle` contract from that controller before attempting credentials. Publishing the config alone does not intercept custom `/login` routes.

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

Create pages such as `/forgot-password` and `/reset-password/{token}` and mount
the shared `bwh-auth` components from the companion `auth-react` repository:

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

### OAuth authorization-server integration

Applications exposing a Passport-protected API can reuse the package's server-side
protocol and consent UX without enabling any routes automatically. Configure
`bherila-auth.oauth_server`, then point application-owned routes and middleware at:

- `BWH\Auth\Http\Controllers\OAuthMetadataController`
- `BWH\Auth\Http\Controllers\OAuthDynamicClientRegistrationController`
- `BWH\Auth\Http\Middleware\EnforceOAuthPkce`
- `BWH\Auth\Http\Middleware\EnforceOAuthResourceIndicator`
- `bherila-auth::oauth.authorize`

The application remains responsible for its scope catalog, Passport token repository
bindings, authorization policy, throttling, MCP tool catalog, and MCP instructions.
Dynamic registration also deliberately does not alter Passport's application-owned
schema. Before exposing the registration route, add an app migration for every column
listed in `oauth_server.dynamic_clients.required_columns`; the default configuration
expects a nullable, indexed `dynamically_registered_at` timestamp. Add the optional
last-used and scopes columns only when the corresponding configuration enables them.
If a custom scopes column is used, the configured Passport client model must cast it
to an array (or store a JSON/string list the middleware can normalize).
The controller returns `503 temporarily_unavailable` until all configured columns are
present, so a missing migration fails closed.

Unknown dynamic-registration metadata is ignored as required by RFC 7591, while the
fields used to create a public client are bounded and validated. Redirect URIs must
use HTTPS or loopback HTTP, authorization requests require S256 PKCE, and a configured
resource-required scope cannot be authorized without the matching resource indicator.

The shared consent view uses `oauth_server.consent` copy and labels so applications can
retain domain-specific language without copying security-sensitive forms or styling.
It warns when a client registered dynamically and shows the validated return URI.

### OAuth client integration

`BWH\Auth\OAuth\OAuthClient` owns state and PKCE generation, authorization redirects,
authorization-code exchange, and validation of the provider identity response. The consuming
application still owns local-user lookup/provisioning, account-state policy, login, auditing,
and the post-login destination.

Configure `OAUTH_PROVIDER`, `OAUTH_PROVIDER_URL`, `OAUTH_CLIENT_ID`,
`OAUTH_CLIENT_SECRET`, and `OAUTH_REDIRECT_URI`, then delegate from the app controller:

```php
public function redirect(Request $request, OAuthClient $oauth): RedirectResponse
{
    return $oauth->redirect($request);
}

public function callback(Request $request, OAuthClient $oauth): RedirectResponse
{
    $identity = $oauth->identityFromCallback($request);
    $user = $this->resolveLocalUser($identity);

    Auth::login($user);
    $request->session()->regenerate();

    return redirect()->intended('/');
}
```

The package deliberately does not match or bind users by email. That decision is
application-specific and must not silently replace a trusted provider-subject binding.

Bind `BWH\Auth\Contracts\AuthUserPolicy` when an app needs custom login gates or redirects.

Bind `BWH\Auth\Contracts\AuthAuditLogger` only when an app wants to override the built-in audit behavior (for example, to mirror events into its own broader audit table). Most apps should instead use the database driver described below.

### canLogin() — the single gate for account state

`AuthUserPolicy::canLogin()` is the **single source of truth** for "is this account allowed to proceed through any login flow." The default implementation duck-types `$user->canLogin()` and falls back to checking `$user->is_disabled`. Apps with additional account-state columns (e.g. `approved_at`, `email_verified_at`, or a role whitelist) must bind a custom policy and encode **all** conditions in `canLogin()`:

```php
// app/Auth/AppUserPolicy.php
class AppUserPolicy extends DefaultAuthUserPolicy
{
    public function canLogin(Authenticatable $user, Request $request): bool
    {
        return $user->approved_at !== null
            && ! $user->is_disabled;
    }
}

// AppServiceProvider::register()
$this->app->bind(AuthUserPolicy::class, AppUserPolicy::class);
```

The package calls `canLogin()` automatically from:

- `RequireActiveUser` middleware, applied to all package audit-log routes
- `canPasskeyLogin()` in the default policy (passkey auth delegates here)
- The 2FA `completeLogin()` path delegates through `redirectAfterLogin()`; if the user should be
  blocked at that point, `canLogin()` must return false so the redirect sends them away from the app

Apps must also call `canLogin()` from their own:

1. **Primary password-login controller** — before `Auth::attempt()` or after resolving the user.
2. **Email-verification callback** — after marking the email verified, call `canLogin()` and use
   `redirectAfterLogin()` (not a hardcoded path) so a just-verified but still-pending user goes to
   the pending page rather than into the app. Hardcoding `/pending` in the verification handler
   causes approved users who verified their email to be falsely shown the pending page.

### Protecting admin gates against pending/disabled accounts

When setting `audit.admin_ability`, the Gate ability definition must verify **both** admin role and active-account state. The package applies `RequireActiveUser` on top, but your Gate definition should be correct independently (it may be called from other locations):

```php
// AppServiceProvider::boot()
Gate::define('admin-only', function (User $user) {
    // WRONG: only checks role — a pending admin bypasses account-state checks
    // return $user->is_admin;

    // CORRECT: role AND account state
    return $user->is_admin
        && $user->approved_at !== null
        && ! $user->is_disabled;
});
```

### Backfilling approved_at after adding an approval column

If you add an `approved_at` (nullable, null = pending) column to your existing `users` table, every pre-existing row will be null after migration, instantly locking out all current users — including the primary admin. Before deploying the migration to production, add a backfill step in your migration (or a separate migration) to grandfather existing rows:

```php
// In your migration's up() method, after adding the column:
DB::table('users')
    ->whereNull('approved_at')
    ->update(['approved_at' => now()]);
```

Alternatively, make null mean "approved" and use a different sentinel (e.g. a `pending` boolean), but document the convention clearly.

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

Retention is **off by default** (`bherila-auth.audit.retention_days = null`), so nothing is ever pruned. To enable pruning, set `BHERILA_AUTH_AUDIT_RETENTION_DAYS` and run the artisan command:

```bash
php artisan bherila-auth:prune-audit-log
```

The command deletes all rows older than `bherila-auth.audit.retention_days` and prints the count of removed rows. It is a no-op when `retention_days` is `null`.

To run it automatically, add it to your application's scheduler (optional):

```php
// bootstrap/app.php or a scheduler
$schedule->command('bherila-auth:prune-audit-log')->daily();
```

You can also continue to use Laravel's built-in prune infrastructure if you prefer:

```php
Schedule::command('model:prune', ['--model' => [\BWH\Auth\Models\AuthAuditLog::class]])->daily();
```

> **Since 0.4.2.** The `bherila-auth:prune-audit-log` artisan command was added in 0.4.2.

> **Since 0.2.0.** The audit-log table, default database logger, `BinaryIpAddressCast`, `ClientIp`, the `LogsAuthEvents` trait, read endpoints, retention, and the `loginSucceeded`/`loginFailed`/`loggedOut` contract methods were added in 0.2.0. The contract gained methods; implementations should extend `BWH\Auth\Services\AbstractAuthAuditLogger` (which provides no-op defaults) rather than implementing the interface directly.

## Login throttling

The package can also enforce a password-login lockout using the same append-only `auth_audit_log` table. It is **off by default** and has no effect until a consuming app enables it and calls the service from its own password-login controller:

```
BHERILA_AUTH_AUDIT_DRIVER=database
BHERILA_AUTH_THROTTLE_ENABLED=true
BHERILA_AUTH_THROTTLE_MAX_ATTEMPTS=5
BHERILA_AUTH_THROTTLE_DECAY_MINUTES=15
# email | ip | email_ip (default)
BHERILA_AUTH_THROTTLE_KEY=email_ip
```

This package does not wrap arbitrary app `/login` routes. If the app disables package auth routes or owns primary login locally, the local login controller is responsible for inspecting the throttle before `Auth::attempt()` and recording blocked attempts.

Use `BWH\Auth\Concerns\ThrottlesLoginAttempts` alongside `LogsAuthEvents`:

```php
use BWH\Auth\Concerns\LogsAuthEvents;
use BWH\Auth\Concerns\ThrottlesLoginAttempts;

class LoginController
{
    use LogsAuthEvents;
    use ThrottlesLoginAttempts;

    public function login(Request $request)
    {
        $email = $request->input('email');
        $state = $this->inspectLoginThrottle($request, null, $email);

        if ($state->locked) {
            $this->auditLoginBlocked($request, null, $email, 'password', $state);

            return response()->json([
                'message' => 'Too many login attempts.',
                'retry_after' => $state->availableInSeconds(),
            ], 429);
        }

        // ... attempt credentials ...
        if (! $ok) {
            $this->auditLoginFailed($request, $user, $email, 'Invalid credentials');
            // ...
        }

        $this->auditLoginSucceeded($request, $user);
    }
}
```

The throttle counts recent `login_failed` rows matching the auth method and the configured `throttle.key`: the normalized email (`email`), the resolved client IP (`ip`), or both (`email_ip`, the default). Second-factor failures (`two_factor_failed`) are excluded by event, so a wrong 2FA code never counts toward credential lockout. A later `login_succeeded` row for the same key resets the count. Blocked requests can be recorded as `login_blocked` rows via `auditLoginBlocked()`, but those rows do not extend the lockout window.

Pick the key strategy to match your threat model: `email` mitigates per-account credential stuffing but lets an attacker lock a victim out by spamming failures for their address; `ip` bounds a single noisy source but can affect users behind a shared NAT/CGNAT egress; `email_ip` (default) is the most conservative and only locks a specific account+source pair.

Because throttling is audit-log-backed, apps must enable the database audit driver, run the package audit migration, record failed/successful primary login events, and configure Laravel trusted proxies correctly.
