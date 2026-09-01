# Changelog

Notable changes per release. Versions follow the tags published to
[Packagist](https://packagist.org/packages/bherila/auth-laravel); anything older than
the first entry here is in the git history.

## Unreleased (v0.10.0)

Breaking: this release drops PHP 8.3 and Laravel 12. For a pre-1.0 package `^0.9`
resolves as `>=0.9.0 <0.10.0`, so shipping a platform drop as 0.9.x would upgrade
consumers into a package their runtime cannot load. Consumers move to `^0.10`
together with PHP 8.4+ and Laravel 13.

### Requirements

- **Requires PHP 8.4+ and Laravel 13.** Earlier releases advertised PHP 8.2 and
  Laravel 12 or 13, but `OAuthClient` used typed class constants (PHP 8.3+) and CI
  installed a single PHP 8.5 / Laravel 12 combination, so neither claim was true or
  tested. CI now runs the floor, the newest runtime, and `--prefer-lowest`.
- `web-auth/webauthn-lib` floor raised to `^5.3.5`, excluding the origin-validation
  advisory affecting 5.2.0–5.2.3 and the advisory fixed in 5.3.5. CI runs
  `composer audit`.

### Security

- `canLogin()` is rechecked immediately before `Auth::login()` on 2FA completion and
  before the post-reset auto-login, so an account disabled after a challenge was
  issued — or one that completes a password reset — no longer receives a session. The
  2FA attempt is consumed either way.
- `/api/change-password` and the authenticated passkey routes carry `RequireActiveUser`
  alongside `auth`.
- The fixed 2FA test code is off by default and now requires all three of: the setting,
  an allowed environment (`two_factor.test_code_environments`), and an `is_test`
  account. Previously either the setting or an `is_test` account sufficed, and the
  setting defaulted to on in every environment except `APP_ENV=production`.
- `POST /api/auth/forgot-password` goes through `PasswordBroker::sendResetLink()`,
  restoring the broker's recently-created-token throttle and timebox, which calling
  `createToken()` directly had bypassed.
- `POST /api/auth/two-factor/resend` refuses an expired attempt, which could previously
  mint a fresh code and expiry for itself indefinitely.
- `ClientIp::resolve()` returns null for an address that will not pack, instead of
  handing back a value that packs to null on write and reads as `ip_address IS NULL` in
  a throttle lookup — counting the failures of every request whose IP was unknown.

### Fixed

- Package config defaults are merged into a published `config/bherila-auth.php` key by
  key. A published config that predates a release no longer erases the nested defaults
  added since, which had left later keys reading as null.
- The `rp_id` migration targets `auth_passkeys` (it fell back to `webauthn_credentials`,
  a name nothing else uses) and skips cleanly when the table is missing or the column
  already exists.
- The package dispatches Laravel's `PasswordResetLinkSent` and `PasswordReset` events.
