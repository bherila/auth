# bherila/auth-laravel

Shared Laravel auth package for BWH applications.

Initial scope:

- WebAuthn/passkey registration and login
- passkey credential model and migration
- route/controller defaults for session-backed Laravel apps
- app-specific policy and audit contracts

Future scope:

- shared password reset mailables
- login audit helpers
- email or SMS two-factor challenges
- Twilio-backed verification

## Install

```sh
composer require bherila/auth-laravel
php artisan vendor:publish --tag=bherila-auth-config
php artisan vendor:publish --tag=bherila-auth-migrations
php artisan migrate
```

## App Integration

Bind `Bherila\AuthLaravel\Contracts\AuthUserPolicy` when an app needs custom login gates or redirects.

Bind `Bherila\AuthLaravel\Contracts\AuthAuditLogger` when an app wants package auth events mirrored into its own audit tables.
