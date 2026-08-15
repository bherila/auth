# BWH Auth

Shared authentication packages for BWH Laravel/Vite applications.

This repository contains:

- `ui`: pnpm package `bwh-auth` for React auth UI and browser WebAuthn helpers.
- `php`: Composer package `bherila/auth-laravel` for Laravel OAuth clients, passkeys, auth services, migrations, routes, and extension contracts. Its manifest is the repository-root `composer.json`; the source lives under `php/`.

The packages intentionally keep app-specific policy outside the shared core. Apps decide whether a user can log in, where they go after login, and how audit events are recorded.

Laravel apps that own their primary `/login` route must wire package opt-in features into that controller. For example, enabling the audit-log-backed throttle config does not by itself enforce lockout on a custom login controller; the app must call the Laravel package's throttle trait or contract before attempting credentials. See `php/README.md`.

## UI Installation

`bwh-auth` is published on npm:

```sh
pnpm add bwh-auth
```

Each consuming app injects its own shadcn/Base UI components into `bwh-auth`.

## Laravel Installation

`bherila/auth-laravel` is published on Packagist:

```sh
composer require bherila/auth-laravel
```

Consumers do not need a Composer VCS repository entry or a GitHub URI.

## Releases

The packages version independently:

- `bwh-auth-v*` tags publish `bwh-auth` to npm and create a GitHub Release.
- `v*` tags update `bherila/auth-laravel` on Packagist.
- Release tags must be annotated and signed; publication stops unless GitHub verifies the signature.

To prepare a UI release, run from `ui/`:

```sh
pnpm release patch
```

The script builds, packs, commits, and pushes the signed release tag. GitHub
Actions publishes the package to npm and attaches the tarball to a GitHub Release.

## Repositories

This auth repository is separate from the `bwh-ui` repository under `/Users/bwh/proj/ui`.
