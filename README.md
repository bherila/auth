# BWH Auth

Shared authentication packages for BWH Laravel/Vite applications.

This repository contains:

- `ui`: pnpm package `bwh-auth` for React auth UI and browser WebAuthn helpers.
- `php`: Composer package `bherila/auth-laravel` for Laravel OAuth clients, passkeys, auth services, migrations, routes, and extension contracts. Its manifest is the repository-root `composer.json` (required for Composer VCS resolution); the source lives under `php/`.

The packages intentionally keep app-specific policy outside the shared core. Apps decide whether a user can log in, where they go after login, and how audit events are recorded.

Laravel apps that own their primary `/login` route must wire package opt-in features into that controller. For example, enabling the audit-log-backed throttle config does not by itself enforce lockout on a custom login controller; the app must call the Laravel package's throttle trait or contract before attempting credentials. See `php/README.md`.

## UI Installation

`bwh-auth` is installed from GitHub Releases:

```sh
pnpm add https://github.com/bherila/auth/releases/download/bwh-auth-v0.2.0/bwh-auth-0.2.0.tgz
```

Each consuming app injects its own shadcn/Base UI components into `bwh-auth`.

## UI Release

From `ui/`:

```sh
pnpm release patch
```

The script builds, packs, tags, uploads the release asset with `gh`, and prints
the tarball URL to use in consumers.

## Repositories

This auth repository is separate from the `bwh-ui` repository under `/Users/bwh/proj/ui`.
