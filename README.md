# BWH Auth

Shared authentication packages for BWH Laravel/Vite applications.

This repository contains:

- `ui`: npm package `bwh-auth` for React auth UI and browser WebAuthn helpers.
- `laravel`: Composer package `bherila/auth-laravel` for Laravel auth services, passkeys, migrations, routes, and extension contracts.

The packages intentionally keep app-specific policy outside the shared core. Apps decide whether a user can log in, where they go after login, and how audit events are recorded.

## Repositories

This auth repository is separate from the `bwh-ui` repository under `/Users/bwh/proj/ui`.
