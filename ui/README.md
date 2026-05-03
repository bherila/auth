# bwh-auth

Shared headless React auth components for BWH applications.

This package owns auth-specific behavior and browser helpers. It does not import
or bundle a UI kit. Consumers must inject their own UI components.

## Components

- `LoginForm`
- `SignupForm`
- `PasswordResetRequestForm`
- `ResetPasswordForm`
- `PasskeyLoginButton`
- `PasskeySection`

## Install

`bwh-auth` is distributed from GitHub Releases as a packed npm tarball.

```sh
pnpm add https://github.com/bherila/auth/releases/download/bwh-auth-v0.1.1/bwh-auth-0.1.1.tgz
```

Or pin it manually in `package.json`:

```json
{
  "dependencies": {
    "bwh-auth": "https://github.com/bherila/auth/releases/download/bwh-auth-v0.1.1/bwh-auth-0.1.1.tgz"
  }
}
```

Install peer dependencies in the consuming app:

```sh
pnpm add @base-ui/react lucide-react react react-dom
```

React and React DOM are usually already present in Laravel/Vite apps.

## Component Injection

Higher-level components require injected components so each app can use its own
shadcn/Base UI components and Vite can tree-shake cleanly.

```tsx
import { LoginForm, type AuthComponentInput } from "bwh-auth"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export function getShadcnComponents() {
  return {
    Button,
    Card,
    CardContent,
    CardDescription: ({ ...props }) => <div {...props} />,
    CardHeader,
    CardTitle,
    Input,
    Label,
    // Extra keys are allowed so this helper can be shared across features.
    Textarea,
    Dialog,
  } satisfies AuthComponentInput
}

export function LoginPage() {
  return <LoginForm components={getShadcnComponents()} />
}
```

## Endpoint Defaults

Passkey components default to the Laravel package routes:

- `GET /api/passkeys`
- `POST /api/passkeys/register/options`
- `POST /api/passkeys/register`
- `DELETE /api/passkeys/:id`
- `POST /api/passkeys/auth/options`
- `POST /api/passkeys/auth`

## Releasing

Create and upload a GitHub release from this package directory:

```sh
pnpm release
```

The release script:

- requires a clean git working tree
- bumps `ui/package.json` version, defaulting to `patch`
- runs `pnpm install --lockfile-only`
- runs typecheck and build
- creates `ui/release/bwh-auth-VERSION.tgz`
- commits the version bump
- creates and pushes a tag like `bwh-auth-v0.1.1`
- creates a GitHub release with the tarball asset
- prints the install URL

Version bump options:

```sh
pnpm release patch
pnpm release minor
pnpm release major
pnpm release --version=0.2.0
pnpm release --dry-run
```
