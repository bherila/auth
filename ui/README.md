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
