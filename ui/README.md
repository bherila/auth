# bwh-auth

Shared headless React auth components for BWH applications.

This package owns auth-specific React behavior and browser helpers. It does not import
or bundle a UI kit, Blade page wrappers, or application Vite entrypoints. Consumers must inject their own UI components and mount these components from app-owned pages/entrypoints.

## Ownership boundary

`bwh-auth` exports React components only. Laravel apps should keep their own Blade files such as `resources/views/auth/login.blade.php` and Vite entrypoints such as `resources/js/auth/login.tsx`; those app files import and mount these shared components.

## Components

- `LoginForm`
- `SignupForm`
- `PasswordResetRequestForm`
- `ResetPasswordForm`
- `ChangePasswordForm`
- `TwoFactorForm`
- `PasskeyLoginButton`
- `PasskeySection`

## Install

Install the published package from npm:

```sh
pnpm add bwh-auth
```

For a deliberately pinned version:

```sh
pnpm add bwh-auth@0.2.0
```

Commit `pnpm-lock.yaml`; consumers do not need a GitHub tarball URL.

When installing locally during package development, a path dependency is still useful:

```sh
pnpm add bwh-auth@file:../auth/ui
```

Install peer dependencies in the consuming app:

```sh
pnpm add lucide-react react react-dom
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

## Custom Signup Fields

`SignupForm` is field-driven so apps can keep app-specific registration concepts, such as invite codes or policy checkboxes, while reusing the shared auth form behavior.

```tsx
<SignupForm
  components={getShadcnComponents()}
  submitMode="native"
  fields={[
    { name: 'first_name', label: 'First Name', required: true, autoComplete: 'given-name' },
    { name: 'last_name', label: 'Last Name', required: true, autoComplete: 'family-name' },
    { name: 'email', label: 'Email', type: 'email', required: true, autoComplete: 'email' },
    { name: 'password', label: 'Password', type: 'password', required: true, minLength: 8, autoComplete: 'new-password' },
    { name: 'password_confirmation', label: 'Confirm Password', type: 'password', required: true, minLength: 8, autoComplete: 'new-password' },
    { name: 'invite_code', label: 'Season Invite Code', required: true },
    { name: 'agreement', label: 'I agree to keep this program confidential.', type: 'checkbox', required: true },
  ]}
/>
```

Signup fields can use `hiddenWhen` for flows such as passwordless signup, where the app submits `passwordless=1` and hides password fields:

```tsx
const fields = [
  { name: 'email', label: 'Email', type: 'email', required: true },
  { name: 'passwordless', label: 'Use a passkey instead of a password', type: 'checkbox' },
  { name: 'password', label: 'Password', type: 'password', required: true, hiddenWhen: (values) => Boolean(values.passwordless) },
  { name: 'password_confirmation', label: 'Confirm Password', type: 'password', required: true, hiddenWhen: (values) => Boolean(values.passwordless) },
]
```

For fetch-based signup flows, `onSuccess` receives both the server result and submitted values. That lets apps create the user first, then enroll a passkey through the shared WebAuthn helper:

```tsx
import { SignupForm, registerPasskey } from 'bwh-auth'

<SignupForm
  components={getShadcnComponents()}
  submitMode="fetch"
  fields={fields}
  onSuccess={async (result, values) => {
    if (values.passwordless) {
      await registerPasskey({ endpoints: { csrfToken } })
    }

    window.location.assign(result.redirect || '/')
  }}
/>
```

## Passkey sign-in

`LoginForm` can include an explicit passkey sign-in button and can opt into WebAuthn conditional UI so passkeys appear in the browser autofill menu for the email field. Conditional UI uses `PublicKeyCredential.isConditionalMediationAvailable()`, starts a conditional `navigator.credentials.get()` request, and sets the email input autocomplete to `username webauthn` when supported.

```tsx
<LoginForm
  components={getShadcnComponents()}
  enablePasskeys
  enablePasskeyAutofill
/>
```

The explicit passkey button and conditional autofill both default to the Laravel package routes:

- `POST /api/passkeys/auth/options`
- `POST /api/passkeys/auth`

## Password Change

`ChangePasswordForm` is intended for authenticated settings pages or dialogs. The consuming app owns the wrapper and backend endpoint; the form posts to `/api/change-password` by default and accepts `endpoints.changePassword` for apps that use a different route.

```tsx
<ChangePasswordForm
  components={getShadcnComponents()}
  endpoints={{ csrfToken }}
  onSuccess={() => setMessage('Password changed successfully.')}
  onError={setError}
/>
```

## Endpoint Defaults

Auth forms default to the Laravel package API routes where the Laravel package owns the endpoint:

- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`
- `POST /api/change-password`
- `POST /api/auth/two-factor/verify`
- `POST /api/auth/two-factor/resend`
- `POST /api/auth/two-factor/report/:token`

Passkey components default to the Laravel package routes:

- `GET /api/passkeys`
- `POST /api/passkeys/register/options`
- `POST /api/passkeys/register`
- `DELETE /api/passkeys/:id`
- `POST /api/passkeys/auth/options`
- `POST /api/passkeys/auth`

## Releasing

Prepare a release from this package directory:

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
- creates and pushes a signed tag like `bwh-auth-v0.1.1`

The release workflow verifies the tag signature, publishes to npm through its
trusted publisher, and creates a GitHub Release with the tarball as a secondary
artifact.

Version bump options:

```sh
pnpm release patch
pnpm release minor
pnpm release major
pnpm release --version=0.2.0
pnpm release --dry-run
```
