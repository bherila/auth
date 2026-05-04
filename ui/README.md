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

For app CI before npm publication, use the GitHub Release tarball. This is the recommended path because the tarball includes built `dist` files and does not require CI to build this package during dependency installation.

```sh
pnpm add https://github.com/bherila/auth/releases/download/bwh-auth-v0.1.2/bwh-auth-0.1.2.tgz
```

Or pin it manually in `package.json`:

```json
{
  "dependencies": {
    "bwh-auth": "https://github.com/bherila/auth/releases/download/bwh-auth-v0.1.2/bwh-auth-0.1.2.tgz"
  }
}
```

When installing locally during package development, a path dependency is still useful:

```sh
pnpm add bwh-auth@file:../auth/ui
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
