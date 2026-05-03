import * as React from 'react';

import { resolveAuthComponents } from './components';
import type { AuthComponentOverrides, AuthEndpointConfig, AuthJsonResponse } from './types';
import { getCsrfToken } from './webauthn-utils';

interface AuthFormProps {
  endpoints?: AuthEndpointConfig;
  components?: AuthComponentOverrides;
  onSuccess?: (result: AuthJsonResponse) => void;
  onError?: (message: string) => void;
}

async function postForm(url: string, body: Record<string, unknown>, csrfToken?: string): Promise<AuthJsonResponse> {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'X-CSRF-TOKEN': getCsrfToken(csrfToken),
    },
    body: JSON.stringify(body),
  });
  const result = await response.json();

  if (!response.ok) {
    throw new Error(result.message || result.error || 'Request failed');
  }

  return result;
}

export function LoginForm({ endpoints = {}, components, onSuccess, onError }: AuthFormProps) {
  const { Button, Card, CardContent, CardHeader, CardTitle, Input, Label } = resolveAuthComponents(components);
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [remember, setRemember] = React.useState(false);
  const [loading, setLoading] = React.useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);

    try {
      const result = await postForm(endpoints.login ?? '/login', { email, password, remember }, endpoints.csrfToken);
      onSuccess?.(result);
      if (!onSuccess && result.redirect) window.location.href = result.redirect;
    } catch (error: unknown) {
      onError?.(error instanceof Error ? error.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Sign In</CardTitle>
      </CardHeader>
      <CardContent>
        <form className="space-y-4" onSubmit={(event) => void onSubmit(event)}>
          <div className="space-y-1">
            <Label htmlFor="login-email">Email</Label>
            <Input id="login-email" type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="login-password">Password</Label>
            <Input id="login-password" type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} />
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={remember} onChange={(event) => setRemember(event.target.checked)} />
            Keep me signed in
          </label>
          <Button type="submit" className="w-full" disabled={loading}>{loading ? 'Signing in...' : 'Sign In'}</Button>
        </form>
      </CardContent>
    </Card>
  );
}

export function SignupForm({ endpoints = {}, components, onSuccess, onError }: AuthFormProps) {
  const { Button, Card, CardContent, CardHeader, CardTitle, Input, Label } = resolveAuthComponents(components);
  const [name, setName] = React.useState('');
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [passwordConfirmation, setPasswordConfirmation] = React.useState('');
  const [loading, setLoading] = React.useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);

    try {
      const result = await postForm(endpoints.signup ?? '/register', {
        name,
        email,
        password,
        password_confirmation: passwordConfirmation,
      }, endpoints.csrfToken);
      onSuccess?.(result);
      if (!onSuccess && result.redirect) window.location.href = result.redirect;
    } catch (error: unknown) {
      onError?.(error instanceof Error ? error.message : 'Signup failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Create Account</CardTitle>
      </CardHeader>
      <CardContent>
        <form className="space-y-4" onSubmit={(event) => void onSubmit(event)}>
          <div className="space-y-1">
            <Label htmlFor="signup-name">Name</Label>
            <Input id="signup-name" autoComplete="name" required value={name} onChange={(event) => setName(event.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="signup-email">Email</Label>
            <Input id="signup-email" type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="signup-password">Password</Label>
            <Input id="signup-password" type="password" autoComplete="new-password" required value={password} onChange={(event) => setPassword(event.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="signup-password-confirmation">Confirm Password</Label>
            <Input id="signup-password-confirmation" type="password" autoComplete="new-password" required value={passwordConfirmation} onChange={(event) => setPasswordConfirmation(event.target.value)} />
          </div>
          <Button type="submit" className="w-full" disabled={loading}>{loading ? 'Creating account...' : 'Create Account'}</Button>
        </form>
      </CardContent>
    </Card>
  );
}

export function PasswordResetRequestForm({ endpoints = {}, components, onSuccess, onError }: AuthFormProps) {
  const { Button, Input, Label } = resolveAuthComponents(components);
  const [email, setEmail] = React.useState('');
  const [loading, setLoading] = React.useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);

    try {
      const result = await postForm(endpoints.forgotPassword ?? '/forgot-password', { email }, endpoints.csrfToken);
      onSuccess?.(result);
    } catch (error: unknown) {
      onError?.(error instanceof Error ? error.message : 'Password reset request failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <form className="space-y-4" onSubmit={(event) => void onSubmit(event)}>
      <div className="space-y-1">
        <Label htmlFor="reset-email">Email</Label>
        <Input id="reset-email" type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} />
      </div>
      <Button type="submit" disabled={loading}>{loading ? 'Sending...' : 'Send Reset Link'}</Button>
    </form>
  );
}

export function ResetPasswordForm({ endpoints = {}, components, onSuccess, onError }: AuthFormProps) {
  const { Button, Input, Label } = resolveAuthComponents(components);
  const [email, setEmail] = React.useState('');
  const [token, setToken] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [passwordConfirmation, setPasswordConfirmation] = React.useState('');

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();

    try {
      const result = await postForm(endpoints.resetPassword ?? '/reset-password', {
        email,
        token,
        password,
        password_confirmation: passwordConfirmation,
      }, endpoints.csrfToken);
      onSuccess?.(result);
    } catch (error: unknown) {
      onError?.(error instanceof Error ? error.message : 'Password reset failed');
    }
  }

  return (
    <form className="space-y-4" onSubmit={(event) => void onSubmit(event)}>
      <Input type="hidden" value={token} onChange={(event) => setToken(event.target.value)} />
      <div className="space-y-1">
        <Label htmlFor="reset-password-email">Email</Label>
        <Input id="reset-password-email" type="email" required value={email} onChange={(event) => setEmail(event.target.value)} />
      </div>
      <div className="space-y-1">
        <Label htmlFor="reset-password">Password</Label>
        <Input id="reset-password" type="password" required value={password} onChange={(event) => setPassword(event.target.value)} />
      </div>
      <div className="space-y-1">
        <Label htmlFor="reset-password-confirmation">Confirm Password</Label>
        <Input id="reset-password-confirmation" type="password" required value={passwordConfirmation} onChange={(event) => setPasswordConfirmation(event.target.value)} />
      </div>
      <Button type="submit">Reset Password</Button>
    </form>
  );
}
