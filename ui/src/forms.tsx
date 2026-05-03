import * as React from 'react';

import { resolveAuthComponents } from './components';
import type { AuthComponentInput, AuthEndpointConfig, AuthJsonResponse } from './types';
import { getCsrfToken } from './webauthn-utils';

interface AuthFormProps {
  endpoints?: AuthEndpointConfig;
  components: AuthComponentInput;
  onSuccess?: (result: AuthJsonResponse) => void;
  onError?: (message: string) => void;
}

interface LoginFormProps extends AuthFormProps {
  onTwoFactorRequired?: (result: AuthJsonResponse & { attempt_token?: string }) => void;
}

interface ResetPasswordFormProps extends AuthFormProps {
  token?: string;
  email?: string;
}

interface TwoFactorFormProps extends AuthFormProps {
  attemptToken: string;
  appEnv?: string;
  onReportSuspicious?: (result: AuthJsonResponse) => void;
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

export function LoginForm({ endpoints = {}, components, onSuccess, onError, onTwoFactorRequired }: LoginFormProps) {
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
      if (result.requires_2fa) {
        onTwoFactorRequired?.(result);
        if (!onTwoFactorRequired && typeof result.attempt_token === 'string') {
          window.location.href = `/login/two-factor/${encodeURIComponent(result.attempt_token)}`;
        }
        return;
      }

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
      const result = await postForm(endpoints.forgotPassword ?? '/api/auth/forgot-password', { email }, endpoints.csrfToken);
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

export function ResetPasswordForm({ endpoints = {}, components, onSuccess, onError, token: initialToken = '', email: initialEmail = '' }: ResetPasswordFormProps) {
  const { Button, Input, Label } = resolveAuthComponents(components);
  const [email, setEmail] = React.useState(initialEmail);
  const [token, setToken] = React.useState(initialToken);
  const [password, setPassword] = React.useState('');
  const [passwordConfirmation, setPasswordConfirmation] = React.useState('');

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();

    try {
      const result = await postForm(endpoints.resetPassword ?? '/api/auth/reset-password', {
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


export function TwoFactorForm({ endpoints = {}, components, attemptToken, appEnv, onSuccess, onError, onReportSuspicious }: TwoFactorFormProps) {
  const { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Label } = resolveAuthComponents(components);
  const [currentAttemptToken, setCurrentAttemptToken] = React.useState(attemptToken);
  const [code, setCode] = React.useState('');
  const [loading, setLoading] = React.useState(false);
  const [resending, setResending] = React.useState(false);
  const [message, setMessage] = React.useState('');

  React.useEffect(() => setCurrentAttemptToken(attemptToken), [attemptToken]);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      const result = await postForm(endpoints.twoFactorVerify ?? '/api/auth/two-factor/verify', {
        attempt_token: currentAttemptToken,
        code: code.trim(),
      }, endpoints.csrfToken);
      onSuccess?.(result);
      if (!onSuccess && result.redirect) window.location.href = result.redirect;
    } catch (error: unknown) {
      setCode('');
      onError?.(error instanceof Error ? error.message : 'Verification failed');
    } finally {
      setLoading(false);
    }
  }

  async function resend() {
    setResending(true);
    setMessage('');

    try {
      const result = await postForm(endpoints.twoFactorResend ?? '/api/auth/two-factor/resend', {
        attempt_token: currentAttemptToken,
      }, endpoints.csrfToken);
      if (typeof result.attempt_token === 'string') setCurrentAttemptToken(result.attempt_token);
      setMessage(result.message ?? 'A new verification code has been sent.');
    } catch (error: unknown) {
      onError?.(error instanceof Error ? error.message : 'Could not resend verification code');
    } finally {
      setResending(false);
    }
  }

  async function reportSuspicious() {
    const url = endpoints.twoFactorReport?.(currentAttemptToken) ?? `/api/auth/two-factor/report/${encodeURIComponent(currentAttemptToken)}`;
    try {
      const result = await postForm(url, {}, endpoints.csrfToken);
      setMessage(result.message ?? 'This login attempt has been reported.');
      onReportSuspicious?.(result);
    } catch (error: unknown) {
      onError?.(error instanceof Error ? error.message : 'Could not report the login attempt');
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Verify Your Login</CardTitle>
        <CardDescription>Enter the 6-digit code sent to your email address.</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="space-y-4" onSubmit={(event) => void onSubmit(event)}>
          <div className="space-y-1">
            <Label htmlFor="two-factor-code">Verification Code</Label>
            <Input
              id="two-factor-code"
              type="text"
              inputMode="numeric"
              pattern="[0-9]{6}"
              maxLength={6}
              autoComplete="one-time-code"
              required
              value={code}
              onChange={(event) => setCode(event.target.value.replace(/\D/g, ''))}
            />
          </div>
          <Button type="submit" className="w-full" disabled={loading || code.length !== 6}>{loading ? 'Verifying...' : 'Verify Code'}</Button>
        </form>

        <div className="mt-4 space-y-2 text-sm">
          <Button type="button" variant="outline" className="w-full" disabled={resending} onClick={() => void resend()}>
            {resending ? 'Sending...' : 'Send a new code'}
          </Button>
          <button type="button" className="text-sm underline" onClick={() => void reportSuspicious()}>
            This was not me
          </button>
          {message ? <p>{message}</p> : null}
          {appEnv && appEnv !== 'production' ? <p>Dev mode: use 999999 to bypass 2FA.</p> : null}
        </div>
      </CardContent>
    </Card>
  );
}
