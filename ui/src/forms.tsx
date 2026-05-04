import * as React from 'react';

import { resolveAuthComponents } from './components';
import { PasskeyLoginButton } from './passkey-login-button';
import type { AuthComponentInput, AuthEndpointConfig, AuthJsonResponse, AuthSignupField, AuthSignupValues, AuthValidationErrors } from './types';
import { authenticateWithPasskey, getCsrfToken, isAbortError, isConditionalMediationAvailable } from './webauthn-utils';

interface AuthFormProps {
  endpoints?: AuthEndpointConfig;
  components: AuthComponentInput;
  onSuccess?: (result: AuthJsonResponse) => void;
  onError?: (message: string) => void;
}

interface LoginFormProps extends AuthFormProps {
  enablePasskeys?: boolean;
  enablePasskeyAutofill?: boolean;
  onTwoFactorRequired?: (result: AuthJsonResponse & { attempt_token?: string }) => void;
  onPasskeySuccess?: (redirectUrl: string, result: AuthJsonResponse) => void;
}

interface SignupFormProps extends Omit<AuthFormProps, 'onSuccess'> {
  fields?: AuthSignupField[];
  initialValues?: AuthSignupValues;
  errors?: AuthValidationErrors;
  submitMode?: 'fetch' | 'native';
  title?: React.ReactNode;
  description?: React.ReactNode;
  submitLabel?: React.ReactNode;
  submittingLabel?: React.ReactNode;
  onSuccess?: (result: AuthJsonResponse, values: AuthSignupValues) => void | Promise<void>;
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

class AuthRequestError extends Error {
  constructor(message: string, public readonly result: AuthJsonResponse) {
    super(message);
    this.name = 'AuthRequestError';
  }
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
    throw new AuthRequestError(result.message || result.error || 'Request failed', result);
  }

  return result;
}

export function LoginForm({
  endpoints = {},
  components,
  onSuccess,
  onError,
  onTwoFactorRequired,
  onPasskeySuccess,
  enablePasskeys = false,
  enablePasskeyAutofill = enablePasskeys,
}: LoginFormProps) {
  const { Button, Card, CardContent, CardHeader, CardTitle, Input, Label } = resolveAuthComponents(components);
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [remember, setRemember] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [conditionalPasskeyAvailable, setConditionalPasskeyAvailable] = React.useState(false);
  const passkeyEndpoints = React.useMemo(() => ({
    csrfToken: endpoints.csrfToken,
    passkeyAuth: endpoints.passkeyAuth,
    passkeyAuthOptions: endpoints.passkeyAuthOptions,
  }), [endpoints.csrfToken, endpoints.passkeyAuth, endpoints.passkeyAuthOptions]);

  React.useEffect(() => {
    if (!enablePasskeyAutofill) return;

    const abortController = new AbortController();
    let active = true;

    async function startConditionalPasskeyLogin() {
      const available = await isConditionalMediationAvailable();
      if (!available || !active) return;

      setConditionalPasskeyAvailable(true);

      try {
        const { redirectUrl, result } = await authenticateWithPasskey({
          endpoints: passkeyEndpoints,
          mediation: 'conditional',
          signal: abortController.signal,
        });

        if (!active) return;

        if (onPasskeySuccess) {
          onPasskeySuccess(redirectUrl, result);
        } else {
          window.location.href = redirectUrl;
        }
      } catch (error: unknown) {
        if (!isAbortError(error) && active) {
          onError?.(error instanceof Error ? error.message : 'Passkey login failed');
        }
      }
    }

    void startConditionalPasskeyLogin();

    return () => {
      active = false;
      abortController.abort();
    };
  }, [enablePasskeyAutofill, onError, onPasskeySuccess, passkeyEndpoints]);

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
            <Input id="login-email" type="email" autoComplete={conditionalPasskeyAvailable ? 'username webauthn' : 'email'} required value={email} onChange={(event) => setEmail(event.target.value)} />
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
        {enablePasskeys ? (
          <div className="mt-4">
            <PasskeyLoginButton
              components={{ Button }}
              endpoints={endpoints}
              onSuccess={(redirectUrl, result) => {
                if (onPasskeySuccess) {
                  onPasskeySuccess(redirectUrl, result);
                } else {
                  window.location.href = redirectUrl;
                }
              }}
              onError={onError}
            />
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

function defaultSignupFields(): AuthSignupField[] {
  return [
    { name: 'name', label: 'Name', required: true, autoComplete: 'name' },
    { name: 'email', label: 'Email', type: 'email', required: true, autoComplete: 'email' },
    { name: 'password', label: 'Password', type: 'password', required: true, autoComplete: 'new-password' },
    { name: 'password_confirmation', label: 'Confirm Password', type: 'password', required: true, autoComplete: 'new-password' },
  ];
}

function initialSignupValue(field: AuthSignupField, initialValues: AuthSignupValues): string | boolean {
  if (Object.prototype.hasOwnProperty.call(initialValues, field.name)) return initialValues[field.name];
  if (field.initialValue !== undefined) return field.initialValue;
  return field.type === 'checkbox' ? false : '';
}

export function SignupForm({
  endpoints = {},
  components,
  onSuccess,
  onError,
  fields = defaultSignupFields(),
  initialValues = {},
  errors = {},
  submitMode = 'fetch',
  title = 'Create Account',
  description,
  submitLabel = 'Create Account',
  submittingLabel = 'Creating account...',
}: SignupFormProps) {
  const { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Label } = resolveAuthComponents(components);
  const [values, setValues] = React.useState<AuthSignupValues>(() => Object.fromEntries(
    fields.map((field) => [field.name, initialSignupValue(field, initialValues)]),
  ));
  const [fieldErrors, setFieldErrors] = React.useState<AuthValidationErrors>(errors);
  const [loading, setLoading] = React.useState(false);

  async function onSubmit(event: React.FormEvent) {
    setLoading(true);

    if (submitMode === 'native') {
      return;
    }

    event.preventDefault();
    setFieldErrors({});

    try {
      const result = await postForm(endpoints.signup ?? '/register', values, endpoints.csrfToken);
      await onSuccess?.(result, values);
      if (!onSuccess && result.redirect) window.location.href = result.redirect;
    } catch (error: unknown) {
      if (error instanceof AuthRequestError && error.result.errors && typeof error.result.errors === 'object') {
        setFieldErrors(error.result.errors as AuthValidationErrors);
      }
      onError?.(error instanceof Error ? error.message : 'Signup failed');
    } finally {
      setLoading(false);
    }
  }

  function setValue(name: string, value: string | boolean) {
    setValues((current) => ({ ...current, [name]: value }));
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description ? <CardDescription>{description}</CardDescription> : null}
      </CardHeader>
      <CardContent>
        <form className="space-y-4" method={submitMode === 'native' ? 'POST' : undefined} action={endpoints.signup ?? '/register'} onSubmit={(event) => void onSubmit(event)}>
          {submitMode === 'native' ? <input type="hidden" name="_token" value={getCsrfToken(endpoints.csrfToken)} /> : null}
          {fields.map((field) => {
            if (field.hiddenWhen?.(values)) return null;

            const error = fieldErrors[field.name]?.[0];
            const value = values[field.name];

            if (field.type === 'checkbox') {
              return (
                <div className={field.containerClassName ?? 'space-y-1'} key={field.name}>
                  <label className="flex items-start gap-2 text-sm">
                    <input
                      id={`signup-${field.name}`}
                      name={field.name}
                      type="checkbox"
                      value="1"
                      checked={Boolean(value)}
                      onChange={(event) => setValue(field.name, event.target.checked)}
                      required={field.required}
                    />
                    <span>{field.label}</span>
                  </label>
                  {field.helpText ? <p className="text-xs text-muted-foreground">{field.helpText}</p> : null}
                  {error ? <p className="text-sm text-destructive">{error}</p> : null}
                </div>
              );
            }

            return (
              <div className={field.containerClassName ?? 'space-y-1'} key={field.name}>
                <Label htmlFor={`signup-${field.name}`}>{field.label}</Label>
                <Input
                  id={`signup-${field.name}`}
                  name={field.name}
                  type={field.type ?? 'text'}
                  placeholder={field.placeholder}
                  required={field.required}
                  autoComplete={field.autoComplete}
                  minLength={field.minLength}
                  maxLength={field.maxLength}
                  pattern={field.pattern}
                  inputMode={field.inputMode}
                  className={field.className}
                  aria-invalid={Boolean(error)}
                  value={String(value ?? '')}
                  onChange={(event) => setValue(field.name, event.target.value)}
                />
                {field.helpText ? <p className="text-xs text-muted-foreground">{field.helpText}</p> : null}
                {error ? <p className="text-sm text-destructive">{error}</p> : null}
              </div>
            );
          })}
          <Button type="submit" className="w-full" disabled={loading}>{loading ? submittingLabel : submitLabel}</Button>
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

export function ChangePasswordForm({ endpoints = {}, components, onSuccess, onError }: AuthFormProps) {
  const { Button, Input, Label } = resolveAuthComponents(components);
  const [currentPassword, setCurrentPassword] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [passwordConfirmation, setPasswordConfirmation] = React.useState('');
  const [loading, setLoading] = React.useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);

    if (password !== passwordConfirmation) {
      onError?.('New passwords do not match.');
      setLoading(false);
      return;
    }

    try {
      const result = await postForm(endpoints.changePassword ?? '/api/change-password', {
        current_password: currentPassword,
        password,
        password_confirmation: passwordConfirmation,
      }, endpoints.csrfToken);
      setCurrentPassword('');
      setPassword('');
      setPasswordConfirmation('');
      onSuccess?.(result);
    } catch (error: unknown) {
      onError?.(error instanceof Error ? error.message : 'Password change failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <form className="space-y-4" onSubmit={(event) => void onSubmit(event)}>
      <div className="space-y-1">
        <Label htmlFor="current-password">Current Password</Label>
        <Input id="current-password" type="password" autoComplete="current-password" required value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} />
      </div>
      <div className="space-y-1">
        <Label htmlFor="new-password">New Password</Label>
        <Input id="new-password" type="password" autoComplete="new-password" minLength={8} required value={password} onChange={(event) => setPassword(event.target.value)} />
      </div>
      <div className="space-y-1">
        <Label htmlFor="confirm-password">Confirm New Password</Label>
        <Input id="confirm-password" type="password" autoComplete="new-password" minLength={8} required value={passwordConfirmation} onChange={(event) => setPasswordConfirmation(event.target.value)} />
      </div>
      <Button type="submit" disabled={loading}>{loading ? 'Changing...' : 'Change Password'}</Button>
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
