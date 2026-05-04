import { KeyRound } from 'lucide-react';
import * as React from 'react';

import { resolveAuthButtonComponent } from './components';
import type { AuthButtonComponentInput, AuthEndpointConfig, AuthJsonResponse } from './types';
import { authenticateWithPasskey, isAbortError } from './webauthn-utils';

interface PasskeyLoginButtonProps {
  endpoints?: AuthEndpointConfig;
  components: AuthButtonComponentInput;
  className?: string;
  onSuccess?: (redirectUrl: string, result: AuthJsonResponse) => void;
  onError?: (message: string) => void;
}

export function PasskeyLoginButton({ endpoints = {}, components, className, onSuccess, onError }: PasskeyLoginButtonProps) {
  const { Button } = resolveAuthButtonComponent(components);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  async function handlePasskeyLogin() {
    setError(null);
    setLoading(true);

    try {
      const { redirectUrl, result } = await authenticateWithPasskey({ endpoints });
      if (onSuccess) {
        onSuccess(redirectUrl, result);
      } else {
        window.location.href = redirectUrl;
      }
    } catch (caughtError: unknown) {
      if (isAbortError(caughtError)) {
        return;
      }

      const message = caughtError instanceof Error ? caughtError.message : 'Passkey login failed';
      setError(message);
      onError?.(message);
    } finally {
      setLoading(false);
    }
  }

  if (typeof window === 'undefined' || !window.PublicKeyCredential) {
    return null;
  }

  return (
    <div className={className}>
      {error ? <p className="mb-2 text-sm text-destructive">{error}</p> : null}
      <Button type="button" variant="outline" className="w-full" disabled={loading} onClick={handlePasskeyLogin}>
        <KeyRound aria-hidden="true" />
        {loading ? 'Verifying...' : 'Sign in with Passkey'}
      </Button>
    </div>
  );
}
