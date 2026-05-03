import { KeyRound } from 'lucide-react';
import * as React from 'react';

import { resolveAuthButtonComponent } from './components';
import type { AuthButtonComponentInput, AuthEndpointConfig, AuthJsonResponse } from './types';
import { arrayBufferToBase64url, base64urlToArrayBuffer, getCsrfToken, isAbortError } from './webauthn-utils';

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

  const authOptionsUrl = endpoints.passkeyAuthOptions ?? '/api/passkeys/auth/options';
  const authUrl = endpoints.passkeyAuth ?? '/api/passkeys/auth';

  async function handlePasskeyLogin() {
    setError(null);
    setLoading(true);

    try {
      const optRes = await fetch(authOptionsUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-TOKEN': getCsrfToken(endpoints.csrfToken),
        },
      });

      if (!optRes.ok) {
        throw new Error('Failed to get authentication options');
      }

      const options = await optRes.json();
      const publicKey: PublicKeyCredentialRequestOptions = {
        ...options,
        challenge: base64urlToArrayBuffer(options.challenge),
        allowCredentials: (options.allowCredentials || []).map((credential: { type: string; id: string }) => ({
          ...credential,
          id: base64urlToArrayBuffer(credential.id),
        })),
      };

      const credential = await navigator.credentials.get({ publicKey });
      if (!credential || credential.type !== 'public-key') {
        throw new Error('No passkey selected');
      }

      const pkCredential = credential as PublicKeyCredential;
      const response = pkCredential.response as AuthenticatorAssertionResponse;
      const credentialData = {
        id: pkCredential.id,
        rawId: arrayBufferToBase64url(pkCredential.rawId),
        type: pkCredential.type,
        response: {
          clientDataJSON: arrayBufferToBase64url(response.clientDataJSON),
          authenticatorData: arrayBufferToBase64url(response.authenticatorData),
          signature: arrayBufferToBase64url(response.signature),
          userHandle: response.userHandle ? arrayBufferToBase64url(response.userHandle) : null,
        },
      };

      const authRes = await fetch(authUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-TOKEN': getCsrfToken(endpoints.csrfToken),
        },
        body: JSON.stringify({ credential: credentialData }),
      });

      const result = await authRes.json();
      if (!authRes.ok) {
        throw new Error(result.error || result.message || 'Authentication failed');
      }

      const redirectUrl = result.redirect || '/';
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
