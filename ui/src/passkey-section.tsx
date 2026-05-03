import { Key, Plus, Trash2 } from 'lucide-react';
import * as React from 'react';
import { flushSync } from 'react-dom';

import { resolveAuthComponents } from './components';
import type { AuthComponentInput, AuthEndpointConfig, Passkey } from './types';
import { arrayBufferToBase64url, base64urlToArrayBuffer, getCsrfToken, isAbortError } from './webauthn-utils';

interface PasskeySectionProps {
  endpoints?: AuthEndpointConfig;
  components: AuthComponentInput;
  onSuccess?: (message: string) => void;
  onError?: (field: string, message: string) => void;
}

function getDeviceName(): string {
  const ua = window.navigator.userAgent;
  let browser = 'Unknown Browser';
  let os = 'Unknown OS';

  if (ua.includes('Firefox')) browser = 'Firefox';
  else if (ua.includes('Edg')) browser = 'Edge';
  else if (ua.includes('Chrome')) browser = 'Chrome';
  else if (ua.includes('Safari')) browser = 'Safari';

  if (ua.includes('Mac OS X')) os = 'macOS';
  else if (ua.includes('Windows')) os = 'Windows';
  else if (ua.includes('Android')) os = 'Android';
  else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';
  else if (ua.includes('Linux')) os = 'Linux';

  return `Passkey (${browser} on ${os})`;
}

export function PasskeySection({ endpoints = {}, components, onSuccess, onError }: PasskeySectionProps) {
  const { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Label } = resolveAuthComponents(components);
  const [passkeys, setPasskeys] = React.useState<Passkey[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [registering, setRegistering] = React.useState(false);
  const [pendingName, setPendingName] = React.useState('');

  const listUrl = endpoints.passkeyList ?? '/api/passkeys';
  const registerOptionsUrl = endpoints.passkeyRegisterOptions ?? '/api/passkeys/register/options';
  const registerUrl = endpoints.passkeyRegister ?? '/api/passkeys/register';
  const deleteUrl = endpoints.passkeyDelete ?? ((id: number | string) => `/api/passkeys/${id}`);

  const fetchPasskeys = React.useCallback(async () => {
    try {
      const res = await fetch(listUrl);
      if (res.ok) {
        setPasskeys(await res.json());
      }
    } catch {
      onError?.('passkeys', 'Failed to load passkeys');
    } finally {
      setLoading(false);
    }
  }, [listUrl, onError]);

  React.useEffect(() => {
    void fetchPasskeys();
  }, [fetchPasskeys]);

  async function registerPasskey() {
    const name = pendingName || getDeviceName();
    flushSync(() => setPendingName(name));
    setRegistering(true);

    try {
      const optRes = await fetch(registerOptionsUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-TOKEN': getCsrfToken(endpoints.csrfToken),
        },
      });

      if (!optRes.ok) {
        throw new Error('Failed to get registration options');
      }

      const options = await optRes.json();
      const publicKey: PublicKeyCredentialCreationOptions = {
        ...options,
        challenge: base64urlToArrayBuffer(options.challenge),
        user: {
          ...options.user,
          id: base64urlToArrayBuffer(options.user.id),
        },
        excludeCredentials: (options.excludeCredentials || []).map((credential: { type: string; id: string }) => ({
          ...credential,
          id: base64urlToArrayBuffer(credential.id),
        })),
      };

      const credential = await navigator.credentials.create({ publicKey });
      if (!credential || credential.type !== 'public-key') {
        throw new Error('Failed to create credential');
      }

      const pkCredential = credential as PublicKeyCredential;
      const response = pkCredential.response as AuthenticatorAttestationResponse;
      const credentialData = {
        id: pkCredential.id,
        rawId: arrayBufferToBase64url(pkCredential.rawId),
        type: pkCredential.type,
        response: {
          clientDataJSON: arrayBufferToBase64url(response.clientDataJSON),
          attestationObject: arrayBufferToBase64url(response.attestationObject),
          transports: response.getTransports ? response.getTransports() : [],
        },
      };

      const verifyRes = await fetch(registerUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-TOKEN': getCsrfToken(endpoints.csrfToken),
        },
        body: JSON.stringify({ credential: credentialData, name }),
      });

      const result = await verifyRes.json();
      if (!verifyRes.ok) {
        throw new Error(result.error || result.message || 'Registration failed');
      }

      setPendingName('');
      onSuccess?.('Passkey registered successfully.');
      await fetchPasskeys();
    } catch (caughtError: unknown) {
      if (!isAbortError(caughtError)) {
        onError?.('passkeys', caughtError instanceof Error ? caughtError.message : 'Passkey registration failed');
      }
    } finally {
      setRegistering(false);
    }
  }

  async function deletePasskey(id: number) {
    try {
      const res = await fetch(deleteUrl(id), {
        method: 'DELETE',
        headers: { 'X-CSRF-TOKEN': getCsrfToken(endpoints.csrfToken) },
      });

      if (!res.ok) {
        throw new Error('Delete failed');
      }

      setPasskeys((current) => current.filter((passkey) => passkey.id !== id));
      onSuccess?.('Passkey removed.');
    } catch {
      onError?.('passkeys', 'Failed to delete passkey');
    }
  }

  const isWebAuthnSupported = typeof window !== 'undefined' && !!window.PublicKeyCredential;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Key className="h-5 w-5" />
          Passkeys
        </CardTitle>
        <CardDescription>Manage passkeys for passwordless login.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!isWebAuthnSupported ? <p className="text-sm text-muted-foreground">Your browser does not support passkeys.</p> : null}

        {loading ? (
          <p className="text-sm text-muted-foreground">Loading passkeys...</p>
        ) : passkeys.length === 0 ? (
          <p className="text-sm text-muted-foreground">No passkeys registered yet.</p>
        ) : (
          <div className="divide-y rounded-md border">
            {passkeys.map((passkey) => (
              <div key={passkey.id} className="flex items-center justify-between gap-3 p-3">
                <div>
                  <div className="font-medium">{passkey.name}</div>
                  <div className="text-sm text-muted-foreground">{new Date(passkey.created_at).toLocaleDateString()}</div>
                </div>
                <Button type="button" variant="ghost" size="icon" aria-label="Delete passkey" onClick={() => void deletePasskey(passkey.id)}>
                  <Trash2 />
                </Button>
              </div>
            ))}
          </div>
        )}

        {isWebAuthnSupported ? (
          <div className="flex flex-col gap-2 sm:flex-row">
            <div className="flex-1 space-y-1">
              <Label htmlFor="passkey-name">Passkey name</Label>
              <Input id="passkey-name" value={pendingName} onChange={(event) => setPendingName(event.target.value)} placeholder={getDeviceName()} />
            </div>
            <Button type="button" className="self-end" variant="outline" disabled={registering} onClick={() => void registerPasskey()}>
              <Plus />
              {registering ? 'Registering...' : 'Add Passkey'}
            </Button>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
