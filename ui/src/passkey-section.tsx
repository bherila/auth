import { Key, Plus, Trash2 } from 'lucide-react';
import * as React from 'react';
import { flushSync } from 'react-dom';

import { resolveAuthComponents } from './components';
import type { AuthComponentInput, AuthEndpointConfig, Passkey } from './types';
import { getCsrfToken, getDefaultPasskeyName, isAbortError, registerPasskey as createPasskey } from './webauthn-utils';

interface PasskeySectionProps {
  endpoints?: AuthEndpointConfig;
  components: AuthComponentInput;
  onSuccess?: (message: string) => void;
  onError?: (field: string, message: string) => void;
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
    const name = pendingName || getDefaultPasskeyName();
    flushSync(() => setPendingName(name));
    setRegistering(true);

    try {
      await createPasskey({ endpoints: { ...endpoints, passkeyRegisterOptions: registerOptionsUrl, passkeyRegister: registerUrl }, name });
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
              <Input id="passkey-name" value={pendingName} onChange={(event) => setPendingName(event.target.value)} placeholder={getDefaultPasskeyName()} />
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
