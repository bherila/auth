import type { AuthEndpointConfig, AuthJsonResponse } from './types';

export function getCsrfToken(explicitToken?: string): string {
  if (explicitToken) {
    return explicitToken;
  }

  return (document.querySelector('meta[name="csrf-token"]') as HTMLMetaElement | null)?.content ?? '';
}

export function base64urlToArrayBuffer(b64: string): ArrayBuffer {
  const base64 = b64.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  const binary = window.atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

export function arrayBufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';

  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i] ?? 0);
  }

  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function isAbortError(error: unknown): boolean {
  return error instanceof Error && (error as DOMException).name === 'AbortError';
}

interface AuthenticateWithPasskeyOptions {
  endpoints?: AuthEndpointConfig;
  mediation?: CredentialMediationRequirement;
  signal?: AbortSignal;
}

interface PasskeyAuthenticationResult {
  redirectUrl: string;
  result: AuthJsonResponse;
}

interface RegisterPasskeyOptions {
  endpoints?: AuthEndpointConfig;
  name?: string;
  signal?: AbortSignal;
}

interface PasskeyRegistrationResult {
  result: AuthJsonResponse;
}

interface ConditionalMediationPublicKeyCredentialConstructor {
  isConditionalMediationAvailable?: () => Promise<boolean>;
}

export function getDefaultPasskeyName(): string {
  if (typeof window === 'undefined') return 'Passkey';

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

export async function isConditionalMediationAvailable(): Promise<boolean> {
  if (typeof window === 'undefined' || !window.PublicKeyCredential) return false;

  const credentialConstructor = window.PublicKeyCredential as typeof PublicKeyCredential & ConditionalMediationPublicKeyCredentialConstructor;
  if (!credentialConstructor.isConditionalMediationAvailable) return false;

  try {
    return await credentialConstructor.isConditionalMediationAvailable();
  } catch {
    return false;
  }
}

export async function authenticateWithPasskey({ endpoints = {}, mediation, signal }: AuthenticateWithPasskeyOptions = {}): Promise<PasskeyAuthenticationResult> {
  const authOptionsUrl = endpoints.passkeyAuthOptions ?? '/api/passkeys/auth/options';
  const authUrl = endpoints.passkeyAuth ?? '/api/passkeys/auth';

  const optRes = await fetch(authOptionsUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-TOKEN': getCsrfToken(endpoints.csrfToken),
    },
    signal,
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

  const credential = await navigator.credentials.get({ publicKey, mediation, signal });
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
    signal,
  });

  const result = await authRes.json();
  if (!authRes.ok) {
    throw new Error(result.error || result.message || 'Authentication failed');
  }

  return {
    result,
    redirectUrl: result.redirect || '/',
  };
}

export async function registerPasskey({ endpoints = {}, name, signal }: RegisterPasskeyOptions = {}): Promise<PasskeyRegistrationResult> {
  const registerOptionsUrl = endpoints.passkeyRegisterOptions ?? '/api/passkeys/register/options';
  const registerUrl = endpoints.passkeyRegister ?? '/api/passkeys/register';
  const passkeyName = name || getDefaultPasskeyName();

  const optRes = await fetch(registerOptionsUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-TOKEN': getCsrfToken(endpoints.csrfToken),
    },
    signal,
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

  const credential = await navigator.credentials.create({ publicKey, signal });
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
    body: JSON.stringify({ credential: credentialData, name: passkeyName }),
    signal,
  });

  const result = await verifyRes.json();
  if (!verifyRes.ok) {
    throw new Error(result.error || result.message || 'Registration failed');
  }

  return { result };
}
