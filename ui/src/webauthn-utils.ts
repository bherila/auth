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
