export interface AuthEndpointConfig {
  csrfToken?: string;
  login?: string;
  signup?: string;
  forgotPassword?: string;
  resetPassword?: string;
  passkeyList?: string;
  passkeyRegisterOptions?: string;
  passkeyRegister?: string;
  passkeyDelete?: (id: number | string) => string;
  passkeyAuthOptions?: string;
  passkeyAuth?: string;
}

export interface Passkey {
  id: number;
  name: string;
  aaguid: string | null;
  created_at: string;
  updated_at: string;
}

export interface AuthJsonResponse {
  success?: boolean;
  message?: string;
  error?: string;
  redirect?: string;
  [key: string]: unknown;
}
