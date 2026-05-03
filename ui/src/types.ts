import type * as React from 'react';

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

export type AuthButtonComponentProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: string;
  size?: string;
};

export type AuthInputComponentProps = React.InputHTMLAttributes<HTMLInputElement>;
export type AuthLabelComponentProps = React.LabelHTMLAttributes<HTMLLabelElement>;
export type AuthContainerComponentProps = React.HTMLAttributes<HTMLDivElement>;

export interface AuthComponentSet {
  Button: React.ComponentType<AuthButtonComponentProps>;
  Card: React.ComponentType<AuthContainerComponentProps>;
  CardContent: React.ComponentType<AuthContainerComponentProps>;
  CardDescription: React.ComponentType<AuthContainerComponentProps>;
  CardHeader: React.ComponentType<AuthContainerComponentProps>;
  CardTitle: React.ComponentType<AuthContainerComponentProps>;
  Input: React.ComponentType<AuthInputComponentProps>;
  Label: React.ComponentType<AuthLabelComponentProps>;
}

export type AuthComponents = AuthComponentSet;
export type AuthComponentOverrides = Partial<AuthComponentSet>;
export type AuthButtonComponent = AuthComponentSet['Button'];
export type AuthComponentSuperset = AuthComponentSet & Record<string, React.ComponentType<any>>;
export type AuthComponentInput = AuthComponentSet | AuthComponentSuperset;
export type AuthButtonComponentInput = Pick<AuthComponentSet, 'Button'> & Record<string, React.ComponentType<any>>;
