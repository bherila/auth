import type * as React from 'react';

export interface AuthEndpointConfig {
  csrfToken?: string;
  login?: string;
  signup?: string;
  forgotPassword?: string;
  resetPassword?: string;
  twoFactorVerify?: string;
  twoFactorResend?: string;
  twoFactorReport?: (token: string) => string;
  passkeyList?: string;
  passkeyRegisterOptions?: string;
  passkeyRegister?: string;
  passkeyDelete?: (id: number | string) => string;
  passkeyAuthOptions?: string;
  passkeyAuth?: string;
}


export interface AuthSignupField {
  name: string;
  label: React.ReactNode;
  type?: React.HTMLInputTypeAttribute;
  placeholder?: string;
  required?: boolean;
  autoComplete?: string;
  initialValue?: string | boolean;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  inputMode?: React.HTMLAttributes<HTMLInputElement>['inputMode'];
  helpText?: React.ReactNode;
  className?: string;
  containerClassName?: string;
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
  requires_2fa?: boolean;
  attempt_token?: string;
  [key: string]: unknown;
}

export type AuthButtonVariant = 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link';
export type AuthButtonSize = 'default' | 'sm' | 'lg' | 'icon' | 'icon-sm' | 'icon-lg';

export type AuthButtonComponentProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: AuthButtonVariant;
  size?: AuthButtonSize;
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
