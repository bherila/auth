import * as react_jsx_runtime from 'react/jsx-runtime';
import * as React from 'react';

interface AuthEndpointConfig {
    csrfToken?: string;
    login?: string;
    signup?: string;
    forgotPassword?: string;
    resetPassword?: string;
    changePassword?: string;
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
type AuthValidationErrors = Record<string, string[]>;
type AuthSignupValues = Record<string, string | boolean>;
interface AuthSignupField {
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
    hiddenWhen?: (values: AuthSignupValues) => boolean;
}
interface Passkey {
    id: number;
    name: string;
    aaguid: string | null;
    created_at: string;
    updated_at: string;
}
interface AuthJsonResponse {
    success?: boolean;
    message?: string;
    error?: string;
    redirect?: string;
    requires_2fa?: boolean;
    attempt_token?: string;
    [key: string]: unknown;
}
type AuthButtonVariant = 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link';
type AuthButtonSize = 'default' | 'sm' | 'lg' | 'icon' | 'icon-sm' | 'icon-lg';
type AuthButtonComponentProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
    variant?: AuthButtonVariant;
    size?: AuthButtonSize;
};
type AuthInputComponentProps = React.InputHTMLAttributes<HTMLInputElement>;
type AuthLabelComponentProps = React.LabelHTMLAttributes<HTMLLabelElement>;
type AuthContainerComponentProps = React.HTMLAttributes<HTMLDivElement>;
interface AuthComponentSet {
    Button: React.ComponentType<AuthButtonComponentProps>;
    Card: React.ComponentType<AuthContainerComponentProps>;
    CardContent: React.ComponentType<AuthContainerComponentProps>;
    CardDescription: React.ComponentType<AuthContainerComponentProps>;
    CardHeader: React.ComponentType<AuthContainerComponentProps>;
    CardTitle: React.ComponentType<AuthContainerComponentProps>;
    Input: React.ComponentType<AuthInputComponentProps>;
    Label: React.ComponentType<AuthLabelComponentProps>;
}
type AuthComponents = AuthComponentSet;
type AuthComponentOverrides = Partial<AuthComponentSet>;
type AuthButtonComponent = AuthComponentSet['Button'];
type AuthComponentSuperset = AuthComponentSet & Record<string, React.ComponentType<any>>;
type AuthComponentInput = AuthComponentSet | AuthComponentSuperset;
type AuthButtonComponentInput = Pick<AuthComponentSet, 'Button'> & Record<string, React.ComponentType<any>>;

interface AuthFormProps {
    endpoints?: AuthEndpointConfig;
    components: AuthComponentInput;
    onSuccess?: (result: AuthJsonResponse) => void;
    onError?: (message: string) => void;
}
interface LoginFormProps extends AuthFormProps {
    enablePasskeys?: boolean;
    enablePasskeyAutofill?: boolean;
    onTwoFactorRequired?: (result: AuthJsonResponse & {
        attempt_token?: string;
    }) => void;
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
declare function LoginForm({ endpoints, components, onSuccess, onError, onTwoFactorRequired, onPasskeySuccess, enablePasskeys, enablePasskeyAutofill, }: LoginFormProps): react_jsx_runtime.JSX.Element;
declare function SignupForm({ endpoints, components, onSuccess, onError, fields, initialValues, errors, submitMode, title, description, submitLabel, submittingLabel, }: SignupFormProps): react_jsx_runtime.JSX.Element;
declare function PasswordResetRequestForm({ endpoints, components, onSuccess, onError }: AuthFormProps): react_jsx_runtime.JSX.Element;
declare function ResetPasswordForm({ endpoints, components, onSuccess, onError, token: initialToken, email: initialEmail }: ResetPasswordFormProps): react_jsx_runtime.JSX.Element;
declare function ChangePasswordForm({ endpoints, components, onSuccess, onError }: AuthFormProps): react_jsx_runtime.JSX.Element;
declare function TwoFactorForm({ endpoints, components, attemptToken, appEnv, onSuccess, onError, onReportSuspicious }: TwoFactorFormProps): react_jsx_runtime.JSX.Element;

interface PasskeyLoginButtonProps {
    endpoints?: AuthEndpointConfig;
    components: AuthButtonComponentInput;
    className?: string;
    onSuccess?: (redirectUrl: string, result: AuthJsonResponse) => void;
    onError?: (message: string) => void;
}
declare function PasskeyLoginButton({ endpoints, components, className, onSuccess, onError }: PasskeyLoginButtonProps): react_jsx_runtime.JSX.Element | null;

interface PasskeySectionProps {
    endpoints?: AuthEndpointConfig;
    components: AuthComponentInput;
    onSuccess?: (message: string) => void;
    onError?: (field: string, message: string) => void;
}
declare function PasskeySection({ endpoints, components, onSuccess, onError }: PasskeySectionProps): react_jsx_runtime.JSX.Element;

declare function getCsrfToken(explicitToken?: string): string;
declare function base64urlToArrayBuffer(b64: string): ArrayBuffer;
declare function arrayBufferToBase64url(buffer: ArrayBuffer): string;
declare function isAbortError(error: unknown): boolean;
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
declare function getDefaultPasskeyName(): string;
declare function isConditionalMediationAvailable(): Promise<boolean>;
declare function authenticateWithPasskey({ endpoints, mediation, signal }?: AuthenticateWithPasskeyOptions): Promise<PasskeyAuthenticationResult>;
declare function registerPasskey({ endpoints, name, signal }?: RegisterPasskeyOptions): Promise<PasskeyRegistrationResult>;

export { type AuthButtonComponent, type AuthButtonComponentInput, type AuthButtonComponentProps, type AuthButtonSize, type AuthButtonVariant, type AuthComponentInput, type AuthComponentOverrides, type AuthComponentSet, type AuthComponentSuperset, type AuthComponents, type AuthContainerComponentProps, type AuthEndpointConfig, type AuthInputComponentProps, type AuthJsonResponse, type AuthLabelComponentProps, type AuthSignupField, type AuthSignupValues, type AuthValidationErrors, ChangePasswordForm, LoginForm, type Passkey, PasskeyLoginButton, PasskeySection, PasswordResetRequestForm, ResetPasswordForm, SignupForm, TwoFactorForm, arrayBufferToBase64url, authenticateWithPasskey, base64urlToArrayBuffer, getCsrfToken, getDefaultPasskeyName, isAbortError, isConditionalMediationAvailable, registerPasskey };
