// src/forms.tsx
import * as React2 from "react";

// src/components.ts
var requiredComponentKeys = [
  "Button",
  "Card",
  "CardContent",
  "CardDescription",
  "CardHeader",
  "CardTitle",
  "Input",
  "Label"
];
function resolveAuthComponents(components) {
  const missing = requiredComponentKeys.filter((key) => !components?.[key]);
  if (missing.length > 0) {
    throw new Error(`bwh-auth requires injected components: ${missing.join(", ")}`);
  }
  return components;
}
function resolveAuthButtonComponent(components) {
  if (!components?.Button) {
    throw new Error("bwh-auth requires an injected Button component");
  }
  return { Button: components.Button };
}

// src/passkey-login-button.tsx
import { KeyRound } from "lucide-react";
import * as React from "react";

// src/webauthn-utils.ts
function getCsrfToken(explicitToken) {
  if (explicitToken) {
    return explicitToken;
  }
  return document.querySelector('meta[name="csrf-token"]')?.content ?? "";
}
function base64urlToArrayBuffer(b64) {
  const base64 = b64.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, "=");
  const binary = window.atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
function arrayBufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i] ?? 0);
  }
  return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
function isAbortError(error) {
  return error instanceof Error && error.name === "AbortError";
}
function getDefaultPasskeyName() {
  if (typeof window === "undefined") return "Passkey";
  const ua = window.navigator.userAgent;
  let browser = "Unknown Browser";
  let os = "Unknown OS";
  if (ua.includes("Firefox")) browser = "Firefox";
  else if (ua.includes("Edg")) browser = "Edge";
  else if (ua.includes("Chrome")) browser = "Chrome";
  else if (ua.includes("Safari")) browser = "Safari";
  if (ua.includes("Mac OS X")) os = "macOS";
  else if (ua.includes("Windows")) os = "Windows";
  else if (ua.includes("Android")) os = "Android";
  else if (ua.includes("iPhone") || ua.includes("iPad")) os = "iOS";
  else if (ua.includes("Linux")) os = "Linux";
  return `Passkey (${browser} on ${os})`;
}
async function isConditionalMediationAvailable() {
  if (typeof window === "undefined" || !window.PublicKeyCredential) return false;
  const credentialConstructor = window.PublicKeyCredential;
  if (!credentialConstructor.isConditionalMediationAvailable) return false;
  try {
    return await credentialConstructor.isConditionalMediationAvailable();
  } catch {
    return false;
  }
}
async function authenticateWithPasskey({ endpoints = {}, mediation, signal } = {}) {
  const authOptionsUrl = endpoints.passkeyAuthOptions ?? "/api/passkeys/auth/options";
  const authUrl = endpoints.passkeyAuth ?? "/api/passkeys/auth";
  const optRes = await fetch(authOptionsUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-TOKEN": getCsrfToken(endpoints.csrfToken)
    },
    signal
  });
  if (!optRes.ok) {
    throw new Error("Failed to get authentication options");
  }
  const options = await optRes.json();
  const publicKey = {
    ...options,
    challenge: base64urlToArrayBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((credential2) => ({
      ...credential2,
      id: base64urlToArrayBuffer(credential2.id)
    }))
  };
  const credential = await navigator.credentials.get({ publicKey, mediation, signal });
  if (!credential || credential.type !== "public-key") {
    throw new Error("No passkey selected");
  }
  const pkCredential = credential;
  const response = pkCredential.response;
  const credentialData = {
    id: pkCredential.id,
    rawId: arrayBufferToBase64url(pkCredential.rawId),
    type: pkCredential.type,
    response: {
      clientDataJSON: arrayBufferToBase64url(response.clientDataJSON),
      authenticatorData: arrayBufferToBase64url(response.authenticatorData),
      signature: arrayBufferToBase64url(response.signature),
      userHandle: response.userHandle ? arrayBufferToBase64url(response.userHandle) : null
    }
  };
  const authRes = await fetch(authUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-TOKEN": getCsrfToken(endpoints.csrfToken)
    },
    body: JSON.stringify({ credential: credentialData }),
    signal
  });
  const result = await authRes.json();
  if (!authRes.ok) {
    throw new Error(result.error || result.message || "Authentication failed");
  }
  return {
    result,
    redirectUrl: result.redirect || "/"
  };
}
async function registerPasskey({ endpoints = {}, name, signal } = {}) {
  const registerOptionsUrl = endpoints.passkeyRegisterOptions ?? "/api/passkeys/register/options";
  const registerUrl = endpoints.passkeyRegister ?? "/api/passkeys/register";
  const passkeyName = name || getDefaultPasskeyName();
  const optRes = await fetch(registerOptionsUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-TOKEN": getCsrfToken(endpoints.csrfToken)
    },
    signal
  });
  if (!optRes.ok) {
    throw new Error("Failed to get registration options");
  }
  const options = await optRes.json();
  const publicKey = {
    ...options,
    challenge: base64urlToArrayBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64urlToArrayBuffer(options.user.id)
    },
    excludeCredentials: (options.excludeCredentials || []).map((credential2) => ({
      ...credential2,
      id: base64urlToArrayBuffer(credential2.id)
    }))
  };
  const credential = await navigator.credentials.create({ publicKey, signal });
  if (!credential || credential.type !== "public-key") {
    throw new Error("Failed to create credential");
  }
  const pkCredential = credential;
  const response = pkCredential.response;
  const credentialData = {
    id: pkCredential.id,
    rawId: arrayBufferToBase64url(pkCredential.rawId),
    type: pkCredential.type,
    response: {
      clientDataJSON: arrayBufferToBase64url(response.clientDataJSON),
      attestationObject: arrayBufferToBase64url(response.attestationObject),
      transports: response.getTransports ? response.getTransports() : []
    }
  };
  const verifyRes = await fetch(registerUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-TOKEN": getCsrfToken(endpoints.csrfToken)
    },
    body: JSON.stringify({ credential: credentialData, name: passkeyName }),
    signal
  });
  const result = await verifyRes.json();
  if (!verifyRes.ok) {
    throw new Error(result.error || result.message || "Registration failed");
  }
  return { result };
}

// src/passkey-login-button.tsx
import { jsx, jsxs } from "react/jsx-runtime";
function PasskeyLoginButton({ endpoints = {}, components, className, onSuccess, onError }) {
  const { Button } = resolveAuthButtonComponent(components);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState(null);
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
    } catch (caughtError) {
      if (isAbortError(caughtError)) {
        return;
      }
      const message = caughtError instanceof Error ? caughtError.message : "Passkey login failed";
      setError(message);
      onError?.(message);
    } finally {
      setLoading(false);
    }
  }
  if (typeof window === "undefined" || !window.PublicKeyCredential) {
    return null;
  }
  return /* @__PURE__ */ jsxs("div", { className, children: [
    error ? /* @__PURE__ */ jsx("p", { className: "mb-2 text-sm text-destructive", children: error }) : null,
    /* @__PURE__ */ jsxs(Button, { type: "button", variant: "outline", className: "w-full", disabled: loading, onClick: handlePasskeyLogin, children: [
      /* @__PURE__ */ jsx(KeyRound, { "aria-hidden": "true" }),
      loading ? "Verifying..." : "Sign in with Passkey"
    ] })
  ] });
}

// src/forms.tsx
import { jsx as jsx2, jsxs as jsxs2 } from "react/jsx-runtime";
var AuthRequestError = class extends Error {
  constructor(message, result) {
    super(message);
    this.result = result;
    this.name = "AuthRequestError";
  }
  result;
};
async function postForm(url, body, csrfToken) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
      "X-CSRF-TOKEN": getCsrfToken(csrfToken)
    },
    body: JSON.stringify(body)
  });
  const result = await response.json();
  if (!response.ok) {
    throw new AuthRequestError(result.message || result.error || "Request failed", result);
  }
  return result;
}
function LoginForm({
  endpoints = {},
  components,
  onSuccess,
  onError,
  onTwoFactorRequired,
  onPasskeySuccess,
  enablePasskeys = false,
  enablePasskeyAutofill = enablePasskeys
}) {
  const { Button, Card, CardContent, CardHeader, CardTitle, Input, Label } = resolveAuthComponents(components);
  const [email, setEmail] = React2.useState("");
  const [password, setPassword] = React2.useState("");
  const [remember, setRemember] = React2.useState(false);
  const [loading, setLoading] = React2.useState(false);
  const [conditionalPasskeyAvailable, setConditionalPasskeyAvailable] = React2.useState(false);
  const passkeyEndpoints = React2.useMemo(() => ({
    csrfToken: endpoints.csrfToken,
    passkeyAuth: endpoints.passkeyAuth,
    passkeyAuthOptions: endpoints.passkeyAuthOptions
  }), [endpoints.csrfToken, endpoints.passkeyAuth, endpoints.passkeyAuthOptions]);
  React2.useEffect(() => {
    if (!enablePasskeyAutofill) return;
    const abortController = new AbortController();
    let active = true;
    async function startConditionalPasskeyLogin() {
      const available = await isConditionalMediationAvailable();
      if (!available || !active) return;
      setConditionalPasskeyAvailable(true);
      try {
        const { redirectUrl, result } = await authenticateWithPasskey({
          endpoints: passkeyEndpoints,
          mediation: "conditional",
          signal: abortController.signal
        });
        if (!active) return;
        if (onPasskeySuccess) {
          onPasskeySuccess(redirectUrl, result);
        } else {
          window.location.href = redirectUrl;
        }
      } catch (error) {
        if (!isAbortError(error) && active) {
          onError?.(error instanceof Error ? error.message : "Passkey login failed");
        }
      }
    }
    void startConditionalPasskeyLogin();
    return () => {
      active = false;
      abortController.abort();
    };
  }, [enablePasskeyAutofill, onError, onPasskeySuccess, passkeyEndpoints]);
  async function onSubmit(event) {
    event.preventDefault();
    setLoading(true);
    try {
      const result = await postForm(endpoints.login ?? "/login", { email, password, remember }, endpoints.csrfToken);
      if (result.requires_2fa) {
        onTwoFactorRequired?.(result);
        if (!onTwoFactorRequired && typeof result.attempt_token === "string") {
          window.location.href = `/login/two-factor/${encodeURIComponent(result.attempt_token)}`;
        }
        return;
      }
      onSuccess?.(result);
      if (!onSuccess && result.redirect) window.location.href = result.redirect;
    } catch (error) {
      onError?.(error instanceof Error ? error.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }
  return /* @__PURE__ */ jsxs2(Card, { children: [
    /* @__PURE__ */ jsx2(CardHeader, { children: /* @__PURE__ */ jsx2(CardTitle, { children: "Sign In" }) }),
    /* @__PURE__ */ jsxs2(CardContent, { children: [
      /* @__PURE__ */ jsxs2("form", { className: "space-y-4", onSubmit: (event) => void onSubmit(event), children: [
        /* @__PURE__ */ jsxs2("div", { className: "space-y-1", children: [
          /* @__PURE__ */ jsx2(Label, { htmlFor: "login-email", children: "Email" }),
          /* @__PURE__ */ jsx2(Input, { id: "login-email", type: "email", autoComplete: conditionalPasskeyAvailable ? "username webauthn" : "email", required: true, value: email, onChange: (event) => setEmail(event.target.value) })
        ] }),
        /* @__PURE__ */ jsxs2("div", { className: "space-y-1", children: [
          /* @__PURE__ */ jsx2(Label, { htmlFor: "login-password", children: "Password" }),
          /* @__PURE__ */ jsx2(Input, { id: "login-password", type: "password", autoComplete: "current-password", required: true, value: password, onChange: (event) => setPassword(event.target.value) })
        ] }),
        /* @__PURE__ */ jsxs2("label", { className: "flex items-center gap-2 text-sm", children: [
          /* @__PURE__ */ jsx2("input", { type: "checkbox", checked: remember, onChange: (event) => setRemember(event.target.checked) }),
          "Keep me signed in"
        ] }),
        /* @__PURE__ */ jsx2(Button, { type: "submit", className: "w-full", disabled: loading, children: loading ? "Signing in..." : "Sign In" })
      ] }),
      enablePasskeys ? /* @__PURE__ */ jsx2("div", { className: "mt-4", children: /* @__PURE__ */ jsx2(
        PasskeyLoginButton,
        {
          components: { Button },
          endpoints,
          onSuccess: (redirectUrl, result) => {
            if (onPasskeySuccess) {
              onPasskeySuccess(redirectUrl, result);
            } else {
              window.location.href = redirectUrl;
            }
          },
          onError
        }
      ) }) : null
    ] })
  ] });
}
function defaultSignupFields() {
  return [
    { name: "name", label: "Name", required: true, autoComplete: "name" },
    { name: "email", label: "Email", type: "email", required: true, autoComplete: "email" },
    { name: "password", label: "Password", type: "password", required: true, autoComplete: "new-password" },
    { name: "password_confirmation", label: "Confirm Password", type: "password", required: true, autoComplete: "new-password" }
  ];
}
function initialSignupValue(field, initialValues) {
  if (Object.prototype.hasOwnProperty.call(initialValues, field.name)) return initialValues[field.name];
  if (field.initialValue !== void 0) return field.initialValue;
  return field.type === "checkbox" ? false : "";
}
function SignupForm({
  endpoints = {},
  components,
  onSuccess,
  onError,
  fields = defaultSignupFields(),
  initialValues = {},
  errors = {},
  submitMode = "fetch",
  title = "Create Account",
  description,
  submitLabel = "Create Account",
  submittingLabel = "Creating account..."
}) {
  const { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Label } = resolveAuthComponents(components);
  const [values, setValues] = React2.useState(() => Object.fromEntries(
    fields.map((field) => [field.name, initialSignupValue(field, initialValues)])
  ));
  const [fieldErrors, setFieldErrors] = React2.useState(errors);
  const [loading, setLoading] = React2.useState(false);
  async function onSubmit(event) {
    setLoading(true);
    if (submitMode === "native") {
      return;
    }
    event.preventDefault();
    setFieldErrors({});
    try {
      const result = await postForm(endpoints.signup ?? "/register", values, endpoints.csrfToken);
      await onSuccess?.(result, values);
      if (!onSuccess && result.redirect) window.location.href = result.redirect;
    } catch (error) {
      if (error instanceof AuthRequestError && error.result.errors && typeof error.result.errors === "object") {
        setFieldErrors(error.result.errors);
      }
      onError?.(error instanceof Error ? error.message : "Signup failed");
    } finally {
      setLoading(false);
    }
  }
  function setValue(name, value) {
    setValues((current) => ({ ...current, [name]: value }));
  }
  return /* @__PURE__ */ jsxs2(Card, { children: [
    /* @__PURE__ */ jsxs2(CardHeader, { children: [
      /* @__PURE__ */ jsx2(CardTitle, { children: title }),
      description ? /* @__PURE__ */ jsx2(CardDescription, { children: description }) : null
    ] }),
    /* @__PURE__ */ jsx2(CardContent, { children: /* @__PURE__ */ jsxs2("form", { className: "space-y-4", method: submitMode === "native" ? "POST" : void 0, action: endpoints.signup ?? "/register", onSubmit: (event) => void onSubmit(event), children: [
      submitMode === "native" ? /* @__PURE__ */ jsx2("input", { type: "hidden", name: "_token", value: getCsrfToken(endpoints.csrfToken) }) : null,
      fields.map((field) => {
        if (field.hiddenWhen?.(values)) return null;
        const error = fieldErrors[field.name]?.[0];
        const value = values[field.name];
        if (field.type === "checkbox") {
          return /* @__PURE__ */ jsxs2("div", { className: field.containerClassName ?? "space-y-1", children: [
            /* @__PURE__ */ jsxs2("label", { className: "flex items-start gap-2 text-sm", children: [
              /* @__PURE__ */ jsx2(
                "input",
                {
                  id: `signup-${field.name}`,
                  name: field.name,
                  type: "checkbox",
                  value: "1",
                  checked: Boolean(value),
                  onChange: (event) => setValue(field.name, event.target.checked),
                  required: field.required
                }
              ),
              /* @__PURE__ */ jsx2("span", { children: field.label })
            ] }),
            field.helpText ? /* @__PURE__ */ jsx2("p", { className: "text-xs text-muted-foreground", children: field.helpText }) : null,
            error ? /* @__PURE__ */ jsx2("p", { className: "text-sm text-destructive", children: error }) : null
          ] }, field.name);
        }
        return /* @__PURE__ */ jsxs2("div", { className: field.containerClassName ?? "space-y-1", children: [
          /* @__PURE__ */ jsx2(Label, { htmlFor: `signup-${field.name}`, children: field.label }),
          /* @__PURE__ */ jsx2(
            Input,
            {
              id: `signup-${field.name}`,
              name: field.name,
              type: field.type ?? "text",
              placeholder: field.placeholder,
              required: field.required,
              autoComplete: field.autoComplete,
              minLength: field.minLength,
              maxLength: field.maxLength,
              pattern: field.pattern,
              inputMode: field.inputMode,
              className: field.className,
              "aria-invalid": Boolean(error),
              value: String(value ?? ""),
              onChange: (event) => setValue(field.name, event.target.value)
            }
          ),
          field.helpText ? /* @__PURE__ */ jsx2("p", { className: "text-xs text-muted-foreground", children: field.helpText }) : null,
          error ? /* @__PURE__ */ jsx2("p", { className: "text-sm text-destructive", children: error }) : null
        ] }, field.name);
      }),
      /* @__PURE__ */ jsx2(Button, { type: "submit", className: "w-full", disabled: loading, children: loading ? submittingLabel : submitLabel })
    ] }) })
  ] });
}
function PasswordResetRequestForm({ endpoints = {}, components, onSuccess, onError }) {
  const { Button, Input, Label } = resolveAuthComponents(components);
  const [email, setEmail] = React2.useState("");
  const [loading, setLoading] = React2.useState(false);
  async function onSubmit(event) {
    event.preventDefault();
    setLoading(true);
    try {
      const result = await postForm(endpoints.forgotPassword ?? "/api/auth/forgot-password", { email }, endpoints.csrfToken);
      onSuccess?.(result);
    } catch (error) {
      onError?.(error instanceof Error ? error.message : "Password reset request failed");
    } finally {
      setLoading(false);
    }
  }
  return /* @__PURE__ */ jsxs2("form", { className: "space-y-4", onSubmit: (event) => void onSubmit(event), children: [
    /* @__PURE__ */ jsxs2("div", { className: "space-y-1", children: [
      /* @__PURE__ */ jsx2(Label, { htmlFor: "reset-email", children: "Email" }),
      /* @__PURE__ */ jsx2(Input, { id: "reset-email", type: "email", autoComplete: "email", required: true, value: email, onChange: (event) => setEmail(event.target.value) })
    ] }),
    /* @__PURE__ */ jsx2(Button, { type: "submit", disabled: loading, children: loading ? "Sending..." : "Send Reset Link" })
  ] });
}
function ResetPasswordForm({ endpoints = {}, components, onSuccess, onError, token: initialToken = "", email: initialEmail = "" }) {
  const { Button, Input, Label } = resolveAuthComponents(components);
  const [email, setEmail] = React2.useState(initialEmail);
  const [token, setToken] = React2.useState(initialToken);
  const [password, setPassword] = React2.useState("");
  const [passwordConfirmation, setPasswordConfirmation] = React2.useState("");
  async function onSubmit(event) {
    event.preventDefault();
    try {
      const result = await postForm(endpoints.resetPassword ?? "/api/auth/reset-password", {
        email,
        token,
        password,
        password_confirmation: passwordConfirmation
      }, endpoints.csrfToken);
      onSuccess?.(result);
    } catch (error) {
      onError?.(error instanceof Error ? error.message : "Password reset failed");
    }
  }
  return /* @__PURE__ */ jsxs2("form", { className: "space-y-4", onSubmit: (event) => void onSubmit(event), children: [
    /* @__PURE__ */ jsx2(Input, { type: "hidden", value: token, onChange: (event) => setToken(event.target.value) }),
    /* @__PURE__ */ jsxs2("div", { className: "space-y-1", children: [
      /* @__PURE__ */ jsx2(Label, { htmlFor: "reset-password-email", children: "Email" }),
      /* @__PURE__ */ jsx2(Input, { id: "reset-password-email", type: "email", required: true, value: email, onChange: (event) => setEmail(event.target.value) })
    ] }),
    /* @__PURE__ */ jsxs2("div", { className: "space-y-1", children: [
      /* @__PURE__ */ jsx2(Label, { htmlFor: "reset-password", children: "Password" }),
      /* @__PURE__ */ jsx2(Input, { id: "reset-password", type: "password", required: true, value: password, onChange: (event) => setPassword(event.target.value) })
    ] }),
    /* @__PURE__ */ jsxs2("div", { className: "space-y-1", children: [
      /* @__PURE__ */ jsx2(Label, { htmlFor: "reset-password-confirmation", children: "Confirm Password" }),
      /* @__PURE__ */ jsx2(Input, { id: "reset-password-confirmation", type: "password", required: true, value: passwordConfirmation, onChange: (event) => setPasswordConfirmation(event.target.value) })
    ] }),
    /* @__PURE__ */ jsx2(Button, { type: "submit", children: "Reset Password" })
  ] });
}
function ChangePasswordForm({ endpoints = {}, components, onSuccess, onError }) {
  const { Button, Input, Label } = resolveAuthComponents(components);
  const [currentPassword, setCurrentPassword] = React2.useState("");
  const [password, setPassword] = React2.useState("");
  const [passwordConfirmation, setPasswordConfirmation] = React2.useState("");
  const [loading, setLoading] = React2.useState(false);
  async function onSubmit(event) {
    event.preventDefault();
    setLoading(true);
    if (password !== passwordConfirmation) {
      onError?.("New passwords do not match.");
      setLoading(false);
      return;
    }
    try {
      const result = await postForm(endpoints.changePassword ?? "/api/change-password", {
        current_password: currentPassword,
        password,
        password_confirmation: passwordConfirmation
      }, endpoints.csrfToken);
      setCurrentPassword("");
      setPassword("");
      setPasswordConfirmation("");
      onSuccess?.(result);
    } catch (error) {
      onError?.(error instanceof Error ? error.message : "Password change failed");
    } finally {
      setLoading(false);
    }
  }
  return /* @__PURE__ */ jsxs2("form", { className: "space-y-4", onSubmit: (event) => void onSubmit(event), children: [
    /* @__PURE__ */ jsxs2("div", { className: "space-y-1", children: [
      /* @__PURE__ */ jsx2(Label, { htmlFor: "current-password", children: "Current Password" }),
      /* @__PURE__ */ jsx2(Input, { id: "current-password", type: "password", autoComplete: "current-password", required: true, value: currentPassword, onChange: (event) => setCurrentPassword(event.target.value) })
    ] }),
    /* @__PURE__ */ jsxs2("div", { className: "space-y-1", children: [
      /* @__PURE__ */ jsx2(Label, { htmlFor: "new-password", children: "New Password" }),
      /* @__PURE__ */ jsx2(Input, { id: "new-password", type: "password", autoComplete: "new-password", minLength: 8, required: true, value: password, onChange: (event) => setPassword(event.target.value) })
    ] }),
    /* @__PURE__ */ jsxs2("div", { className: "space-y-1", children: [
      /* @__PURE__ */ jsx2(Label, { htmlFor: "confirm-password", children: "Confirm New Password" }),
      /* @__PURE__ */ jsx2(Input, { id: "confirm-password", type: "password", autoComplete: "new-password", minLength: 8, required: true, value: passwordConfirmation, onChange: (event) => setPasswordConfirmation(event.target.value) })
    ] }),
    /* @__PURE__ */ jsx2(Button, { type: "submit", disabled: loading, children: loading ? "Changing..." : "Change Password" })
  ] });
}
function TwoFactorForm({ endpoints = {}, components, attemptToken, appEnv, onSuccess, onError, onReportSuspicious }) {
  const { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Label } = resolveAuthComponents(components);
  const [currentAttemptToken, setCurrentAttemptToken] = React2.useState(attemptToken);
  const [code, setCode] = React2.useState("");
  const [loading, setLoading] = React2.useState(false);
  const [resending, setResending] = React2.useState(false);
  const [message, setMessage] = React2.useState("");
  React2.useEffect(() => setCurrentAttemptToken(attemptToken), [attemptToken]);
  async function onSubmit(event) {
    event.preventDefault();
    setLoading(true);
    setMessage("");
    try {
      const result = await postForm(endpoints.twoFactorVerify ?? "/api/auth/two-factor/verify", {
        attempt_token: currentAttemptToken,
        code: code.trim()
      }, endpoints.csrfToken);
      onSuccess?.(result);
      if (!onSuccess && result.redirect) window.location.href = result.redirect;
    } catch (error) {
      setCode("");
      onError?.(error instanceof Error ? error.message : "Verification failed");
    } finally {
      setLoading(false);
    }
  }
  async function resend() {
    setResending(true);
    setMessage("");
    try {
      const result = await postForm(endpoints.twoFactorResend ?? "/api/auth/two-factor/resend", {
        attempt_token: currentAttemptToken
      }, endpoints.csrfToken);
      if (typeof result.attempt_token === "string") setCurrentAttemptToken(result.attempt_token);
      setMessage(result.message ?? "A new verification code has been sent.");
    } catch (error) {
      onError?.(error instanceof Error ? error.message : "Could not resend verification code");
    } finally {
      setResending(false);
    }
  }
  async function reportSuspicious() {
    const url = endpoints.twoFactorReport?.(currentAttemptToken) ?? `/api/auth/two-factor/report/${encodeURIComponent(currentAttemptToken)}`;
    try {
      const result = await postForm(url, {}, endpoints.csrfToken);
      setMessage(result.message ?? "This login attempt has been reported.");
      onReportSuspicious?.(result);
    } catch (error) {
      onError?.(error instanceof Error ? error.message : "Could not report the login attempt");
    }
  }
  return /* @__PURE__ */ jsxs2(Card, { children: [
    /* @__PURE__ */ jsxs2(CardHeader, { children: [
      /* @__PURE__ */ jsx2(CardTitle, { children: "Verify Your Login" }),
      /* @__PURE__ */ jsx2(CardDescription, { children: "Enter the 6-digit code sent to your email address." })
    ] }),
    /* @__PURE__ */ jsxs2(CardContent, { children: [
      /* @__PURE__ */ jsxs2("form", { className: "space-y-4", onSubmit: (event) => void onSubmit(event), children: [
        /* @__PURE__ */ jsxs2("div", { className: "space-y-1", children: [
          /* @__PURE__ */ jsx2(Label, { htmlFor: "two-factor-code", children: "Verification Code" }),
          /* @__PURE__ */ jsx2(
            Input,
            {
              id: "two-factor-code",
              type: "text",
              inputMode: "numeric",
              pattern: "[0-9]{6}",
              maxLength: 6,
              autoComplete: "one-time-code",
              required: true,
              value: code,
              onChange: (event) => setCode(event.target.value.replace(/\D/g, ""))
            }
          )
        ] }),
        /* @__PURE__ */ jsx2(Button, { type: "submit", className: "w-full", disabled: loading || code.length !== 6, children: loading ? "Verifying..." : "Verify Code" })
      ] }),
      /* @__PURE__ */ jsxs2("div", { className: "mt-4 space-y-2 text-sm", children: [
        /* @__PURE__ */ jsx2(Button, { type: "button", variant: "outline", className: "w-full", disabled: resending, onClick: () => void resend(), children: resending ? "Sending..." : "Send a new code" }),
        /* @__PURE__ */ jsx2("button", { type: "button", className: "text-sm underline", onClick: () => void reportSuspicious(), children: "This was not me" }),
        message ? /* @__PURE__ */ jsx2("p", { children: message }) : null,
        appEnv && appEnv !== "production" ? /* @__PURE__ */ jsx2("p", { children: "Dev mode: use 999999 to bypass 2FA." }) : null
      ] })
    ] })
  ] });
}

// src/passkey-section.tsx
import { Key, Plus, Trash2 } from "lucide-react";
import * as React3 from "react";
import { flushSync } from "react-dom";
import { jsx as jsx3, jsxs as jsxs3 } from "react/jsx-runtime";
function PasskeySection({ endpoints = {}, components, onSuccess, onError }) {
  const { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Input, Label } = resolveAuthComponents(components);
  const [passkeys, setPasskeys] = React3.useState([]);
  const [loading, setLoading] = React3.useState(true);
  const [registering, setRegistering] = React3.useState(false);
  const [pendingName, setPendingName] = React3.useState("");
  const listUrl = endpoints.passkeyList ?? "/api/passkeys";
  const registerOptionsUrl = endpoints.passkeyRegisterOptions ?? "/api/passkeys/register/options";
  const registerUrl = endpoints.passkeyRegister ?? "/api/passkeys/register";
  const deleteUrl = endpoints.passkeyDelete ?? ((id) => `/api/passkeys/${id}`);
  const fetchPasskeys = React3.useCallback(async () => {
    try {
      const res = await fetch(listUrl);
      if (res.ok) {
        setPasskeys(await res.json());
      }
    } catch {
      onError?.("passkeys", "Failed to load passkeys");
    } finally {
      setLoading(false);
    }
  }, [listUrl, onError]);
  React3.useEffect(() => {
    void fetchPasskeys();
  }, [fetchPasskeys]);
  async function registerPasskey2() {
    const name = pendingName || getDefaultPasskeyName();
    flushSync(() => setPendingName(name));
    setRegistering(true);
    try {
      await registerPasskey({ endpoints: { ...endpoints, passkeyRegisterOptions: registerOptionsUrl, passkeyRegister: registerUrl }, name });
      setPendingName("");
      onSuccess?.("Passkey registered successfully.");
      await fetchPasskeys();
    } catch (caughtError) {
      if (!isAbortError(caughtError)) {
        onError?.("passkeys", caughtError instanceof Error ? caughtError.message : "Passkey registration failed");
      }
    } finally {
      setRegistering(false);
    }
  }
  async function deletePasskey(id) {
    try {
      const res = await fetch(deleteUrl(id), {
        method: "DELETE",
        headers: { "X-CSRF-TOKEN": getCsrfToken(endpoints.csrfToken) }
      });
      if (!res.ok) {
        throw new Error("Delete failed");
      }
      setPasskeys((current) => current.filter((passkey) => passkey.id !== id));
      onSuccess?.("Passkey removed.");
    } catch {
      onError?.("passkeys", "Failed to delete passkey");
    }
  }
  const isWebAuthnSupported = typeof window !== "undefined" && !!window.PublicKeyCredential;
  return /* @__PURE__ */ jsxs3(Card, { children: [
    /* @__PURE__ */ jsxs3(CardHeader, { children: [
      /* @__PURE__ */ jsxs3(CardTitle, { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsx3(Key, { className: "h-5 w-5" }),
        "Passkeys"
      ] }),
      /* @__PURE__ */ jsx3(CardDescription, { children: "Manage passkeys for passwordless login." })
    ] }),
    /* @__PURE__ */ jsxs3(CardContent, { className: "space-y-4", children: [
      !isWebAuthnSupported ? /* @__PURE__ */ jsx3("p", { className: "text-sm text-muted-foreground", children: "Your browser does not support passkeys." }) : null,
      loading ? /* @__PURE__ */ jsx3("p", { className: "text-sm text-muted-foreground", children: "Loading passkeys..." }) : passkeys.length === 0 ? /* @__PURE__ */ jsx3("p", { className: "text-sm text-muted-foreground", children: "No passkeys registered yet." }) : /* @__PURE__ */ jsx3("div", { className: "divide-y rounded-md border", children: passkeys.map((passkey) => /* @__PURE__ */ jsxs3("div", { className: "flex items-center justify-between gap-3 p-3", children: [
        /* @__PURE__ */ jsxs3("div", { children: [
          /* @__PURE__ */ jsx3("div", { className: "font-medium", children: passkey.name }),
          /* @__PURE__ */ jsx3("div", { className: "text-sm text-muted-foreground", children: new Date(passkey.created_at).toLocaleDateString() })
        ] }),
        /* @__PURE__ */ jsx3(Button, { type: "button", variant: "ghost", size: "icon", "aria-label": "Delete passkey", onClick: () => void deletePasskey(passkey.id), children: /* @__PURE__ */ jsx3(Trash2, {}) })
      ] }, passkey.id)) }),
      isWebAuthnSupported ? /* @__PURE__ */ jsxs3("div", { className: "flex flex-col gap-2 sm:flex-row", children: [
        /* @__PURE__ */ jsxs3("div", { className: "flex-1 space-y-1", children: [
          /* @__PURE__ */ jsx3(Label, { htmlFor: "passkey-name", children: "Passkey name" }),
          /* @__PURE__ */ jsx3(Input, { id: "passkey-name", value: pendingName, onChange: (event) => setPendingName(event.target.value), placeholder: getDefaultPasskeyName() })
        ] }),
        /* @__PURE__ */ jsxs3(Button, { type: "button", className: "self-end", variant: "outline", disabled: registering, onClick: () => void registerPasskey2(), children: [
          /* @__PURE__ */ jsx3(Plus, {}),
          registering ? "Registering..." : "Add Passkey"
        ] })
      ] }) : null
    ] })
  ] });
}
export {
  ChangePasswordForm,
  LoginForm,
  PasskeyLoginButton,
  PasskeySection,
  PasswordResetRequestForm,
  ResetPasswordForm,
  SignupForm,
  TwoFactorForm,
  arrayBufferToBase64url,
  authenticateWithPasskey,
  base64urlToArrayBuffer,
  getCsrfToken,
  getDefaultPasskeyName,
  isAbortError,
  isConditionalMediationAvailable,
  registerPasskey
};
