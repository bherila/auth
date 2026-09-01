<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Contracts\AuthUserPolicy;
use BWH\Auth\Mail\PasswordResetConfirmationMail;
use BWH\Auth\Mail\PasswordResetNoticeMail;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\PasswordResetLinkSent;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Validation\Rules\Password as PasswordRule;

class PasswordResetController extends Controller
{
    public function __construct(
        private readonly AuthAuditLogger $auditLogger,
        private readonly AuthUserPolicy $userPolicy,
    ) {}

    public function sendResetLink(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'email'],
        ]);

        // Go through the broker rather than looking the user up and calling createToken()
        // directly. The broker wraps the whole operation in a timebox and refuses to issue
        // a token when one was created too recently, so this endpoint keeps the framework's
        // reset throttling and constant-time behaviour instead of bypassing both.
        Password::broker()->sendResetLink($validated, function ($user, string $token) use ($request): void {
            $emailAttribute = config('bherila-auth.users.email_attribute', 'email');
            $email = data_get($user, $emailAttribute);
            $resetUrl = $this->resetUrl($token, (string) $email);

            Mail::to($email)->send(new PasswordResetConfirmationMail($user, $resetUrl, config('app.name', 'Application')));

            if ($user instanceof Authenticatable) {
                $this->auditLogger->passwordResetRequested($request, $user);
            }

            // The broker only dispatches this itself when it sends the notification,
            // which a custom callback replaces.
            event(new PasswordResetLinkSent($user));
        });

        // Deliberately the same response for a sent link, an unknown address, and a
        // throttled request, so the endpoint cannot be used to enumerate accounts.
        return response()->json([
            'success' => true,
            'message' => 'If an account exists with this email, a password reset link has been sent.',
        ]);
    }

    public function reset(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'token' => ['required', 'string'],
            'email' => ['required', 'email'],
            'password' => ['required', 'confirmed', PasswordRule::defaults()],
        ]);

        $resetUser = null;
        $status = Password::broker()->reset($validated, function ($user, string $password) use (&$resetUser): void {
            $attributes = [
                'password' => Hash::make($password),
                'remember_token' => Str::random(60),
            ];

            $forceChangeAttribute = config('bherila-auth.users.force_change_password_attribute');
            if (is_string($forceChangeAttribute) && $forceChangeAttribute !== '' && $this->modelHasColumn($user, $forceChangeAttribute)) {
                $attributes[$forceChangeAttribute] = false;
            }

            if ((bool) config('bherila-auth.password_resets.verify_email_on_reset', false)
                && $user instanceof MustVerifyEmail
                && ! $user->hasVerifiedEmail()
                && $this->modelHasColumn($user, 'email_verified_at')) {
                $attributes['email_verified_at'] = now();
            }

            $user->forceFill($attributes)->save();

            $resetUser = $user;
        });

        if ($status !== Password::PASSWORD_RESET) {
            return response()->json([
                'success' => false,
                'message' => __($status),
            ], 422);
        }

        $redirect = config('bherila-auth.password_resets.redirect_after_reset', '/');

        if ($resetUser instanceof Authenticatable) {
            $appName = config('app.name', 'Application');
            $emailAttribute = config('bherila-auth.users.email_attribute', 'email');

            Mail::to(data_get($resetUser, $emailAttribute))->send(new PasswordResetNoticeMail($resetUser, $appName));
            $this->auditLogger->passwordResetCompleted($request, $resetUser);
            event(new PasswordReset($resetUser));

            // The reset itself is allowed to finish — a disabled account should still be
            // able to take its password back — but completing one is not a way around
            // canLogin(), which gates every login this package performs.
            if ($this->userPolicy->canLogin($resetUser, $request)) {
                Auth::login($resetUser);
                $request->session()->regenerate();
            } else {
                $redirect = config('bherila-auth.two_factor.login_url', '/login');
            }
        }

        return response()->json([
            'success' => true,
            'message' => __($status),
            'redirect' => $redirect,
        ]);
    }

    private function resetUrl(string $token, string $email): string
    {
        return strtr(config('bherila-auth.password_resets.reset_url'), [
            '{token}' => rawurlencode($token),
            '{email}' => rawurlencode($email),
        ]);
    }

    private function modelHasColumn(mixed $user, string $column): bool
    {
        return $user instanceof Model
            && $user->getConnection()->getSchemaBuilder()->hasColumn($user->getTable(), $column);
    }
}
