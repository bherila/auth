<?php

namespace BWH\Auth\Http\Controllers;

use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Mail\PasswordResetConfirmationMail;
use BWH\Auth\Mail\PasswordResetNoticeMail;
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
    public function __construct(private readonly AuthAuditLogger $auditLogger) {}

    public function sendResetLink(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'email'],
        ]);

        $model = config('bherila-auth.users.model');
        $emailAttribute = config('bherila-auth.users.email_attribute', 'email');
        $user = $model::query()->where($emailAttribute, $validated['email'])->first();

        if ($user instanceof Authenticatable) {
            $token = Password::broker()->createToken($user);
            $resetUrl = $this->resetUrl($token, (string) data_get($user, $emailAttribute));
            $appName = config('app.name', 'Application');

            Mail::to(data_get($user, $emailAttribute))->send(new PasswordResetConfirmationMail($user, $resetUrl, $appName));
            $this->auditLogger->passwordResetRequested($request, $user);
        }

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

        if ($resetUser instanceof Authenticatable) {
            $appName = config('app.name', 'Application');
            $emailAttribute = config('bherila-auth.users.email_attribute', 'email');

            Mail::to(data_get($resetUser, $emailAttribute))->send(new PasswordResetNoticeMail($resetUser, $appName));
            $this->auditLogger->passwordResetCompleted($request, $resetUser);
            Auth::login($resetUser);
            $request->session()->regenerate();
        }

        return response()->json([
            'success' => true,
            'message' => __($status),
            'redirect' => config('bherila-auth.password_resets.redirect_after_reset', '/'),
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
