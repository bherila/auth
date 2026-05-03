<?php

namespace BWH\Auth\Services;

use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Mail\TwoFactorLoginMail;
use BWH\Auth\Models\TwoFactorAttempt;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;

class TwoFactorService
{
    public function __construct(private readonly AuthAuditLogger $auditLogger) {}

    public function startChallenge(Authenticatable $user, Request $request, bool $remember = false): TwoFactorAttempt
    {
        $attempt = TwoFactorAttempt::createForUser($user, $request->ip(), $request->userAgent());

        $request->session()->put(config('bherila-auth.two_factor.session_user_key', 'bherila_auth_2fa_user_id'), $user->getAuthIdentifier());
        $request->session()->put(config('bherila-auth.two_factor.session_remember_key', 'bherila_auth_2fa_remember'), $remember);

        $email = data_get($user, config('bherila-auth.users.email_attribute', 'email'));
        $appName = config('app.name', 'Application');

        Mail::to($email)->send(new TwoFactorLoginMail(
            $user,
            $attempt,
            route('bherila-auth.two-factor.confirm', ['token' => $attempt->token]),
            route('bherila-auth.two-factor.report', ['token' => $attempt->token]),
            $appName,
        ));

        $this->auditLogger->twoFactorChallengeCreated($request, $user, $attempt);

        return $attempt;
    }
}
