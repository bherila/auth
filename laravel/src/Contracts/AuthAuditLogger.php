<?php

namespace BWH\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

interface AuthAuditLogger
{
    public function loginSucceeded(Request $request, Authenticatable $user, ?string $method = 'password'): void;

    public function loginFailed(Request $request, ?Authenticatable $user, ?string $email, string $reason, ?string $method = 'password'): void;

    public function loggedOut(Request $request, ?Authenticatable $user): void;

    public function passkeyRegistered(Request $request, Authenticatable $user, object $credential): void;

    public function passkeyDeleted(Request $request, Authenticatable $user, object $credential): void;

    public function passkeyLoginSucceeded(Request $request, Authenticatable $user, object $credential): void;

    public function passkeyLoginFailed(Request $request, ?Authenticatable $user, ?string $credentialId, string $reason): void;

    public function twoFactorChallengeCreated(Request $request, Authenticatable $user, object $attempt): void;

    public function twoFactorLoginSucceeded(Request $request, Authenticatable $user, object $attempt): void;

    public function twoFactorLoginFailed(Request $request, ?Authenticatable $user, ?object $attempt, string $reason): void;

    public function twoFactorReportedSuspicious(Request $request, Authenticatable $user, object $attempt): void;

    public function passwordResetRequested(Request $request, Authenticatable $user): void;

    public function passwordResetCompleted(Request $request, Authenticatable $user): void;

    public function passwordChanged(Request $request, Authenticatable $user): void;
}
