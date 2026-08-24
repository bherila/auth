<?php

namespace BWH\Auth\Services;

use BWH\Auth\Contracts\AuthAuditLogger;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

/**
 * No-op base implementation of {@see AuthAuditLogger}.
 *
 * Concrete loggers (e.g. {@see NullAuthAuditLogger}, {@see DatabaseAuthAuditLogger})
 * extend this and override only the events they care about. Providing default
 * no-op bodies here means future additions to the contract do not break existing
 * implementations that extend this class.
 */
abstract class AbstractAuthAuditLogger implements AuthAuditLogger
{
    public function loginSucceeded(Request $request, Authenticatable $user, ?string $method = 'password'): void {}

    public function loginFailed(Request $request, ?Authenticatable $user, ?string $email, string $reason, ?string $method = 'password'): void {}

    public function loggedOut(Request $request, ?Authenticatable $user): void {}

    public function passkeyRegistered(Request $request, Authenticatable $user, object $credential): void {}

    public function passkeyDeleted(Request $request, Authenticatable $user, object $credential): void {}

    public function passkeyLoginSucceeded(Request $request, Authenticatable $user, object $credential): void {}

    public function passkeyLoginFailed(Request $request, ?Authenticatable $user, ?string $credentialId, string $reason): void {}

    public function twoFactorChallengeCreated(Request $request, Authenticatable $user, object $attempt): void {}

    public function twoFactorLoginSucceeded(Request $request, Authenticatable $user, object $attempt): void {}

    public function twoFactorLoginFailed(Request $request, ?Authenticatable $user, ?object $attempt, string $reason): void {}

    public function twoFactorReportedSuspicious(Request $request, Authenticatable $user, object $attempt): void {}

    public function passwordResetRequested(Request $request, Authenticatable $user): void {}

    public function passwordResetCompleted(Request $request, Authenticatable $user): void {}

    public function passwordChanged(Request $request, Authenticatable $user): void {}
}
