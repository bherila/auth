<?php

namespace BWH\Auth\Concerns;

use BWH\Auth\Contracts\AuthAuditLogger;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

/**
 * Convenience helpers for consuming apps whose own login controllers need to
 * record primary login/logout audit events through the shared contract.
 *
 * The bound {@see AuthAuditLogger} decides where events go (a database row via
 * DatabaseAuthAuditLogger, nothing via NullAuthAuditLogger, or an app override).
 */
trait LogsAuthEvents
{
    protected function authAuditLogger(): AuthAuditLogger
    {
        return app(AuthAuditLogger::class);
    }

    protected function auditLoginSucceeded(Request $request, Authenticatable $user, ?string $method = 'password'): void
    {
        $this->authAuditLogger()->loginSucceeded($request, $user, $method);
    }

    protected function auditLoginFailed(Request $request, ?Authenticatable $user, ?string $email, string $reason, ?string $method = 'password'): void
    {
        $this->authAuditLogger()->loginFailed($request, $user, $email, $reason, $method);
    }

    protected function auditLoggedOut(Request $request, ?Authenticatable $user): void
    {
        $this->authAuditLogger()->loggedOut($request, $user);
    }
}
