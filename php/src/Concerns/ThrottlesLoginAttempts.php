<?php

namespace BWH\Auth\Concerns;

use BWH\Auth\Contracts\LoginThrottle;
use BWH\Auth\Support\LoginThrottleState;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

trait ThrottlesLoginAttempts
{
    protected function loginThrottle(): LoginThrottle
    {
        return app(LoginThrottle::class);
    }

    protected function inspectLoginThrottle(Request $request, ?Authenticatable $user = null, ?string $email = null, ?string $method = 'password'): LoginThrottleState
    {
        return $this->loginThrottle()->inspect($request, $user, $email, $method);
    }

    protected function auditLoginBlocked(Request $request, ?Authenticatable $user = null, ?string $email = null, ?string $method = 'password', ?LoginThrottleState $state = null): void
    {
        $this->loginThrottle()->recordBlocked($request, $user, $email, $method, $state);
    }
}
