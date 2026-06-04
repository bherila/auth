<?php

namespace BWH\Auth\Contracts;

use BWH\Auth\Support\LoginThrottleState;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

interface LoginThrottle
{
    public function inspect(Request $request, ?Authenticatable $user = null, ?string $email = null, ?string $method = 'password'): LoginThrottleState;

    public function recordBlocked(Request $request, ?Authenticatable $user = null, ?string $email = null, ?string $method = 'password', ?LoginThrottleState $state = null): void;
}
