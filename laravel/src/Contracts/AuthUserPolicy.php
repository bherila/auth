<?php

namespace BWH\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

interface AuthUserPolicy
{
    public function canPasskeyLogin(Authenticatable $user, Request $request): bool;

    public function redirectAfterLogin(Authenticatable $user, Request $request): string;
}
