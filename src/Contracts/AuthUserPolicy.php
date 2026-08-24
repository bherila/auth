<?php

namespace BWH\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

interface AuthUserPolicy
{
    /**
     * Whether the user is allowed to complete any login (active, not disabled, approved, etc.).
     *
     * The package's own middleware ({@see \BWH\Auth\Http\Middleware\RequireActiveUser}) calls
     * this before serving audit-log endpoints. Implementing apps must also call it from their
     * primary password-login controller and from any post-email-verification redirect.
     *
     * The default implementation duck-types `$user->canLogin()`, then falls back to checking
     * `$user->is_disabled`. If neither exists the user is assumed to be allowed.
     */
    public function canLogin(Authenticatable $user, Request $request): bool;

    public function canPasskeyLogin(Authenticatable $user, Request $request): bool;

    public function redirectAfterLogin(Authenticatable $user, Request $request): string;
}
