<?php

namespace Bherila\AuthLaravel\Services;

use Bherila\AuthLaravel\Contracts\AuthUserPolicy;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

class DefaultAuthUserPolicy implements AuthUserPolicy
{
    public function canPasskeyLogin(Authenticatable $user, Request $request): bool
    {
        if (method_exists($user, 'canLogin')) {
            return (bool) $user->canLogin();
        }

        if (isset($user->is_disabled)) {
            return ! (bool) $user->is_disabled;
        }

        return true;
    }

    public function redirectAfterLogin(Authenticatable $user, Request $request): string
    {
        if (method_exists($user, 'getLoginRedirectUrl')) {
            return (string) $user->getLoginRedirectUrl();
        }

        return $request->session()->pull('url.intended') ?? '/';
    }
}
