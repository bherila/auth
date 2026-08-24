<?php

namespace BWH\Auth\Http\Middleware;

use BWH\Auth\Contracts\AuthUserPolicy;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Abort with 403 if the authenticated user is not allowed to log in.
 *
 * Applied automatically to the package's own audit-log routes so that a pending
 * or disabled account cannot reach those endpoints even if the surrounding gate
 * ability only checks admin role without verifying account state.
 *
 * Apps may also apply this middleware to their own authenticated routes:
 *
 * ```php
 * Route::middleware(['auth', \BWH\Auth\Http\Middleware\RequireActiveUser::class])
 *     ->group(function () { ... });
 * ```
 *
 * The check delegates to {@see \BWH\Auth\Contracts\AuthUserPolicy::canLogin()}, which
 * by default duck-types `$user->canLogin()` and falls back to `$user->is_disabled`.
 * Bind a custom AuthUserPolicy to add approved-at, email-verified, or other checks.
 */
class RequireActiveUser
{
    public function __construct(private readonly AuthUserPolicy $policy) {}

    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if ($user === null) {
            // Let the auth middleware handle unauthenticated requests.
            return $next($request);
        }

        if (! $this->policy->canLogin($user, $request)) {
            abort(403, 'Your account is not active.');
        }

        return $next($request);
    }
}
