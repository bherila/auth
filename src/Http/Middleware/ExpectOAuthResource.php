<?php

namespace BWH\Auth\Http\Middleware;

use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/** Establish the audience expected by one protected application route. */
final class ExpectOAuthResource
{
    public function handle(Request $request, Closure $next): Response
    {
        OAuthResourceIndicator::expectConfiguredFor($request);

        return $next($request);
    }
}
