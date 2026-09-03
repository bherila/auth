<?php

namespace BWH\Auth\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/** Make an application-owned OAuth route honor the package's opt-in switch. */
final class EnsureOAuthServerEnabled
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! (bool) config('bherila-auth.oauth_server.enabled', false)) {
            return new JsonResponse(['error' => 'not_found'], 404, [
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
                'X-Content-Type-Options' => 'nosniff',
            ]);
        }

        return $next($request);
    }
}
