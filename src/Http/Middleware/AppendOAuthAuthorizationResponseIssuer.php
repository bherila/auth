<?php

namespace BWH\Auth\Http\Middleware;

use BWH\Auth\OAuth\Server\OAuthAuthorizationResponseIssuer;
use Closure;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Install on Passport authorization and consent routes when RFC 9207 is enabled.
 */
final class AppendOAuthAuthorizationResponseIssuer
{
    public function handle(Request $request, Closure $next): Response
    {
        try {
            return OAuthAuthorizationResponseIssuer::decorate($next($request));
        } catch (HttpResponseException $exception) {
            // Passport turns OAuth validation failures into HttpResponseException
            // before the route middleware can receive a normal response.
            return OAuthAuthorizationResponseIssuer::decorate($exception->getResponse());
        }
    }
}
