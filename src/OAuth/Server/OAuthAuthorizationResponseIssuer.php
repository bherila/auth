<?php

namespace BWH\Auth\OAuth\Server;

use Symfony\Component\HttpFoundation\Response;

/**
 * Adds RFC 9207's `iss` parameter to OAuth authorization success/error redirects.
 */
final class OAuthAuthorizationResponseIssuer
{
    public static function decorate(Response $response): Response
    {
        if (! config('bherila-auth.oauth_server.authorization_response_issuer.enabled', false)
            || $response->isRedirection() === false) {
            return $response;
        }

        $location = $response->headers->get('Location');
        if (! is_string($location) || ! self::isAuthorizationResponse($location)) {
            return $response;
        }

        $issuer = OAuthResourceIndicator::issuer();
        $encodedIssuer = rawurlencode($issuer);
        $fragment = null;
        $fragmentPosition = strpos($location, '#');
        if ($fragmentPosition !== false) {
            $fragment = substr($location, $fragmentPosition + 1);
            $location = substr($location, 0, $fragmentPosition);
        }

        if (self::hasQueryResponseParameter($location)) {
            $location = self::setQueryParameter($location, $encodedIssuer);
        } elseif (is_string($fragment) && self::hasFragmentResponseParameter($fragment)) {
            $fragment = self::setFragmentParameter($fragment, $encodedIssuer);
        } else {
            return $response;
        }

        $response->headers->set(
            'Location',
            $location.(is_string($fragment) ? '#'.$fragment : ''),
        );

        return $response;
    }

    private static function isAuthorizationResponse(string $location): bool
    {
        return self::hasQueryResponseParameter($location)
            || (str_contains($location, '#')
                && self::hasFragmentResponseParameter((string) substr($location, strpos($location, '#') + 1)));
    }

    private static function hasQueryResponseParameter(string $location): bool
    {
        return preg_match('/(?:[?&])(code|error)=[^&#]*/', $location) === 1;
    }

    private static function hasFragmentResponseParameter(string $fragment): bool
    {
        return preg_match('/(?:^|&)(code|error)=[^&]*/', $fragment) === 1;
    }

    private static function setQueryParameter(string $location, string $encodedIssuer): string
    {
        if (preg_match('/([?&])iss=[^&#]*/', $location) === 1) {
            return (string) preg_replace_callback(
                '/([?&])iss=[^&#]*/',
                static fn (array $match): string => $match[1].'iss='.$encodedIssuer,
                $location,
            );
        }

        return $location.(str_contains($location, '?') ? '&' : '?').'iss='.$encodedIssuer;
    }

    private static function setFragmentParameter(string $fragment, string $encodedIssuer): string
    {
        if (preg_match('/(^|&)iss=[^&]*/', $fragment) === 1) {
            return (string) preg_replace_callback(
                '/(^|&)iss=[^&]*/',
                static fn (array $match): string => $match[1].'iss='.$encodedIssuer,
                $fragment,
            );
        }

        return $fragment.($fragment === '' ? '' : '&').'iss='.$encodedIssuer;
    }
}
