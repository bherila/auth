<?php

namespace BWH\Auth\OAuth\Server;

use Illuminate\Http\JsonResponse;

/**
 * RFC 9728 protected-resource metadata and RFC 6750 bearer challenges.
 *
 * Route registration remains an application concern because the metadata URI
 * normally includes the concrete MCP endpoint path.
 */
final class OAuthProtectedResource
{
    /** @return array<string, mixed> */
    public static function metadata(?array $supportedScopes = null): array
    {
        $metadata = [
            'resource' => OAuthResourceIndicator::resource(),
            'authorization_servers' => [OAuthResourceIndicator::issuer()],
            'scopes_supported' => self::scopes($supportedScopes),
            'bearer_methods_supported' => ['header'],
        ];

        return $metadata;
    }

    public static function metadataResponse(?array $supportedScopes = null): JsonResponse
    {
        return response()->json(self::metadata($supportedScopes))->withHeaders([
            'Cache-Control' => 'public, max-age=300',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }

    /**
     * Return the exact metadata URI that should be put in a bearer challenge.
     * Applications serving multiple resources should configure this per route.
     */
    public static function metadataUrl(): ?string
    {
        $url = config('bherila-auth.oauth_server.protected_resource_metadata_url');
        if ($url !== null) {
            return OAuthResourceIndicator::absoluteHttpUrl($url);
        }

        $resource = OAuthResourceIndicator::resource();
        try {
            $parts = parse_url($resource);
        } catch (\ValueError) {
            return null;
        }
        if (! is_array($parts)
            || ! isset($parts['scheme'], $parts['host'])
            || ! in_array(strtolower((string) $parts['scheme']), ['http', 'https'], true)) {
            return null;
        }

        $port = isset($parts['port']) ? ':'.(int) $parts['port'] : '';
        $path = (string) ($parts['path'] ?? '');

        return "{$parts['scheme']}://{$parts['host']}{$port}/.well-known/oauth-protected-resource".$path;
    }

    /**
     * Build a standards-compatible Bearer challenge. Values are quoted and escaped
     * rather than emitted with http_build_query, which uses the wrong grammar here.
     *
     * @param  list<string>  $scopes
     * @param  array<string, string>  $extraParameters
     */
    public static function bearerChallenge(
        ?string $error = null,
        ?string $errorDescription = null,
        array $scopes = [],
        array $extraParameters = [],
    ): string {
        $parameters = [];
        if (is_string($error) && ($error = self::headerValue($error)) !== '') {
            $parameters['error'] = $error;
        }
        if (is_string($errorDescription)
            && ($errorDescription = self::headerValue($errorDescription)) !== '') {
            $parameters['error_description'] = $errorDescription;
        }
        $scopes = array_values(array_filter(
            OAuthResourceIndicator::scopeIdentifiers($scopes),
            static fn (string $scope): bool => preg_match(
                '/^[\x21\x23-\x5B\x5D-\x7E]+$/D',
                $scope,
            ) === 1,
        ));
        if ($scopes !== []) {
            $parameters['scope'] = implode(' ', $scopes);
        }
        if (($metadataUrl = self::metadataUrl()) !== null) {
            $parameters['resource_metadata'] = $metadataUrl;
        }
        foreach ($extraParameters as $name => $value) {
            if (is_string($name)
                && preg_match("/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/D", $name) === 1
                && is_string($value)
                && ($value = self::headerValue($value)) !== ''
                && ! array_key_exists($name, $parameters)) {
                $parameters[$name] = $value;
            }
        }

        if ($parameters === []) {
            return 'Bearer';
        }

        return 'Bearer '.collect($parameters)
            ->map(fn (string $value, string $name): string => $name.'='.self::quoted($value))
            ->implode(', ');
    }

    /** @param list<string> $scopes */
    public static function unauthorizedResponse(
        ?string $error = 'invalid_token',
        ?string $errorDescription = null,
        array $scopes = [],
    ): JsonResponse {
        return self::challengeResponse(401, $error, $errorDescription, $scopes, [
            'error' => $error ?? 'invalid_token',
        ]);
    }

    /** @param list<string> $scopes */
    public static function insufficientScopeResponse(array $scopes): JsonResponse
    {
        return self::challengeResponse(403, 'insufficient_scope', null, $scopes, [
            'error' => 'insufficient_scope',
        ]);
    }

    /** @param list<string> $scopes @param array<string, mixed> $body */
    private static function challengeResponse(
        int $status,
        ?string $error,
        ?string $errorDescription,
        array $scopes,
        array $body,
    ): JsonResponse {
        return response()->json($body, $status, [
            'Cache-Control' => 'private, no-store',
            'Pragma' => 'no-cache',
            'WWW-Authenticate' => self::bearerChallenge($error, $errorDescription, $scopes),
        ]);
    }

    private static function quoted(string $value): string
    {
        return '"'.addcslashes($value, "\\\"").'"';
    }

    private static function headerValue(string $value): string
    {
        return preg_replace('/[\x00-\x1F\x7F]/', '', $value) ?? '';
    }

    /** @return list<string> */
    private static function scopes(?array $supportedScopes = null): array
    {
        if ($supportedScopes === null) {
            $supportedScopes = config('bherila-auth.oauth_server.protected_resource_scopes');
        }
        $scopes = $supportedScopes ?? config('bherila-auth.oauth_server.scopes', []);
        if (! is_array($scopes)) {
            return [];
        }

        $scopes = array_is_list($scopes) ? $scopes : array_keys($scopes);

        return array_values(array_unique(array_filter(
            $scopes,
            static fn (mixed $scope): bool => is_string($scope) && $scope !== '',
        )));
    }
}
