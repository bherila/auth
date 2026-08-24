<?php

namespace BWH\Auth\OAuth\Server;

use Illuminate\Http\Request;
use RuntimeException;

final class OAuthResourceIndicator
{
    public const REQUEST_ATTRIBUTE = 'bherila_auth_oauth_resource';

    public static function resource(): string
    {
        $resource = config('bherila-auth.oauth_server.resource');
        if (! is_string($resource) || self::canonicalize($resource) === null) {
            throw new RuntimeException('The OAuth protected resource is not configured.');
        }

        return $resource;
    }

    public static function canonicalize(mixed $value): ?string
    {
        if (! is_string($value) || $value === '' || strlen($value) > 2048) {
            return null;
        }

        $parts = parse_url($value);
        if (! is_array($parts)
            || ! isset($parts['scheme'], $parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])) {
            return null;
        }

        $scheme = strtolower((string) $parts['scheme']);
        $host = strtolower((string) $parts['host']);
        if (! in_array($scheme, ['http', 'https'], true) || $host === '') {
            return null;
        }

        $port = isset($parts['port']) ? ':'.(int) $parts['port'] : '';
        if (($scheme === 'https' && $port === ':443') || ($scheme === 'http' && $port === ':80')) {
            $port = '';
        }

        return "{$scheme}://{$host}{$port}".rtrim((string) ($parts['path'] ?? ''), '/');
    }

    public static function isConfiguredResource(mixed $value): bool
    {
        return self::canonicalize($value) === self::canonicalize(self::resource());
    }

    public static function validatedFor(Request $request): ?string
    {
        $attribute = $request->attributes->get(self::REQUEST_ATTRIBUTE);

        return is_string($attribute) ? $attribute : null;
    }
}
