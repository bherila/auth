<?php

namespace BWH\Auth\OAuth\Introspection;

use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Response;
use Throwable;

final readonly class RemoteOAuthTokenIntrospector implements OAuthTokenIntrospector
{
    public function __construct(private Factory $http) {}

    public function introspect(string $token): IntrospectedToken
    {
        if ($token === '' || strlen($token) > 32_768) {
            return IntrospectedToken::inactive();
        }

        $endpoint = $this->requiredUrlConfig('introspection_endpoint');
        $clientId = $this->requiredStringConfig('client_id', trim: false);
        $clientSecret = $this->requiredStringConfig('client_secret', trim: false);
        $issuer = $this->requiredUrlConfig('issuer');
        $resource = $this->requiredResourceConfig();
        if ($this->origin($endpoint) !== $this->origin($issuer)) {
            throw new OAuthIntrospectionException(
                'The OAuth introspection endpoint must use the authorization server issuer origin.',
            );
        }
        $timeout = max(1, min(30, (int) config(
            'bherila-auth.oauth_resource_server.timeout_seconds',
            5,
        )));

        try {
            $response = $this->http
                ->asForm()
                ->acceptJson()
                ->withBasicAuth(urlencode($clientId), urlencode($clientSecret))
                ->withoutRedirecting()
                ->connectTimeout($timeout)
                ->timeout($timeout)
                ->post($endpoint, [
                    'token' => $token,
                    'token_type_hint' => 'access_token',
                ]);
        } catch (Throwable $exception) {
            throw new OAuthIntrospectionException(
                'The OAuth authorization server could not be reached.',
                previous: $exception,
            );
        }

        if (! $response->successful()) {
            throw new OAuthIntrospectionException('The OAuth authorization server rejected introspection.');
        }

        return $this->parse($response, $issuer, $resource);
    }

    private function parse(Response $response, string $issuer, string $resource): IntrospectedToken
    {
        $payload = json_decode($response->body(), true, 512, JSON_BIGINT_AS_STRING);
        if (json_last_error() !== JSON_ERROR_NONE
            || ! is_array($payload)
            || ! is_bool($payload['active'] ?? null)) {
            throw new OAuthIntrospectionException('The OAuth introspection response is invalid.');
        }

        if ($payload['active'] === false) {
            return IntrospectedToken::inactive();
        }

        $subject = $this->nonEmptyString($payload['sub'] ?? null, preserveWhitespace: true);
        $tokenClientId = $this->nonEmptyString($payload['client_id'] ?? null, preserveWhitespace: true);
        $tokenIssuer = $this->nonEmptyString($payload['iss'] ?? null);
        $tokenResource = $this->canonicalResource($payload['resource'] ?? null);
        $expiresAt = $this->integer($payload['exp'] ?? null);
        $issuedAt = $this->optionalInteger($payload['iat'] ?? null);
        $notBefore = $this->optionalInteger($payload['nbf'] ?? null);
        $audiences = $this->stringList($payload['aud'] ?? null);
        $scopes = $this->scopes($payload['scope'] ?? null);
        $now = time();

        if ($tokenIssuer !== $issuer
            || $tokenResource !== $resource
            || ! $this->audienceContainsResource($audiences, $resource)
            || $expiresAt <= $now
            || ($notBefore !== null && $notBefore > $now)) {
            throw new OAuthIntrospectionException('The active OAuth token context does not match this resource server.');
        }

        return new IntrospectedToken(
            active: true,
            issuer: $tokenIssuer,
            subject: $subject,
            clientId: $tokenClientId,
            scopes: $scopes,
            audiences: $audiences,
            resource: $tokenResource,
            expiresAt: $expiresAt,
            issuedAt: $issuedAt,
            notBefore: $notBefore,
        );
    }

    private function requiredStringConfig(string $key, bool $trim = true): string
    {
        $value = config("bherila-auth.oauth_resource_server.{$key}");
        if (! is_string($value) || trim($value) === '') {
            throw new OAuthIntrospectionException("OAuth resource-server {$key} is not configured.");
        }

        return $trim ? trim($value) : $value;
    }

    private function requiredUrlConfig(string $key): string
    {
        $value = $this->requiredStringConfig($key);
        if (filter_var($value, FILTER_VALIDATE_URL) === false) {
            throw new OAuthIntrospectionException("OAuth resource-server {$key} must be an absolute URL.");
        }

        $parts = parse_url($value);
        if (! is_array($parts)
            || ! isset($parts['scheme'], $parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['fragment'])
            || ! $this->isSecureScheme((string) $parts['scheme'], (string) $parts['host'])) {
            throw new OAuthIntrospectionException("OAuth resource-server {$key} must use HTTPS.");
        }

        return $value;
    }

    private function requiredResourceConfig(): string
    {
        $value = $this->requiredStringConfig('resource');
        $canonical = OAuthResourceIndicator::canonicalize($value);
        if ($canonical === null) {
            throw new OAuthIntrospectionException('OAuth resource-server resource must be an absolute HTTP URL.');
        }

        return $canonical;
    }

    private function isSecureScheme(string $scheme, string $host): bool
    {
        if (strtolower($scheme) === 'https') {
            return true;
        }

        $normalizedHost = strtolower(trim($host, '[]'));

        return strtolower($scheme) === 'http'
            && in_array((string) config('app.env'), ['local', 'testing'], true)
            && in_array($normalizedHost, ['localhost', '127.0.0.1', '::1'], true);
    }

    private function origin(string $url): string
    {
        $parts = parse_url($url);
        if (! is_array($parts) || ! isset($parts['scheme'], $parts['host'])) {
            throw new OAuthIntrospectionException('The OAuth endpoint origin is invalid.');
        }

        $scheme = strtolower((string) $parts['scheme']);
        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);

        return $scheme.'://'.strtolower((string) $parts['host']).':'.$port;
    }

    private function nonEmptyString(mixed $value, bool $preserveWhitespace = false): string
    {
        if (! is_string($value) || trim($value) === '') {
            throw new OAuthIntrospectionException('The active OAuth introspection response is incomplete.');
        }

        return $preserveWhitespace ? $value : trim($value);
    }

    private function canonicalResource(mixed $value): string
    {
        $canonical = OAuthResourceIndicator::canonicalize($value);
        if ($canonical === null) {
            throw new OAuthIntrospectionException('The active OAuth introspection response is incomplete.');
        }

        return $canonical;
    }

    /** @param list<string> $audiences */
    private function audienceContainsResource(array $audiences, string $resource): bool
    {
        foreach ($audiences as $audience) {
            if (OAuthResourceIndicator::canonicalize($audience) === $resource) {
                return true;
            }
        }

        return false;
    }

    private function integer(mixed $value): int
    {
        if (is_int($value)) {
            return $value;
        }

        if (! is_float($value)
            || ! is_finite($value)
            || floor($value) !== $value
            || ! $this->withinIntegerRange($value)) {
            throw new OAuthIntrospectionException('The active OAuth introspection response has an invalid timestamp.');
        }

        return (int) $value;
    }

    /**
     * Doubles cannot represent every integer near the 64-bit bounds, so an
     * out-of-range JSON literal such as -9223372036854775809.0 decodes to the
     * double that is exactly PHP_INT_MIN and would otherwise be accepted. Both
     * bounds are therefore exclusive there. A 32-bit int range is represented
     * exactly by a double, so those bounds stay inclusive.
     */
    private function withinIntegerRange(float $value): bool
    {
        if (PHP_INT_SIZE >= 8) {
            return $value > -(2 ** 63) && $value < 2 ** 63;
        }

        return $value >= (float) PHP_INT_MIN && $value <= (float) PHP_INT_MAX;
    }

    private function optionalInteger(mixed $value): ?int
    {
        if ($value === null) {
            return null;
        }

        return $this->integer($value);
    }

    /** @return list<string> */
    private function stringList(mixed $value): array
    {
        if (is_string($value)) {
            $value = [$value];
        }
        if (! is_array($value) || ! array_is_list($value)) {
            throw new OAuthIntrospectionException('The active OAuth introspection response has an invalid audience.');
        }

        $values = [];
        foreach ($value as $item) {
            if (! is_string($item) || trim($item) === '') {
                throw new OAuthIntrospectionException('The active OAuth introspection response has an invalid audience.');
            }
            $values[] = $item;
        }

        return array_values(array_unique($values));
    }

    /** @return list<string> */
    private function scopes(mixed $value): array
    {
        if (! is_string($value)) {
            throw new OAuthIntrospectionException('The active OAuth introspection response has an invalid scope.');
        }

        return array_values(array_unique(array_filter(
            preg_split('/\s+/', trim($value)) ?: [],
            static fn (string $scope): bool => $scope !== '',
        )));
    }
}
