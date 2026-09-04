<?php

namespace BWH\Auth\OAuth\Introspection;

use Illuminate\Http\Request;
use RuntimeException;

final class OAuthIntrospectionClientRegistry
{
    public function resourceFor(Request $request): ?string
    {
        $encodedClientId = $request->getUser();
        $encodedClientSecret = $request->getPassword();
        if (! is_string($encodedClientId) || $encodedClientId === ''
            || ! is_string($encodedClientSecret) || $encodedClientSecret === '') {
            return null;
        }
        $clientId = urldecode($encodedClientId);
        $clientSecret = urldecode($encodedClientSecret);

        $clients = config('bherila-auth.oauth_server.introspection.clients', []);
        if (! is_array($clients)) {
            throw new RuntimeException('OAuth introspection clients must be configured as a list.');
        }

        foreach ($clients as $client) {
            if (! is_array($client)) {
                continue;
            }

            $configuredId = $client['id'] ?? null;
            $configuredSecretHash = $client['secret_hash'] ?? null;
            $resource = $client['resource'] ?? null;
            if (! is_string($configuredId) || $configuredId === ''
                || ! is_string($configuredSecretHash) || $configuredSecretHash === ''
                || ! is_string($resource) || $resource === '') {
                continue;
            }

            if (hash_equals($configuredId, $clientId)
                && password_verify($clientSecret, $configuredSecretHash)) {
                return $resource;
            }
        }

        return null;
    }
}
