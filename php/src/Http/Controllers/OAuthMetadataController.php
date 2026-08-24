<?php

namespace BWH\Auth\Http\Controllers;

use Illuminate\Http\JsonResponse;

final class OAuthMetadataController
{
    public function authorizationServer(): JsonResponse
    {
        return $this->publicJson([
            'issuer' => $this->url('issuer'),
            'authorization_endpoint' => $this->url('authorization_endpoint'),
            'token_endpoint' => $this->url('token_endpoint'),
            'registration_endpoint' => $this->url('registration_endpoint'),
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'response_types_supported' => ['code'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => $this->tokenEndpointAuthMethods(),
            'scopes_supported' => $this->scopes(),
            'resource_indicators_supported' => true,
        ]);
    }

    public function protectedResource(): JsonResponse
    {
        return $this->publicJson([
            'resource' => $this->url('resource'),
            'authorization_servers' => [$this->url('issuer')],
            'scopes_supported' => $this->scopes(),
            'bearer_methods_supported' => ['header'],
        ]);
    }

    /** @return list<string> */
    private function scopes(): array
    {
        $scopes = config('bherila-auth.oauth_server.scopes', []);
        if (! is_array($scopes)) {
            return [];
        }

        return array_is_list($scopes) ? array_values($scopes) : array_keys($scopes);
    }

    /** @return list<string> */
    private function tokenEndpointAuthMethods(): array
    {
        $methods = config('bherila-auth.oauth_server.token_endpoint_auth_methods', ['none']);

        return is_array($methods) ? array_values($methods) : ['none'];
    }

    private function url(string $key): string
    {
        $value = config("bherila-auth.oauth_server.{$key}");

        return is_string($value) ? $value : '';
    }

    /** @param array<string, mixed> $payload */
    private function publicJson(array $payload): JsonResponse
    {
        return response()->json($payload)->withHeaders([
            'Cache-Control' => 'public, max-age=300',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }
}
